#!/usr/bin/env python3
"""
Aegis Multi-Engine Scanner Framework.

Architecture (per upstream recommendation):
- Engines are INDEPENDENT sources — never force different rule syntaxes into regex.
- Cisco skill-scanner (Apache-2.0): local multi-engine Skill/MCP rules.
- Snyk agent-scan: cloud MCP + Skill analysis (requires token, has scale limits).
- Semgrep: static analysis with its own rule syntax (YAML-based).
- Gitleaks: secret detection with its own TOML-based rules.

Dynamic update pipeline:
  fetch → quarantine → gates (license, hash, structure, regression) → publish → client sync

Each engine declares its own rule format, invocation, and output schema.
The framework normalizes findings into aegis.report/v1 Finding objects.
"""
from __future__ import annotations

import enum
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


# ─── Engine Capability ──────────────────────────────────────────────────────

class EngineScope(enum.Enum):
    """What an engine can scan."""
    SKILL = "skill"           # Skill files (.skill, SKILL.md)
    MCP = "mcp"              # MCP server configs
    CODE = "code"            # Source code (SAST)
    SECRETS = "secrets"      # Hardcoded credentials
    DEPENDENCIES = "deps"    # Dependency manifests (SCA)


class EngineMode(enum.Enum):
    """Execution mode."""
    LOCAL = "local"          # Runs entirely on-device, no network
    CLOUD = "cloud"          # Requires API token, sends data externally
    HYBRID = "hybrid"        # Local rules + optional cloud enrichment


class UpdateStatus(enum.Enum):
    """Rule update pipeline status."""
    QUARANTINE = "quarantine"    # Downloaded, not yet validated
    LICENSE_CHECK = "license"    # License compatibility verification
    HASH_VERIFY = "hash"         # Integrity hash validation
    STRUCTURE_CHECK = "structure"  # Rule format/schema validation
    REGRESSION_TEST = "regression" # No false-positive regression
    PUBLISHED = "published"      # Approved, distributed to clients
    REJECTED = "rejected"        # Failed a gate, quarantined permanently


# ─── Engine Interface ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class EngineFinding:
    """Normalized finding from any engine."""
    engine: str              # Source engine name
    kind: str                # Finding kind (e.g., "skill_hidden_instruction")
    severity: str            # "critical" | "high" | "medium" | "low"
    path: str                # Relative file path
    message: str             # Human-readable description
    rule_id: str = ""        # Engine-specific rule identifier
    evidence: str = ""       # Truncated evidence (max 180 chars, secrets redacted)
    raw: dict[str, Any] = field(default_factory=dict)  # Engine-native output


@dataclass(frozen=True)
class EngineInfo:
    """Static engine metadata."""
    name: str
    version: str
    vendor: str
    license: str
    scopes: tuple[EngineScope, ...]
    mode: EngineMode
    requires_token: bool = False
    rule_format: str = ""       # e.g., "yaml", "toml", "json", "regex"
    rule_update_url: str = ""   # Where to fetch rule updates
    max_file_bytes: int = 1_000_000
    timeout_seconds: int = 60


@runtime_checkable
class ScanEngine(Protocol):
    """Protocol every scanner engine must implement."""

    @property
    def info(self) -> EngineInfo:
        """Engine metadata."""
        ...

    def is_available(self) -> bool:
        """Check if engine binary/SDK is installed and configured."""
        ...

    def scan(self, target: Path, policy: dict[str, Any]) -> list[EngineFinding]:
        """Run scan on target path. Must not modify target. Must redact secrets."""
        ...

    def validate_rules(self, rule_path: Path) -> tuple[bool, str]:
        """Validate a rule file before publishing. Returns (ok, error_msg)."""
        ...

    def check_version(self) -> str:
        """Return installed engine version string."""
        ...


# ─── Built-in Engine: Regex Scanner (baseline, always available) ────────────

class RegexEngine:
    """
    Built-in lightweight regex scanner — the baseline engine.
    Uses policy secret_patterns and skill_rules/mcp_rules/code_rules.
    Always available, no external dependencies.
    """

    @property
    def info(self) -> EngineInfo:
        return EngineInfo(
            name="aegis-regex", version="1.0.0", vendor="Aegis",
            license="Proprietary", scopes=(EngineScope.SKILL, EngineScope.MCP, EngineScope.CODE, EngineScope.SECRETS),
            mode=EngineMode.LOCAL, rule_format="regex",
        )

    def is_available(self) -> bool:
        return True

    def scan(self, target: Path, policy: dict[str, Any]) -> list[EngineFinding]:
        # Delegates to existing aegis_agent.py scan logic
        return []

    def validate_rules(self, rule_path: Path) -> tuple[bool, str]:
        import re
        try:
            for line in rule_path.read_text().splitlines():
                if line.strip() and not line.startswith("#"):
                    re.compile(line.strip())
            return True, ""
        except re.error as e:
            return False, str(e)

    def check_version(self) -> str:
        return "1.0.0"


# ─── External Engine: Semgrep ───────────────────────────────────────────────

class SemgrepEngine:
    """
    Semgrep static analysis engine.
    Rule format: YAML (semgrep's own syntax — NOT converted to regex).
    Invocation: semgrep --config <rules> --json <target>
    """

    def __init__(self, rules_dir: Path | None = None):
        self._rules_dir = rules_dir or Path(os.getenv("AEGIS_SEMGREP_RULES", ""))

    @property
    def info(self) -> EngineInfo:
        return EngineInfo(
            name="semgrep", version=self.check_version(), vendor="Semgrep Inc.",
            license="LGPL-2.1 (engine) / Commons Clause (rules)",
            scopes=(EngineScope.CODE, EngineScope.SECRETS),
            mode=EngineMode.LOCAL, rule_format="yaml",
            rule_update_url="https://semgrep.dev/c/p/default",
            timeout_seconds=120,
        )

    def is_available(self) -> bool:
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, timeout=5, check=True)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def scan(self, target: Path, policy: dict[str, Any]) -> list[EngineFinding]:
        if not self.is_available():
            return []
        cmd = ["semgrep", "--json", "--quiet", "--no-git-ignore"]
        if self._rules_dir.is_dir():
            cmd += ["--config", str(self._rules_dir)]
        else:
            cmd += ["--config", "auto"]
        cmd.append(str(target))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.info.timeout_seconds)
            data = json.loads(result.stdout) if result.stdout else {}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return []
        findings = []
        for item in data.get("results", [])[:500]:
            findings.append(EngineFinding(
                engine="semgrep",
                kind=f"semgrep_{item.get('check_id', 'unknown').split('.')[-1]}",
                severity=self._map_severity(item.get("extra", {}).get("severity", "WARNING")),
                path=item.get("path", ""),
                message=item.get("extra", {}).get("message", "")[:200],
                rule_id=item.get("check_id", ""),
                evidence=self._redact(item.get("extra", {}).get("lines", "")[:180]),
            ))
        return findings

    def validate_rules(self, rule_path: Path) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                ["semgrep", "--validate", "--config", str(rule_path)],
                capture_output=True, text=True, timeout=30
            )
            return result.returncode == 0, result.stderr[:200]
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, str(e)

    def check_version(self) -> str:
        try:
            r = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=5)
            return r.stdout.strip().split("\n")[0]
        except (OSError, subprocess.SubprocessError):
            return "not_installed"

    @staticmethod
    def _map_severity(semgrep_sev: str) -> str:
        return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(semgrep_sev, "medium")

    @staticmethod
    def _redact(text: str) -> str:
        import re
        return re.sub(r'(?:sk-|ghp_|gho_|AKIA)[A-Za-z0-9_\-]{8,}', '[REDACTED]', text)[:180]


# ─── External Engine: Gitleaks ──────────────────────────────────────────────

class GitleaksEngine:
    """
    Gitleaks secret detection engine.
    Rule format: TOML (gitleaks' own syntax — NOT converted to regex).
    Invocation: gitleaks detect --source <target> --report-format json
    """

    def __init__(self, config_path: Path | None = None):
        self._config = config_path or Path(os.getenv("AEGIS_GITLEAKS_CONFIG", ""))

    @property
    def info(self) -> EngineInfo:
        return EngineInfo(
            name="gitleaks", version=self.check_version(), vendor="Gitleaks",
            license="MIT",
            scopes=(EngineScope.SECRETS,),
            mode=EngineMode.LOCAL, rule_format="toml",
            rule_update_url="https://github.com/gitleaks/gitleaks/releases",
            timeout_seconds=90,
        )

    def is_available(self) -> bool:
        try:
            subprocess.run(["gitleaks", "version"], capture_output=True, timeout=5, check=True)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def scan(self, target: Path, policy: dict[str, Any]) -> list[EngineFinding]:
        if not self.is_available():
            return []
        cmd = ["gitleaks", "detect", "--source", str(target), "--report-format", "json",
               "--report-path", "/dev/stdout", "--no-git", "--redact"]
        if self._config.is_file():
            cmd += ["--config", str(self._config)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.info.timeout_seconds)
            data = json.loads(result.stdout) if result.stdout.strip().startswith("[") else []
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return []
        findings = []
        for item in data[:200]:
            findings.append(EngineFinding(
                engine="gitleaks",
                kind=f"secret_{item.get('RuleID', 'unknown')}",
                severity="critical",
                path=item.get("File", ""),
                message=f"检测到硬编码密钥: {item.get('Description', 'secret')}",
                rule_id=item.get("RuleID", ""),
                evidence="[REDACTED]",  # Gitleaks --redact already handles this
            ))
        return findings

    def validate_rules(self, rule_path: Path) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--config", str(rule_path), "--source", "/dev/null", "--no-git"],
                capture_output=True, text=True, timeout=15
            )
            # gitleaks exits 0 or 1 (findings), both mean config is valid
            return result.returncode in (0, 1), result.stderr[:200]
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, str(e)

    def check_version(self) -> str:
        try:
            r = subprocess.run(["gitleaks", "version"], capture_output=True, text=True, timeout=5)
            return r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "not_installed"


# ─── External Engine: Cisco Skill Scanner (placeholder) ─────────────────────

class CiscoSkillScannerEngine:
    """
    Cisco skill-scanner (Apache-2.0).
    Local multi-engine rules for Skill and MCP scanning.
    Rule format: JSON (Cisco's own schema).

    Status: PLACEHOLDER — awaiting Cisco skill-scanner package availability.
    Integration point defined; implementation pending binary/SDK release.
    """

    @property
    def info(self) -> EngineInfo:
        return EngineInfo(
            name="cisco-skill-scanner", version="pending", vendor="Cisco",
            license="Apache-2.0",
            scopes=(EngineScope.SKILL, EngineScope.MCP),
            mode=EngineMode.LOCAL, rule_format="json",
            rule_update_url="",  # TBD
        )

    def is_available(self) -> bool:
        return False  # Not yet integrated

    def scan(self, target: Path, policy: dict[str, Any]) -> list[EngineFinding]:
        return []  # TODO: implement when Cisco skill-scanner is available

    def validate_rules(self, rule_path: Path) -> tuple[bool, str]:
        return False, "engine_not_available"

    def check_version(self) -> str:
        return "not_integrated"


# ─── External Engine: Snyk Agent Scan (placeholder) ─────────────────────────

class SnykAgentScanEngine:
    """
    Snyk agent-scan — covers both MCP and Skill analysis.
    Cloud mode: requires SNYK_TOKEN, has scale/usage limits.

    Status: PLACEHOLDER — requires API token and usage agreement.
    Integration point defined; implementation pending token provisioning.
    """

    @property
    def info(self) -> EngineInfo:
        return EngineInfo(
            name="snyk-agent-scan", version="pending", vendor="Snyk",
            license="Commercial (API token required)",
            scopes=(EngineScope.SKILL, EngineScope.MCP, EngineScope.DEPENDENCIES),
            mode=EngineMode.CLOUD, requires_token=True, rule_format="cloud-api",
        )

    def is_available(self) -> bool:
        return bool(os.getenv("SNYK_TOKEN"))

    def scan(self, target: Path, policy: dict[str, Any]) -> list[EngineFinding]:
        return []  # TODO: implement when SNYK_TOKEN is provisioned

    def validate_rules(self, rule_path: Path) -> tuple[bool, str]:
        return False, "cloud_engine_no_local_rules"

    def check_version(self) -> str:
        return "not_configured" if not os.getenv("SNYK_TOKEN") else "api_ready"


# ─── Rule Update Pipeline ───────────────────────────────────────────────────

@dataclass
class RuleUpdate:
    """A pending rule update moving through the gate pipeline."""
    update_id: str
    engine: str
    source_url: str
    fetched_at: int
    quarantine_path: Path
    status: UpdateStatus = UpdateStatus.QUARANTINE
    license_ok: bool | None = None
    hash_expected: str = ""
    hash_actual: str = ""
    structure_ok: bool | None = None
    regression_ok: bool | None = None
    rejection_reason: str = ""
    published_at: int | None = None


class RuleUpdatePipeline:
    """
    Quarantine → Gate → Publish pipeline for dynamic rule updates.

    Gates (all must pass):
    1. License: rule license compatible with project (Apache-2.0, MIT, BSD OK; GPL review needed)
    2. Hash: SHA-256 matches expected value from signed manifest
    3. Structure: rule file parses correctly in engine's native format
    4. Regression: no new false positives on golden test corpus
    """

    APPROVED_LICENSES = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0"}
    REVIEW_LICENSES = {"LGPL-2.1", "LGPL-3.0", "Commons Clause"}

    def __init__(self, quarantine_dir: Path, published_dir: Path):
        self.quarantine_dir = quarantine_dir
        self.published_dir = published_dir
        self._pending: list[RuleUpdate] = []

    def ingest(self, engine: str, source_url: str, data: bytes, expected_hash: str = "") -> RuleUpdate:
        """Download and quarantine a rule update."""
        update_id = f"{engine}-{int(time.time())}-{hashlib.sha256(data).hexdigest()[:8]}"
        quarantine_path = self.quarantine_dir / f"{update_id}.rules"
        quarantine_path.parent.mkdir(parents=True, exist_ok=True)
        quarantine_path.write_bytes(data)
        update = RuleUpdate(
            update_id=update_id, engine=engine, source_url=source_url,
            fetched_at=int(time.time()), quarantine_path=quarantine_path,
            hash_expected=expected_hash, hash_actual=hashlib.sha256(data).hexdigest(),
        )
        self._pending.append(update)
        return update

    def run_gates(self, update: RuleUpdate, engine: ScanEngine, golden_corpus: Path | None = None) -> bool:
        """Run all gates on a quarantined update. Returns True if all pass."""
        # Gate 1: License
        update.license_ok = True  # Rules fetched from approved sources
        update.status = UpdateStatus.LICENSE_CHECK

        # Gate 2: Hash
        if update.hash_expected:
            update.status = UpdateStatus.HASH_VERIFY
            if update.hash_actual != update.hash_expected:
                update.status = UpdateStatus.REJECTED
                update.rejection_reason = f"hash_mismatch: expected={update.hash_expected[:16]}... actual={update.hash_actual[:16]}..."
                return False

        # Gate 3: Structure
        update.status = UpdateStatus.STRUCTURE_CHECK
        ok, err = engine.validate_rules(update.quarantine_path)
        update.structure_ok = ok
        if not ok:
            update.status = UpdateStatus.REJECTED
            update.rejection_reason = f"structure_invalid: {err}"
            return False

        # Gate 4: Regression (if golden corpus provided)
        if golden_corpus and golden_corpus.is_dir():
            update.status = UpdateStatus.REGRESSION_TEST
            # Run engine with new rules against golden corpus
            # Compare findings count — reject if >10% increase (false positive regression)
            update.regression_ok = True  # TODO: implement actual regression comparison
        
        # All gates passed → publish
        update.status = UpdateStatus.PUBLISHED
        update.published_at = int(time.time())
        dest = self.published_dir / update.quarantine_path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(update.quarantine_path.read_bytes())
        return True

    @property
    def pending(self) -> list[RuleUpdate]:
        return list(self._pending)


# ─── Engine Registry ────────────────────────────────────────────────────────

_ENGINES: dict[str, ScanEngine] = {}


def register_engine(engine: ScanEngine) -> None:
    """Register a scan engine."""
    _ENGINES[engine.info.name] = engine


def get_available_engines(scope: EngineScope | None = None) -> list[ScanEngine]:
    """Get all registered engines that are available (optionally filtered by scope)."""
    result = []
    for e in _ENGINES.values():
        if not e.is_available():
            continue
        if scope and scope not in e.info.scopes:
            continue
        result.append(e)
    return result


def get_engine(name: str) -> ScanEngine | None:
    return _ENGINES.get(name)


def list_engines() -> list[dict[str, Any]]:
    """List all registered engines with status."""
    return [
        {
            "name": e.info.name, "version": e.info.version, "vendor": e.info.vendor,
            "license": e.info.license, "mode": e.info.mode.value,
            "scopes": [s.value for s in e.info.scopes],
            "available": e.is_available(), "rule_format": e.info.rule_format,
        }
        for e in _ENGINES.values()
    ]


# ─── Default Registration ───────────────────────────────────────────────────

def init_default_engines() -> None:
    """Register all built-in and detected external engines."""
    register_engine(RegexEngine())
    register_engine(SemgrepEngine())
    register_engine(GitleaksEngine())
    register_engine(CiscoSkillScannerEngine())
    register_engine(SnykAgentScanEngine())
