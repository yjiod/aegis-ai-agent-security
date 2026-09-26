"""Read-only Mac health summary. Never print identity, credentials or finding content."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

from aegis_macos_maintenance import MaintenanceError, directory
from aegis_macos_configuration import ConfigurationError, config_fingerprint, read_config, read_private_json

FRESHNESS_SECONDS = 7200
SEVERITIES = ("critical", "high", "medium", "low")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,32})?")
DIGEST = re.compile(r"[0-9a-f]{64}")


class DiagnosticError(Exception):
    pass


def read_file(root, name, limit, owner, private=False):
    # Callers supply fixed names. Open ancestors and final component without links;
    # nonblocking open prevents a FIFO from hanging before fstat rejects it.
    with directory(root) as parent:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner
                    or info.st_mode & (0o077 if private else 0o022) or info.st_size > limit):
                raise DiagnosticError("unsafe_file")
            value = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(value) > limit or (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise DiagnosticError("changing_or_oversized_file")
            return value


def read_json(root, name, limit, owner, private=False):
    value = json.loads(read_file(root, name, limit, owner, private))
    if not isinstance(value, dict):
        raise DiagnosticError("invalid_object")
    return value


def empty_status(reason=None):
    return {"schema": "aegis.macos-health/v1", "AegisInstalled": False,
            "AegisIntegrityValid": False, "AegisIntegrityScope": "local-package-checksums",
            "AegisLaunchDaemonRegistered": False, "AegisLaunchDaemonHealthy": False,
            "AegisLegacyServicePresent": False, "AegisReportingConfigured": False,
            "AegisReportingHealthy": False, "AegisPolicyVersion": "missing",
            "AegisReportValid": False, "AegisScanRecent": False, "AegisFindingsKnown": False,
            "AegisCriticalFindings": 0, "AegisHighFindings": 0,
            "AegisFreshnessSeconds": FRESHNESS_SECONDS, "AegisDiagnosticIssues": [reason] if reason else []}


def valid_report(report, version, policy_version):
    findings, summary = report.get("findings"), report.get("summary")
    if (report.get("schema") != "aegis.report/v1" or report.get("agent_version") != version
            or report.get("policy_version") != policy_version or policy_version == "missing"
            or not isinstance(report.get("device_id"), str) or not re.fullmatch(r"[0-9a-f]{12}", report["device_id"])
            or type(report.get("scanned_at")) is not int or not isinstance(findings, list)
            or len(findings) > 10000 or not isinstance(summary, dict)):
        return False
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        if (not isinstance(finding, dict) or finding.get("severity") not in SEVERITIES
                or any(not isinstance(finding.get(key), str) for key in ("kind", "path", "message"))):
            return False
        counts[finding["severity"]] += 1
    return all(type(summary.get(name)) is int and summary[name] == counts[name] for name in SEVERITIES)


def recent(timestamp, now):
    return type(timestamp) is int and 0 <= now - timestamp < FRESHNESS_SECONDS


def service_status(root):
    result = subprocess.run(["/bin/launchctl", "print", "system/com.aegis.agent"],
                            capture_output=True, text=True, timeout=5, check=False)
    if result.returncode == 113:
        return False, False
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise DiagnosticError("service_probe_failed")
    state = re.search(r"(?m)^\s*state = (\S+)\s*$", result.stdout)
    pid = re.search(r"(?m)^\s*pid = ([1-9][0-9]*)\s*$", result.stdout)
    program = re.search(r"(?m)^\s*program = (.+)$", result.stdout)
    healthy = bool(state and state[1] == "running" and pid and program
                   and program[1].strip().strip('"') == str(Path(root) / "aegis-agent"))
    if healthy:
        try:
            os.kill(int(pid[1]), 0)
        except (OSError, ValueError, OverflowError):
            healthy = False
    return True, healthy


def legacy_service_present():
    result = subprocess.run(["/bin/launchctl", "print", "system/com.company.aegis-agent"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
    if result.returncode not in (0, 113):
        raise DiagnosticError("service_probe_failed")
    return result.returncode == 0


def collect(root, version, validate_policy, owner=0, now=None, probe=service_status, legacy_probe=legacy_service_present):
    now = int(time.time()) if now is None else now
    result = empty_status()
    issues = result["AegisDiagnosticIssues"]
    failures = (OSError, ValueError, TypeError, RecursionError, DiagnosticError, MaintenanceError, ConfigurationError)
    try:
        binary = read_file(root, "aegis-agent", 128 * 1024 * 1024, owner)
        result["AegisInstalled"] = bool(binary)
        manifest = read_json(root, "aegis-runtime-manifest.json", 16384, owner)
        files = manifest.get("files", {})
        if not isinstance(files, dict):
            raise DiagnosticError("invalid_runtime_manifest")
        artifact = "aegis-agent-darwin-" + ("arm64" if os.uname().machine == "arm64" else "x64")
        expected = files.get(artifact)
        expected_version = manifest.get("agent_version")
        # A successful updater records the verified applied digest. This receipt
        # is local bookkeeping, not a cryptographic proof of publisher identity.
        if expected_version != version:
            receipt = read_json(root, "aegis-update-receipt.json", 16384, owner, private=True)
            if (receipt.get("schema") != "aegis.update-receipt/v1" or receipt.get("artifact") != artifact
                    or receipt.get("agent_version") != version):
                raise DiagnosticError("invalid_update_receipt")
            expected = receipt.get("sha256")
        baseline = read_file(root, "aegis-security-baseline.md", 2 * 1024 * 1024, owner)
        expected_baseline = files.get("aegis-security-baseline.md")
        result["AegisIntegrityValid"] = (manifest.get("schema") == "aegis.macos-runtime/v1"
            and isinstance(expected, str) and bool(DIGEST.fullmatch(expected))
            and hashlib.sha256(binary).hexdigest() == expected
            and isinstance(expected_baseline, str) and bool(DIGEST.fullmatch(expected_baseline))
            and hashlib.sha256(baseline).hexdigest() == expected_baseline)
        if not result["AegisIntegrityValid"]:
            issues.append("runtime_integrity_unconfirmed")
    except failures:
        issues.append("runtime_integrity_unconfirmed")
    try:
        policy = validate_policy(read_json(root, "aegis-policy.json", 4 * 1024 * 1024, owner))
        value = policy.get("version")
        if not isinstance(value, str) or len(value) > 64 or not VERSION.fullmatch(value):
            raise DiagnosticError("invalid_policy_version")
        result["AegisPolicyVersion"] = value
    except failures:
        issues.append("policy_unavailable")
    host, fingerprint = "", ""
    try:
        config = read_config(Path(root) / "reporting.json", owner)
        host = urlsplit(config["report_url"]).hostname.lower().rstrip(".")
        fingerprint = config_fingerprint(config)
        result["AegisReportingConfigured"] = True
    except failures:
        issues.append("reporting_unavailable")
    try:
        upload = read_json(root, "upload-status.json", 16384, owner, private=True)
        result["AegisReportingHealthy"] = (bool(host) and upload.get("schema") == "aegis.upload-status/v1"
            and upload.get("status") == "accepted" and upload.get("collector_host") == host
            and isinstance(upload.get("configuration_fingerprint"), str)
            and hmac.compare_digest(upload["configuration_fingerprint"], fingerprint)
            and recent(upload.get("last_success"), now))
        if not result["AegisReportingHealthy"]:
            issues.append("upload_unconfirmed_or_stale")
    except failures:
        issues.append("upload_unconfirmed_or_stale")
    try:
        report = read_json(root, "last-report.json", 32 * 1024 * 1024, owner)
        result["AegisReportValid"] = valid_report(report, version, result["AegisPolicyVersion"])
        if result["AegisReportValid"]:
            result["AegisScanRecent"] = recent(report["scanned_at"], now)
            result["AegisFindingsKnown"] = True
            result["AegisCriticalFindings"] = report["summary"]["critical"]
            result["AegisHighFindings"] = report["summary"]["high"]
        if not result["AegisReportValid"] or not result["AegisScanRecent"]:
            issues.append("report_invalid_or_stale")
    except failures:
        issues.append("report_invalid_or_stale")
    try:
        result["AegisLaunchDaemonRegistered"], result["AegisLaunchDaemonHealthy"] = probe(root)
        result["AegisLegacyServicePresent"] = legacy_probe()
        if not result["AegisLaunchDaemonHealthy"]:
            issues.append("service_not_running")
        if result["AegisLegacyServicePresent"]:
            result["AegisLaunchDaemonHealthy"] = False
            issues.append("legacy_service_requires_migration")
    except (OSError, subprocess.SubprocessError, DiagnosticError):
        result["AegisLaunchDaemonHealthy"] = False
        issues.append("service_state_unavailable")
    try:
        migration = read_private_json(Path(root) / "legacy-service-migration.json", owner)
        if (not isinstance(migration, dict) or migration.get("schema") != "aegis.legacy-services/v1"
                or migration.get("status") != "prepared" or not isinstance(migration.get("items"), list)
                or not migration["items"] or any(not isinstance(item, dict) or item.get("stage") != "retired"
                                                for item in migration["items"])):
            result["AegisLaunchDaemonHealthy"] = False
            issues.append("legacy_migration_requires_verification")
    except FileNotFoundError:
        migration = None  # No optional migration journal on a fresh installation.
    except failures:
        result["AegisLaunchDaemonHealthy"] = False
        issues.append("legacy_migration_state_unavailable")
    try:
        from aegis_macos_runtime_activation import JOURNAL, valid_journal
        activation = read_private_json(Path(root) / JOURNAL, owner)
        if not valid_journal(activation) or activation["status"] != "service_registered":
            result["AegisLaunchDaemonHealthy"] = False
            issues.append("native_activation_requires_verification")
    except FileNotFoundError:
        activation = None  # Older clients have no activation journal.
    except failures:
        result["AegisLaunchDaemonHealthy"] = False
        issues.append("native_activation_state_unavailable")
    try:
        from aegis_macos_lifecycle import state
        if state(root, owner) not in (None, "ready"):
            result["AegisLaunchDaemonHealthy"] = False
            issues.append("system_maintenance_pending")
    except failures:
        result["AegisLaunchDaemonHealthy"] = False
        issues.append("system_maintenance_state_unavailable")
    try:
        with directory(root) as parent:
            os.stat("watch-cleanup-pending.json", dir_fd=parent, follow_symlinks=False)
        result["AegisLaunchDaemonHealthy"] = False
        issues.append("watch_cleanup_requires_verification")
    except FileNotFoundError:
        return result
    except (OSError, DiagnosticError, MaintenanceError, ConfigurationError):
        result["AegisLaunchDaemonHealthy"] = False
        issues.append("cleanup_state_unavailable")
    return result


def selftest():
    report = {"schema": "aegis.report/v1", "agent_version": "1.2.3", "policy_version": "1.0.0",
              "device_id": "012345abcdef", "scanned_at": 1, "findings": [], "summary": dict.fromkeys(SEVERITIES, 0)}
    return valid_report(report, "1.2.3", "1.0.0") and not valid_report(report, "1.2.4", "1.0.0")


def main(root, version, validate_policy):
    if sys.platform != "darwin" or os.geteuid() != 0:
        print(json.dumps(empty_status("administrator_required"), separators=(",", ":")))
        return 2
    print(json.dumps(collect(root, version, validate_policy), separators=(",", ":")))
    return 0
