#!/usr/bin/env python3
"""Seed realistic demo device reports into a running Aegis collector.

Generates 8-12 varied aegis.report/v1 documents (see
public/downloads/aegis-report.schema.json) and POSTs them to the collector's
/v1/reports endpoint. Reports are HMAC-signed exactly like aegis_agent.py when
a signing secret is supplied (--signing-secret or AEGIS_REPORT_SIGNING_SECRET);
otherwise they are sent unsigned, which only works when the collector runs
with AEGIS_ALLOW_UNSIGNED_REPORTS=1.

Examples:
  python3 scripts/seed-demo-reports.py --token "$AEGIS_COLLECTOR_TOKEN" \
      --signing-secret "$AEGIS_REPORT_SIGNING_SECRET"
  python3 scripts/seed-demo-reports.py --collector-url http://127.0.0.1:8931 \
      --token dev-token --signing-secret dev-secret --count 12 --seed 7
"""
import argparse
import hashlib
import hmac
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

SCHEMA = "aegis.report/v1"
CURRENT_AGENT_VERSION = "0.30.0"
OUTDATED_AGENT_VERSIONS = ["0.28.1", "0.26.4", "0.24.0"]
CURRENT_POLICY_VERSION = "4.8.0"
OUTDATED_POLICY_VERSIONS = ["4.6.0", "4.2.1"]

# device_id prefix -> (count in fleet, home template, os)
DEVICE_POOLS = [
    ("ENG-MBP", 5, "/Users/{user}", "macos"),
    ("MKT-LT", 4, "/Users/{user}", "macos"),
    ("OPS-WIN", 3, "C:\\Users\\{user}", "windows"),
]

USERS = [
    "demo.eng", "demo.eng2", "demo.mkt", "demo.mkt2", "demo.ops",
    "j.rivera", "k.tanaka", "a.okafor", "m.lindqvist", "s.patel",
    "t.nguyen", "r.castellanos",
]

AI_TOOLS = [
    ("Cursor", ["1.2.7", "1.3.5", "1.4.2"]),
    ("Claude Code", ["0.1.8", "0.2.4", "0.2.9"]),
    ("Codex CLI", ["0.8.0", "0.9.1", "0.10.0"]),
    ("Windsurf", ["1.2.1", "1.3.0", "1.4.0"]),
]

MCP_SERVERS = ["filesystem", "github", "slack", "postgres", "puppeteer", "sentry"]
SKILLS = ["pdf-export", "code-review", "release-notes", "db-migrate", "deploy-helper"]

# Finding templates keyed by severity: (kind, relative path, message, evidence)
FINDING_CATALOG = {
    "critical": [
        ("unsigned_skill_install", ".cursor/skills/deploy-helper",
         "Skill executes curl | sh from an unverified third-party source",
         "install.sh fetched from non-allowlisted host"),
        ("secret_in_mcp_config", ".claude/mcp.json",
         "Plaintext API credential committed inside an MCP server configuration",
         "key redacted; pattern matched known vendor prefix"),
        ("prompt_injection_artifact", ".codex/sessions/last.jsonl",
         "Agent session contains tool output matching known prompt-injection signatures",
         None),
    ],
    "high": [
        ("stale_mcp_config", ".codeium/windsurf/mcp_config.json",
         "MCP server pinned to a version with a known command-injection advisory", None),
        ("outdated_agent", "/usr/local/bin/aegis-agent",
         "Agent version is behind the required baseline {required_agent}", None),
        ("unsigned_mcp_server", ".cursor/mcp.json",
         "MCP server binary is not signed by an allowlisted publisher", None),
    ],
    "medium": [
        ("dev_tool_detected", "Applications/{tool}",
         "Unmanaged AI coding tool ({tool}) discovered on this workstation", None),
        ("world_readable_config", ".codex/config.json",
         "Codex CLI configuration is readable by all local users", None),
        ("skill_scope_overbroad", ".claude/skills/db-migrate",
         "Skill requests filesystem scope beyond its declared purpose", None),
    ],
    "low": [
        ("informational_scan", "{home}",
         "Routine scan completed with no policy violations", None),
        ("managed_tool_current", "Applications/{tool}",
         "Managed AI tool {tool} is on the current approved version", None),
    ],
}

# Fleet posture profiles: how many findings per severity a device gets.
PROFILES = [
    ("compliant", {"critical": 0, "high": 0, "medium": 0, "low": 1}, 35),
    ("typical", {"critical": 0, "high": 0, "medium": 1, "low": 1}, 30),
    ("at-risk", {"critical": 0, "high": 1, "medium": 1, "low": 0}, 20),
    ("breached", {"critical": 1, "high": 1, "medium": 1, "low": 0}, 15),
]


def pick_profile(rng):
    names = [name for name, _, _ in PROFILES]
    weights = [weight for _, _, weight in PROFILES]
    chosen = rng.choices(names, weights=weights, k=1)[0]
    return next(counts for name, counts, _ in PROFILES if name == chosen)


def device_ids(rng, count):
    """Return `count` unique device ids spread across the department pools."""
    ids = set()
    attempts = 0
    while len(ids) < count and attempts < count * 50:
        prefix, _, _, _ = DEVICE_POOLS[attempts % len(DEVICE_POOLS)]
        ids.add(f"{prefix}-{rng.randint(1000, 9999)}")
        attempts += 1
    while len(ids) < count:  # extremely unlikely fallback
        ids.add(f"ENG-MBP-{rng.randint(1000, 9999)}")
    return sorted(ids)


def build_inventory(rng, home, os_name):
    inventory = []
    apps_dir = "/Applications" if os_name == "macos" else "C:\\Program Files"
    for name, versions in rng.sample(AI_TOOLS, k=rng.randint(1, 3)):
        inventory.append({
            "category": "tool",
            "name": name,
            "version": rng.choice(versions),
            "path": f"{apps_dir}\\{name}" if os_name == "windows" else f"{apps_dir}/{name}",
            "managed": rng.random() < 0.5,
        })
    for server in rng.sample(MCP_SERVERS, k=rng.randint(0, 3)):
        inventory.append({
            "category": "mcp_server",
            "name": server,
            "scope": rng.choice(["user", "project"]),
            "status": rng.choice(["enabled", "enabled", "disabled"]),
        })
    for skill in rng.sample(SKILLS, k=rng.randint(0, 3)):
        inventory.append({
            "category": "skill",
            "name": skill,
            "source": rng.choice(["marketplace", "internal", "unknown"]),
            "signature": rng.choice(["verified", "unsigned"]),
        })
    return inventory


def build_report(rng, device, now):
    prefix, _, home_template, os_name = next(
        pool for pool in DEVICE_POOLS if device.startswith(pool[0])
    )
    user = rng.choice(USERS)
    home = home_template.format(user=user)

    outdated_agent = rng.random() < 0.4
    agent_version = rng.choice(OUTDATED_AGENT_VERSIONS) if outdated_agent else CURRENT_AGENT_VERSION
    if outdated_agent:
        policy_version = rng.choice(OUTDATED_POLICY_VERSIONS) if rng.random() < 0.5 else CURRENT_POLICY_VERSION
    else:
        policy_version = CURRENT_POLICY_VERSION if rng.random() < 0.8 else rng.choice(OUTDATED_POLICY_VERSIONS)

    profile = pick_profile(rng)
    findings = []
    tool_names = [name for name, _ in AI_TOOLS]
    for severity, wanted in profile.items():
        pool = FINDING_CATALOG[severity]
        for kind, rel_path, message, evidence in rng.sample(pool, k=min(wanted, len(pool))):
            finding = {
                "kind": kind,
                "severity": severity,
                "path": rel_path if rel_path.startswith(("/", "C:\\")) else f"{home}/{rel_path}",
                "message": message.format(tool=rng.choice(tool_names), required_agent=CURRENT_AGENT_VERSION, home=home),
            }
            if evidence:
                finding["evidence"] = evidence
            findings.append(finding)
    if outdated_agent and not any(f["kind"] == "outdated_agent" for f in findings):
        findings.append({
            "kind": "outdated_agent",
            "severity": "high",
            "path": "/usr/local/bin/aegis-agent",
            "message": f"Agent version is behind the required baseline {CURRENT_AGENT_VERSION}",
        })
    rng.shuffle(findings)

    summary = {level: 0 for level in ("critical", "high", "medium", "low")}
    for finding in findings:
        summary[finding["severity"]] += 1

    return {
        "schema": SCHEMA,
        "agent_version": agent_version,
        "policy_version": policy_version,
        "device_id": device,
        "scanned_at": now - rng.randint(0, 3600),
        "scan_root": home,
        "inventory": build_inventory(rng, home, os_name),
        "summary": summary,
        "findings": findings,
    }


def report_headers(body, token, signing_secret, device_id):
    """Mirror aegis_agent.py report_headers(): HMAC over '<ts>.<device_id>.<body>'."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Aegis-Device-ID": device_id,
    }
    if signing_secret:
        timestamp = str(int(time.time()))
        signed = timestamp.encode() + b"." + device_id.encode() + b"." + body
        headers["X-Aegis-Timestamp"] = timestamp
        headers["X-Aegis-Signature"] = "sha256=" + hmac.new(
            signing_secret.encode(), signed, hashlib.sha256
        ).hexdigest()
    return headers


def post_report(url, body, headers, retries=3):
    last_error = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
                return response.status, payload
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:200]
            return error.code, {"error": detail}
        except (urllib.error.URLError, OSError) as error:
            last_error = error
            time.sleep(1 + attempt)
    return None, {"error": f"unreachable: {last_error}"}


def load_dev_credentials():
    """Fallback: read demo credentials written by scripts/dev-collector.sh."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".dev", "collector.env")
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    except OSError:
        pass
    return values


def resolve_secret(cli_value, env_name, dev_credentials):
    return cli_value or os.getenv(env_name, "") or dev_credentials.get(env_name, "")


def main():
    dev_credentials = load_dev_credentials()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--collector-url", default=os.getenv("AEGIS_COLLECTOR_URL", "http://127.0.0.1:8931"),
                        help="collector base URL (default: %(default)s)")
    parser.add_argument("--token", default=None,
                        help="collector bearer token (default: $AEGIS_COLLECTOR_TOKEN, then .dev/collector.env)")
    parser.add_argument("--signing-secret", default=None,
                        help="report signing secret; omit only if the collector allows unsigned reports "
                             "(default: $AEGIS_REPORT_SIGNING_SECRET, then .dev/collector.env)")
    parser.add_argument("--count", type=int, default=0,
                        help="number of reports to send, clamped to 8-12 (default: random 8-12)")
    parser.add_argument("--seed", type=int, default=None, help="PRNG seed for reproducible fleets")
    args = parser.parse_args()
    args.token = resolve_secret(args.token, "AEGIS_COLLECTOR_TOKEN", dev_credentials)
    args.signing_secret = resolve_secret(args.signing_secret, "AEGIS_REPORT_SIGNING_SECRET", dev_credentials)

    if not args.token:
        parser.error("a collector token is required (--token or AEGIS_COLLECTOR_TOKEN)")
    if len(args.token) < 32:
        parser.error("collector token must be at least 32 characters")

    rng = random.Random(args.seed)
    count = rng.randint(8, 12) if args.count <= 0 else min(max(args.count, 8), 12)
    url = args.collector_url.rstrip("/") + "/v1/reports"
    now = int(time.time())

    print(f"seeding {count} demo reports -> {url} (signing: {'on' if args.signing_secret else 'off'})")
    accepted = duplicates = failed = 0
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for device in device_ids(rng, count):
        report = build_report(rng, device, now)
        body = json.dumps(report, ensure_ascii=False).encode("utf-8")
        headers = report_headers(body, args.token, args.signing_secret, device)
        status, payload = post_report(url, body, headers)
        summary = report["summary"]
        for level in severity_totals:
            severity_totals[level] += summary[level]
        posture = f"agent={report['agent_version']} policy={report['policy_version']}"
        if status == 202:
            accepted += 1
            outcome = "accepted"
        elif status == 200:
            duplicates += 1
            outcome = "duplicate"
        else:
            failed += 1
            outcome = f"FAILED ({status}: {payload.get('error', payload)})"
        counts = " ".join(f"{level[:4]}={summary[level]}" for level in ("critical", "high", "medium", "low"))
        tools = ", ".join(item["name"] for item in report["inventory"] if item["category"] == "tool") or "-"
        print(f"  {device:<14} {posture:<32} {counts:<38} tools=[{tools}] -> {outcome}")

    print(f"\nsent {accepted + duplicates + failed} reports: "
          f"{accepted} accepted, {duplicates} duplicate, {failed} failed")
    print("finding totals: " + ", ".join(f"{level}={severity_totals[level]}" for level in severity_totals))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
