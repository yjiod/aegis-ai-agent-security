#!/usr/bin/env python3
"""Offline integrity and contract verifier for a Sentinel enterprise release."""
import argparse, hashlib, json, re, sys, zipfile
from pathlib import Path

RUNTIME_FILES=("sentinel_agent.py","sentinel-windows.ps1","sentinel-policy.json","sentinel-security-baseline.md")
HASH_CONSUMERS={
    "sentinel_agent.py":("install-sentinel.sh","intune-macos-install.sh","intune-macos-compliance.sh"),
    "sentinel-windows.ps1":("intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1"),
    "sentinel-policy.json":("install-sentinel.sh","intune-macos-install.sh","intune-macos-compliance.sh","intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1"),
    "sentinel-security-baseline.md":("install-sentinel.sh","intune-macos-install.sh","intune-macos-compliance.sh","intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1"),
}
BUNDLE_FILES=(
    "DEPLOYMENT-GUIDE.md","sentinel-policy.json","sentinel-security-baseline.md","sentinel-report.schema.json",
    "sentinel_agent.py","sentinel_collector.py","sentinel-windows.ps1","install-sentinel.sh","intune-windows-detect.ps1",
    "intune-windows-remediate.ps1","intune-compliance-discovery.ps1","intune-compliance-policy.json","intune-macos-install.sh",
    "intune-macos-compliance.sh","intune-macos-compliance-policy.json","rollback-sentinel-windows.ps1","rollback-sentinel-macos.sh",
    "uninstall-sentinel-windows.ps1","uninstall-sentinel-macos.sh","CHECKSUMS.sha256","release.json","sentinel_adapter.py",
    "sentinel-adapters.example.json","sentinel_release_verify.py","sentinel_collector_backup.py","sentinel_collector_restore.py",
)

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def verify(downloads):
    downloads=Path(downloads); errors=[]
    try: release=json.loads((downloads/"release.json").read_text())
    except (OSError,ValueError) as exc: return [f"invalid_release_json:{type(exc).__name__}"]
    if not re.fullmatch(r"\d+\.\d+\.\d+",str(release.get("release",""))): errors.append("invalid_release_version")
    try: policy=json.loads((downloads/"sentinel-policy.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_policy_json:{type(exc).__name__}"); policy={}
    patterns=policy.get("secret_patterns",[]) if isinstance(policy,dict) else []
    if not isinstance(patterns,list): errors.append("invalid_secret_patterns_type")
    else:
        for index,pattern in enumerate(patterns):
            if not isinstance(pattern,str): errors.append(f"invalid_secret_pattern_type:{index}"); continue
            try: re.compile(pattern)
            except re.error: errors.append(f"invalid_secret_pattern_regex:{index}")
    invocations=policy.get("allowed_mcp_invocations",[]) if isinstance(policy,dict) else []
    if not isinstance(invocations,list): errors.append("invalid_allowed_mcp_invocations_type")
    else:
        for index,invocation in enumerate(invocations):
            if not isinstance(invocation,list) or len(invocation)<2 or any(not isinstance(value,str) or not value for value in invocation):
                errors.append(f"invalid_allowed_mcp_invocation:{index}")
    try: manifest={line.split()[1]:line.split()[0] for line in (downloads/"CHECKSUMS.sha256").read_text().splitlines() if len(line.split())==2}
    except OSError as exc: errors.append(f"invalid_checksum_manifest:{type(exc).__name__}"); manifest={}
    for name in RUNTIME_FILES:
        path=downloads/name
        if not path.is_file(): errors.append(f"missing_runtime:{name}"); continue
        actual=digest(path)
        if manifest.get(name)!=actual: errors.append(f"checksum_mismatch:{name}")
        for consumer in HASH_CONSUMERS[name]:
            try: text=(downloads/consumer).read_text()
            except OSError: errors.append(f"missing_hash_consumer:{consumer}"); continue
            if actual not in text: errors.append(f"stale_embedded_hash:{consumer}:{name}")
    for name in ("intune-compliance-policy.json","intune-macos-compliance-policy.json"):
        try: rules=json.loads((downloads/name).read_text()).get("Rules",[])
        except (OSError,ValueError): errors.append(f"invalid_compliance_json:{name}"); continue
        if not rules: errors.append(f"empty_compliance_rules:{name}")
        for rule in rules:
            if "en_US" not in {item.get("Language") for item in rule.get("RemediationStrings",[])}: errors.append(f"missing_en_US:{name}:{rule.get('SettingName','unknown')}")
        versions=[rule.get("Operand") for rule in rules if rule.get("SettingName")=="SentinelPolicyVersion"]
        if versions!=[policy.get("version")]: errors.append(f"policy_version_drift:{name}")
    archive=downloads/"sentinel-enterprise-bundle.zip"
    try:
        with zipfile.ZipFile(archive) as bundle:
            names=set(bundle.namelist()); expected=set(BUNDLE_FILES)
            for name in sorted(expected-names): errors.append(f"bundle_missing:{name}")
            for name in sorted(names-expected): errors.append(f"bundle_unexpected:{name}")
            for name in sorted(expected&names):
                path=downloads/name
                if not path.is_file() or bundle.read(name)!=path.read_bytes(): errors.append(f"bundle_content_mismatch:{name}")
    except (OSError,zipfile.BadZipFile) as exc: errors.append(f"invalid_bundle:{type(exc).__name__}")
    return errors

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("downloads",nargs="?",default=str(Path(__file__).parent)); args=ap.parse_args()
    errors=verify(args.downloads)
    print(json.dumps({"ok":not errors,"errors":errors},ensure_ascii=False,separators=(",",":")))
    return 1 if errors else 0
if __name__=="__main__": sys.exit(main())
