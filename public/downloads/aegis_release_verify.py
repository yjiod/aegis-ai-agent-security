#!/usr/bin/env python3
"""Offline integrity and contract verifier for a Aegis enterprise release."""
import argparse, hashlib, json, re, sys, zipfile
from pathlib import Path

RUNTIME_FILES=("aegis_agent.py","aegis-windows.ps1","aegis-policy.json","aegis-security-baseline.md")
HASH_CONSUMERS={
    "aegis_agent.py":("install-aegis.sh","intune-macos-install.sh","intune-macos-compliance.sh"),
    "aegis-windows.ps1":("intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1"),
    "aegis-policy.json":("install-aegis.sh","intune-macos-install.sh","intune-macos-compliance.sh","intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1"),
    "aegis-security-baseline.md":("install-aegis.sh","intune-macos-install.sh","intune-macos-compliance.sh","intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1"),
}
BUNDLE_FILES=(
    "DEPLOYMENT-GUIDE.md","aegis-policy.json","aegis-security-baseline.md","aegis-report.schema.json",
    "aegis_agent.py","aegis_collector.py","aegis-windows.ps1","install-aegis.sh","intune-windows-detect.ps1",
    "intune-windows-remediate.ps1","intune-compliance-discovery.ps1","intune-compliance-policy.json","intune-macos-install.sh",
    "intune-macos-compliance.sh","intune-macos-compliance-policy.json","rollback-aegis-windows.ps1","rollback-aegis-macos.sh",
    "uninstall-aegis-windows.ps1","uninstall-aegis-macos.sh","CHECKSUMS.sha256","release.json","aegis_adapter.py",
    "aegis-adapters.example.json","aegis_release_verify.py","aegis_collector_backup.py","aegis_collector_restore.py",
    "aegis-collector.service","aegis-collector.env.example","aegis-collector.nginx.conf",
    "aegis_adapter_worker.py","aegis-adapter-worker.service","aegis-adapter.env.example",
    "aegis-configure-windows.ps1","aegis-configure-macos.sh","aegis-device-credentials.example.json","aegis_device_credentials.py",
    "aegis_production_preflight.py","aegis_release_build.py","aegis_vendor_probe.py","aegis_4a_interface.py",
)

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def verify(downloads):
    downloads=Path(downloads); errors=[]
    try: release=json.loads((downloads/"release.json").read_text())
    except (OSError,ValueError) as exc: return [f"invalid_release_json:{type(exc).__name__}"]
    if not re.fullmatch(r"\d+\.\d+\.\d+",str(release.get("release",""))): errors.append("invalid_release_version")
    try: policy=json.loads((downloads/"aegis-policy.json").read_text())
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
        versions=[rule.get("Operand") for rule in rules if rule.get("SettingName")=="AegisPolicyVersion"]
        if versions!=[policy.get("version")]: errors.append(f"policy_version_drift:{name}")
    try: service=(downloads/"aegis-collector.service").read_text()
    except OSError as exc: errors.append(f"invalid_collector_service:{type(exc).__name__}"); service=""
    for directive in ("User=aegis","EnvironmentFile=/etc/aegis/collector.env","--listen 127.0.0.1","NoNewPrivileges=true","ProtectSystem=strict","ProtectHome=true","CapabilityBoundingSet="):
        if directive not in service: errors.append(f"unsafe_collector_service:{directive}")
    try: env_example=(downloads/"aegis-collector.env.example").read_text()
    except OSError as exc: errors.append(f"invalid_collector_env:{type(exc).__name__}"); env_example=""
    for secret_name in ("AEGIS_COLLECTOR_TOKEN","AEGIS_REPORT_SIGNING_SECRET"):
        if not re.search(rf"(?m)^{secret_name}=$",env_example): errors.append(f"collector_example_secret_not_empty:{secret_name}")
    if "AEGIS_ALLOW_UNSIGNED_REPORTS=false" not in env_example: errors.append("collector_unsigned_mode_not_disabled")
    if not re.search(r"(?m)^AEGIS_DEVICE_CREDENTIALS_FILE=$",env_example): errors.append("device_credentials_path_not_empty")
    try: nginx=(downloads/"aegis-collector.nginx.conf").read_text()
    except OSError as exc: errors.append(f"invalid_collector_nginx:{type(exc).__name__}"); nginx=""
    for directive in ("listen 443 ssl", "ssl_protocols TLSv1.2 TLSv1.3", "client_max_body_size 2m", "limit_req zone=aegis_reports", "proxy_pass http://127.0.0.1:8788"):
        if directive not in nginx: errors.append(f"unsafe_collector_nginx:{directive}")
    try: worker=(downloads/"aegis_adapter_worker.py").read_text(); worker_service=(downloads/"aegis-adapter-worker.service").read_text()
    except OSError as exc: errors.append(f"invalid_adapter_worker:{type(exc).__name__}"); worker=worker_service=""
    for directive in ("adapter_dispatches","adapter.validate_target","result_summary(outputs)","INSERT OR IGNORE INTO adapter_dispatches"):
        if directive not in worker: errors.append(f"unsafe_adapter_worker:{directive}")
    for directive in ("User=aegis","EnvironmentFile=/etc/aegis/adapter.env","NoNewPrivileges=true","ProtectSystem=strict","CapabilityBoundingSet="):
        if directive not in worker_service: errors.append(f"unsafe_adapter_worker_service:{directive}")
    try: adapter_text=(downloads/"aegis_adapter.py").read_text()
    except OSError as exc: errors.append(f"invalid_adapter:{type(exc).__name__}"); adapter_text=""
    if '"Idempotency-Key":hashlib.sha256(body).hexdigest()' not in adapter_text: errors.append("missing_adapter_idempotency_key")
    try: windows_config=(downloads/"aegis-configure-windows.ps1").read_text(); windows_agent=(downloads/"aegis-windows.ps1").read_text(); mac_config=(downloads/"aegis-configure-macos.sh").read_text(); python_agent=(downloads/"aegis_agent.py").read_text()
    except OSError as exc: errors.append(f"invalid_endpoint_reporting_config:{type(exc).__name__}"); windows_config=windows_agent=mac_config=python_agent=""
    for directive in ("DataProtectionScope]::LocalMachine","AEGIS_REPORT_SIGNING_SECRET","Report token and signing secret must be independent","icacls.exe"):
        if directive not in windows_config: errors.append(f"unsafe_windows_reporting_config:{directive}")
    for directive in ("ProtectedData]::Unprotect","reporting_config_invalid","report_token,report_url,schema,signing_secret"):
        if directive not in windows_agent: errors.append(f"missing_windows_reporting_loader:{directive}")
    for directive in ("umask 077","os.replace(temp,path)","hmac.compare_digest(token,secret)"):
        if directive not in mac_config: errors.append(f"unsafe_macos_reporting_config:{directive}")
    for directive in ("def load_reporting_config(path):","reporting_config_permissions","reporting_config_invalid"):
        if directive not in python_agent: errors.append(f"missing_python_reporting_loader:{directive}")
    for directive in ("def write_upload_status(path,url,now=None):","aegis.upload-status/v1","write_private_atomic(path"):
        if directive not in python_agent: errors.append(f"missing_python_upload_receipt:{directive}")
    for directive in ("function Write-AegisUploadStatus","aegis.upload-status/v1","Write-AegisUploadStatus $ReportUrl"):
        if directive not in windows_agent: errors.append(f"missing_windows_upload_receipt:{directive}")
    for directive in ("response.read(4097)","collector_ack_too_large","collector_ack_invalid_json","collector_ack_invalid_contract",'set(ack)!={"accepted","duplicate","report_id","severity"}',"expected_report_id=hashlib.sha256(body).hexdigest()[:20]",'ack.get("report_id")!=expected_report_id'):
        if directive not in python_agent: errors.append(f"missing_python_strict_ack:{directive}")
    for directive in ("Invoke-WebRequest -UseBasicParsing","GetByteCount([string]$response.Content)","$ackBytes -gt 4096","Collector acknowledgement contract is invalid","accepted,duplicate,report_id,severity","$expectedReportId","-cne $expectedReportId"):
        if directive not in windows_agent: errors.append(f"missing_windows_strict_ack:{directive}")
    try: collector_text=(downloads/"aegis_collector.py").read_text()
    except OSError as exc: errors.append(f"invalid_collector:{type(exc).__name__}"); collector_text=""
    for directive in ("receipt_id=hashlib.sha256(body).hexdigest()[:20]",'"report_id":receipt_id'):
        if directive not in collector_text: errors.append(f"missing_collector_receipt_binding:{directive}")
    for directive in ("def device_credentials(path=None):","aegis.device-credentials/v1","device_credentials_permissions",'report["device_id"]!=binding[0]',"X-Aegis-Device-ID","credential_generation_mismatch","device_auth_state","credential_posture","generated_at=int(time.time())","COALESCE(a.last_seen,r.received_at)","parse_qs(parsed.query","1<=limit<=10000",'"complete":complete',"WITH fleet AS"):
        if directive not in collector_text: errors.append(f"missing_device_identity_boundary:{directive}")
    try: device_example=json.loads((downloads/"aegis-device-credentials.example.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_device_credentials_example:{type(exc).__name__}"); device_example={}
    if device_example!={"schema":"aegis.device-credentials/v1","devices":{"0123456789ab":{"tokens":[""],"signing_secrets":[""]}}}: errors.append("unsafe_device_credentials_example")
    try: provisioner=(downloads/"aegis_device_credentials.py").read_text()
    except OSError as exc: errors.append(f"invalid_device_credential_provisioner:{type(exc).__name__}"); provisioner=""
    for directive in ("secrets.token_urlsafe(48)","os.fsync(handle.fileno())","os.replace(temp,path)","secrets_printed","--prune-old","enrollment_directory_symlink","preserve_metadata=True","os.chown(temp,metadata[1],metadata[2])","stat.S_IMODE(info.st_mode) not in {0o600,0o640}","activation_evidence_required","devices_not_on_current_credentials","--activation-evidence","activation_evidence_stale","now-generated_at<=max_age","generated_at-row[\"last_seen\"]<=active_window",'value.get("complete") is not True'):
        if directive not in provisioner: errors.append(f"unsafe_device_credential_provisioner:{directive}")
    archive=downloads/"aegis-enterprise-bundle.zip"
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
