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
    "sentinel-collector.service","sentinel-collector.env.example","sentinel-collector.nginx.conf",
    "sentinel_adapter_worker.py","sentinel-adapter-worker.service","sentinel-adapter.env.example",
    "sentinel-configure-windows.ps1","sentinel-configure-macos.sh","sentinel-device-credentials.example.json","sentinel_device_credentials.py","sentinel_collector_probe.py","intune-deployment-manifest.json","sentinel_intune_preflight.py","intune-rollout-evidence.example.json","sentinel-collector.openapi.json","sentinel-vendor-contracts.json","sentinel_vendor_preflight.py","vendor-acceptance-evidence.example.json","sentinel-sign-intune.ps1",
)

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def verify(downloads):
    downloads=Path(downloads); errors=[]
    for script in downloads.glob("*.ps1"):
        try: content=script.read_bytes()
        except OSError as exc: errors.append(f"invalid_powershell_encoding:{script.name}:{type(exc).__name__}"); continue
        if any(byte>=128 for byte in content) and not content.startswith(b"\xef\xbb\xbf"): errors.append(f"powershell_5_1_utf8_bom_missing:{script.name}")
    try: release=json.loads((downloads/"release.json").read_text())
    except (OSError,ValueError) as exc: return [f"invalid_release_json:{type(exc).__name__}"]
    if not re.fullmatch(r"\d+\.\d+\.\d+",str(release.get("release",""))): errors.append("invalid_release_version")
    try: policy=json.loads((downloads/"sentinel-policy.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_policy_json:{type(exc).__name__}"); policy={}
    patterns=policy.get("secret_patterns",[]) if isinstance(policy,dict) else []
    required_secret_patterns={"AKIA[0-9A-Z]{16}","sk-[A-Za-z0-9_-]{20,}","ghp_[A-Za-z0-9]{30,}","AIza[0-9A-Za-z_-]{35}","xox[baprs]-[0-9A-Za-z-]{10,}","glpat-[0-9A-Za-z_-]{20,}","npm_[0-9A-Za-z]{36}","-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"}
    if policy.get("version")!="4.9.0" or set(patterns)!=required_secret_patterns: errors.append("policy_secret_pattern_drift")
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
    try: intune=json.loads((downloads/"intune-deployment-manifest.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_intune_manifest:{type(exc).__name__}"); intune={}
    execution=intune.get("execution",{}) if isinstance(intune,dict) else {}; artifacts=intune.get("artifacts",{}) if isinstance(intune,dict) else {}
    if intune.get("schema")!="sentinel.intune-deployment/v1" or intune.get("secrets_embedded") is not False: errors.append("unsafe_intune_manifest_contract")
    state=execution.get("script_signature_state"); expected_execution={"windows_run_as":"system","windows_run_as_32_bit":False,"macos_run_as":"root","macos_hide_notifications":True,"script_signature_state":state,"production_signature_required":True}
    if state not in {"pilot_unsigned","production_signed"} or execution!=expected_execution: errors.append("unsafe_intune_execution_context")
    expected_intune_files={"intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1","intune-compliance-policy.json","sentinel-configure-windows.ps1","rollback-sentinel-windows.ps1","uninstall-sentinel-windows.ps1","intune-macos-install.sh","intune-macos-compliance.sh","intune-macos-compliance-policy.json","sentinel-configure-macos.sh","rollback-sentinel-macos.sh","uninstall-sentinel-macos.sh"}
    listed=[]
    for item in artifacts.values() if isinstance(artifacts,dict) else []:
        if not isinstance(item,dict) or set(item)!={"file","sha256"}: errors.append("invalid_intune_artifact"); continue
        name=item.get("file",""); listed.append(name); path=downloads/name
        if name not in expected_intune_files or not path.is_file() or item.get("sha256")!=digest(path): errors.append(f"intune_artifact_mismatch:{name}")
    if set(listed)!=expected_intune_files or len(listed)!=len(expected_intune_files): errors.append("incomplete_intune_artifact_set")
    signing=intune.get("signing")
    if state=="pilot_unsigned" and signing is not None: errors.append("unexpected_intune_signing_metadata")
    if state=="production_signed":
        signable={"intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1","sentinel-configure-windows.ps1","rollback-sentinel-windows.ps1","uninstall-sentinel-windows.ps1"}
        if not isinstance(signing,dict) or set(signing)!={"certificate_thumbprint","timestamp_server","signed_at","verified_files"} or not re.fullmatch(r"[0-9a-f]{40}",str(signing.get("certificate_thumbprint",""))) or not str(signing.get("timestamp_server","")).startswith("https://") or isinstance(signing.get("signed_at"),bool) or not isinstance(signing.get("signed_at"),int) or set(signing.get("verified_files",[]))!=signable: errors.append("invalid_intune_signing_metadata")
        for name in signable:
            try: signed=(downloads/name).read_text(errors="ignore")
            except OSError: signed=""
            if "# SIG # Begin signature block" not in signed or "# SIG # End signature block" not in signed: errors.append(f"missing_authenticode_signature:{name}")
    if intune.get("deployment_order")!=["collector_and_tls","reporting_credentials","endpoint_installation","reporting_configuration","custom_compliance","conditional_access"]: errors.append("unsafe_intune_deployment_order")
    if intune.get("rollout_rings")!=[{"name":"lab","maximum_percent":1,"minimum_observation_hours":24},{"name":"pilot","maximum_percent":5,"minimum_observation_hours":48},{"name":"broad","maximum_percent":25,"minimum_observation_hours":72},{"name":"production","maximum_percent":100,"minimum_observation_hours":168}]: errors.append("unsafe_intune_rollout_rings")
    if intune.get("gates")!=["collector_probe_read_only_passed","release_verifier_passed","reporting_credentials_delivered_out_of_band","rollback_tested_in_ring","no_critical_findings","reporting_healthy_24h"]: errors.append("incomplete_intune_gates")
    try: evidence=json.loads((downloads/"intune-rollout-evidence.example.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_intune_evidence_example:{type(exc).__name__}"); evidence={}
    expected_evidence={"schema":"sentinel.intune-evidence/v1","generated_at":0,"current_ring":"lab","current_ring_entered_at":0,"collector_probe_read_only_passed":False,"release_verifier_passed":False,"reporting_credentials_delivered_out_of_band":False,"rollback_tested_in_ring":False,"critical_findings":0,"reporting_healthy_since":0,"production_signature_verified":False}
    if evidence!=expected_evidence: errors.append("unsafe_intune_evidence_example")
    try: preflight=(downloads/"sentinel_intune_preflight.py").read_text()
    except OSError as exc: errors.append(f"invalid_intune_preflight:{type(exc).__name__}"); preflight=""
    for directive in ('script_signature_state")!="production_signed"','evidence.get("production_signature_verified") is not True','artifact_digest_mismatch','now-generated>86400','now-healthy<86400','RINGS.index(target_ring)!=RINGS.index(current)+1','now-entered<minimum*3600'):
        if directive not in preflight: errors.append(f"unsafe_intune_preflight:{directive}")
    try: windows_remediation=(downloads/"intune-windows-remediate.ps1").read_text(); windows_detection=(downloads/"intune-windows-detect.ps1").read_text(); windows_compliance=(downloads/"intune-compliance-discovery.ps1").read_text(); macos_install=(downloads/"intune-macos-install.sh").read_text(); macos_compliance=(downloads/"intune-macos-compliance.sh").read_text()
    except OSError as exc: errors.append(f"invalid_endpoint_schedule:{type(exc).__name__}"); windows_remediation=windows_detection=windows_compliance=macos_install=macos_compliance=""
    for directive in ('New-ScheduledTaskTrigger -AtStartup',"Delay = 'PT2M'",'New-TimeSpan -Hours 1','-StartWhenAvailable','-MultipleInstances IgnoreNew','-ExecutionTimeLimit (New-TimeSpan -Minutes 30)','-RestartCount 3'):
        if directive not in windows_remediation: errors.append(f"unsafe_windows_schedule:{directive}")
    for source in (windows_detection,windows_compliance):
        for directive in ("Repetition.Interval -eq 'PT1H'","MSFT_TaskBootTrigger","StartWhenAvailable","MultipleInstances -eq 'IgnoreNew'","ExecutionTimeLimit -eq 'PT30M'","RestartCount -eq 3"):
            if directive not in source: errors.append(f"missing_windows_schedule_compliance:{directive}")
    for directive in ('<key>StartInterval</key><integer>3600</integer>','<key>RunAtLoad</key><true/>','<key>ProcessType</key><string>Background</string>'):
        if directive not in macos_install: errors.append(f"unsafe_macos_schedule:{directive}")
    for directive in ("Print :StartInterval",'[[ "$interval" == 3600 ]]',"Print :RunAtLoad",'[[ "$process_type" == Background ]]'):
        if directive not in macos_compliance: errors.append(f"missing_macos_schedule_compliance:{directive}")
    try: windows_rollback=(downloads/"rollback-sentinel-windows.ps1").read_text(); macos_rollback=(downloads/"rollback-sentinel-macos.sh").read_text()
    except OSError as exc: errors.append(f"invalid_schedule_rollback:{type(exc).__name__}"); windows_rollback=macos_rollback=""
    for directive in ('scheduled-task.xml','Export-ScheduledTask','$taskSafe','Principal.UserId'):
        if directive not in windows_remediation: errors.append(f"missing_windows_task_snapshot:{directive}")
    for directive in ('scheduled-task.xml','Previous scheduled task snapshot is missing or oversized','failed the safety contract','Register-ScheduledTask'):
        if directive not in windows_rollback: errors.append(f"unsafe_windows_task_rollback:{directive}")
    for directive in ('launch-daemon.plist','PlistBuddy','CURRENT_COMPLETE=0'):
        if directive not in macos_install: errors.append(f"missing_macos_daemon_snapshot:{directive}")
    for directive in ('launch-daemon.plist','Previous LaunchDaemon snapshot is missing or oversized','failed the safety contract'):
        if directive not in macos_rollback: errors.append(f"unsafe_macos_daemon_rollback:{directive}")
    try: windows_uninstall=(downloads/"uninstall-sentinel-windows.ps1").read_text(); macos_uninstall=(downloads/"uninstall-sentinel-macos.sh").read_text()
    except OSError as exc: errors.append(f"invalid_uninstall_boundary:{type(exc).__name__}"); windows_uninstall=macos_uninstall=""
    for directive in ('ReparsePoint','$starts.Count -ne 1','$ends.Count -ne 1','$starts[0].Index -ge $ends[0].Index','refusing recursive removal'):
        if directive not in windows_uninstall: errors.append(f"unsafe_windows_uninstall:{directive}")
    for directive in ('[ ! -L "$home" ]','[ ! -L "$(/usr/bin/dirname "$file")" ]','start_count','end_count','refusing recursive removal','not owned by root'):
        if directive not in macos_uninstall: errors.append(f"unsafe_macos_uninstall:{directive}")
    try: service=(downloads/"sentinel-collector.service").read_text()
    except OSError as exc: errors.append(f"invalid_collector_service:{type(exc).__name__}"); service=""
    for directive in ("User=sentinel","EnvironmentFile=/etc/sentinel/collector.env","--listen 127.0.0.1","NoNewPrivileges=true","ProtectSystem=strict","ProtectHome=true","CapabilityBoundingSet="):
        if directive not in service: errors.append(f"unsafe_collector_service:{directive}")
    try: env_example=(downloads/"sentinel-collector.env.example").read_text()
    except OSError as exc: errors.append(f"invalid_collector_env:{type(exc).__name__}"); env_example=""
    for secret_name in ("SENTINEL_COLLECTOR_TOKEN","SENTINEL_REPORT_SIGNING_SECRET"):
        if not re.search(rf"(?m)^{secret_name}=$",env_example): errors.append(f"collector_example_secret_not_empty:{secret_name}")
    if "SENTINEL_ALLOW_UNSIGNED_REPORTS=false" not in env_example: errors.append("collector_unsigned_mode_not_disabled")
    if not re.search(r"(?m)^SENTINEL_DEVICE_CREDENTIALS_FILE=$",env_example): errors.append("device_credentials_path_not_empty")
    try: nginx=(downloads/"sentinel-collector.nginx.conf").read_text()
    except OSError as exc: errors.append(f"invalid_collector_nginx:{type(exc).__name__}"); nginx=""
    for directive in ("listen 443 ssl", "ssl_protocols TLSv1.2 TLSv1.3", "client_max_body_size 2m", "limit_req zone=sentinel_reports", "proxy_pass http://127.0.0.1:8788"):
        if directive not in nginx: errors.append(f"unsafe_collector_nginx:{directive}")
    try: worker=(downloads/"sentinel_adapter_worker.py").read_text(); worker_service=(downloads/"sentinel-adapter-worker.service").read_text()
    except OSError as exc: errors.append(f"invalid_adapter_worker:{type(exc).__name__}"); worker=worker_service=""
    for directive in ("adapter_dispatches","adapter.validate_target","result_summary(outputs)","INSERT OR IGNORE INTO adapter_dispatches"):
        if directive not in worker: errors.append(f"unsafe_adapter_worker:{directive}")
    for directive in ("User=sentinel","EnvironmentFile=/etc/sentinel/adapter.env","--acceptance /etc/sentinel/vendor-acceptance.json","NoNewPrivileges=true","ProtectSystem=strict","CapabilityBoundingSet="):
        if directive not in worker_service: errors.append(f"unsafe_adapter_worker_service:{directive}")
    try: adapter_text=(downloads/"sentinel_adapter.py").read_text()
    except OSError as exc: errors.append(f"invalid_adapter:{type(exc).__name__}"); adapter_text=""
    if '"Idempotency-Key":hashlib.sha256(body).hexdigest()' not in adapter_text: errors.append("missing_adapter_idempotency_key")
    for directive in ('SentinelAdapter/0.9','action not in SAFE_ACTIONS','set(compliance)!={"max_policy_age_hours","critical_allowed"}','not 1<=age<=168','critical!=0'):
        if directive not in adapter_text: errors.append(f"missing_vendor_config_boundary:{directive}")
    try: vendor_contract=json.loads((downloads/"sentinel-vendor-contracts.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_vendor_contract:{type(exc).__name__}"); vendor_contract={}
    if vendor_contract.get("schema")!="sentinel.vendor-contracts/v1" or vendor_contract.get("adapter_version")!="0.9" or vendor_contract.get("secrets_embedded") is not False: errors.append("vendor_contract_version_drift")
    transport=vendor_contract.get("transport",{}); boundaries=vendor_contract.get("credential_boundaries",{})
    if transport.get("scheme")!="https" or transport.get("timeout_seconds")!=15 or transport.get("idempotency_header")!="Idempotency-Key" or transport.get("credentials_in_url_allowed") is not False: errors.append("unsafe_vendor_transport_contract")
    if vendor_contract.get("sangfor",{}).get("safe_actions")!=["observe","alert","isolate_pending_approval","block_pending_approval"] or vendor_contract.get("sangfor",{}).get("direct_destructive_actions_allowed") is not False: errors.append("unsafe_sangfor_contract")
    if vendor_contract.get("leagsoft",{}).get("compliance_configuration")!={"max_policy_age_hours_min":1,"max_policy_age_hours_max":168,"critical_allowed":0}: errors.append("unsafe_leagsoft_contract")
    if [boundaries.get(name,{}).get("allowed_env_prefix") for name in ("sangfor","leagsoft","security_webhook")]!=["SANGFOR_","LEAGSOFT_","SENTINEL_"]: errors.append("vendor_credential_boundary_drift")
    enablement=vendor_contract.get("production_enablement",{})
    if enablement!={"evidence_schema":"sentinel.vendor-acceptance/v1","maximum_evidence_age_seconds":604800,"required_for":["sangfor","leagsoft"],"secrets_allowed":False}: errors.append("vendor_enablement_contract_drift")
    try: vendor_evidence=json.loads((downloads/"vendor-acceptance-evidence.example.json").read_text()); vendor_preflight=(downloads/"sentinel_vendor_preflight.py").read_text()
    except (OSError,ValueError) as exc: errors.append(f"invalid_vendor_preflight:{type(exc).__name__}"); vendor_evidence={}; vendor_preflight=""
    if vendor_evidence.get("schema")!="sentinel.vendor-acceptance/v1" or vendor_evidence.get("adapter_version")!="0.9" or vendor_evidence.get("secrets_embedded") is not False: errors.append("unsafe_vendor_acceptance_example")
    for directive in ('max_age_seconds=604800','vendor_endpoint_not_accepted','vendor_gate_failed','vendor_acceptance_must_be_secret_free','auth_scheme'):
        if directive not in vendor_preflight: errors.append(f"unsafe_vendor_preflight:{directive}")
    for directive in ('--acceptance','vendor_acceptance_failed','adapter_version="0.9"'):
        if directive not in worker: errors.append(f"missing_vendor_worker_gate:{directive}")
    try: windows_config=(downloads/"sentinel-configure-windows.ps1").read_text(); windows_agent=(downloads/"sentinel-windows.ps1").read_text(); mac_config=(downloads/"sentinel-configure-macos.sh").read_text(); python_agent=(downloads/"sentinel_agent.py").read_text()
    except OSError as exc: errors.append(f"invalid_endpoint_reporting_config:{type(exc).__name__}"); windows_config=windows_agent=mac_config=python_agent=""
    for directive in ("DataProtectionScope]::LocalMachine","SENTINEL_REPORT_SIGNING_SECRET","Report token and signing secret must be independent","icacls.exe"):
        if directive not in windows_config: errors.append(f"unsafe_windows_reporting_config:{directive}")
    for directive in ("ProtectedData]::Unprotect","reporting_config_invalid","report_token,report_url,schema,signing_secret"):
        if directive not in windows_agent: errors.append(f"missing_windows_reporting_loader:{directive}")
    for directive in ("umask 077","os.replace(temp,path)","hmac.compare_digest(token,secret)"):
        if directive not in mac_config: errors.append(f"unsafe_macos_reporting_config:{directive}")
    for directive in ("def load_reporting_config(path):","reporting_config_permissions","reporting_config_invalid"):
        if directive not in python_agent: errors.append(f"missing_python_reporting_loader:{directive}")
    for directive in ('"gemini_cli"','"github_copilot_cli"','".gemini/settings.json"','".copilot/mcp-config.json"','".gemini/GEMINI.md"','".copilot/copilot-instructions.md"','cfg.get("httpUrl"','".gemini/skills"','".copilot/skills"','def verify_user_baselines','"agent_baseline_not_loaded"','"type":"agent_baseline"','SentinelAgent/0.35.0'):
        if directive not in python_agent: errors.append(f"missing_python_agent_coverage:{directive}")
    for directive in ("gemini_cli=@(","github_copilot_cli=@(",".gemini\\GEMINI.md","copilot-instructions.md","$cfg.httpUrl","'.gemini','.copilot'","Get-SentinelUserBaselineStatus","type='agent_baseline'","agent_baseline_not_loaded","agent_version='0.35.0'","foreach ($userHome in $userHomes)","function Get-SentinelUserBaselineStatus([string]$userHomePath","[string]$ManagedUsersRoot = 'C:\\Users'","Get-ChildItem $ManagedUsersRoot","foreach($secretPattern in @($policy.secret_patterns))","[regex]::new([string]$secretPattern","[TimeSpan]::FromMilliseconds(250)","RegexMatchTimeoutException","scan_rule_timeout","Kind='credential_access'","Kind='dynamic_eval'"):
        if directive not in windows_agent: errors.append(f"missing_windows_agent_coverage:{directive}")
    for directive in ("def write_upload_status(path,url,now=None):","sentinel.upload-status/v1","write_private_atomic(path"):
        if directive not in python_agent: errors.append(f"missing_python_upload_receipt:{directive}")
    for directive in ("function Write-SentinelUploadStatus","sentinel.upload-status/v1","Write-SentinelUploadStatus $ReportUrl"):
        if directive not in windows_agent: errors.append(f"missing_windows_upload_receipt:{directive}")
    for directive in ("response.read(4097)","collector_ack_too_large","collector_ack_invalid_json","collector_ack_invalid_contract",'set(ack)!={"accepted","duplicate","report_id","severity"}',"expected_report_id=hashlib.sha256(body).hexdigest()[:20]",'ack.get("report_id")!=expected_report_id'):
        if directive not in python_agent: errors.append(f"missing_python_strict_ack:{directive}")
    for directive in ("Invoke-WebRequest -UseBasicParsing","GetByteCount([string]$response.Content)","$ackBytes -gt 4096","Collector acknowledgement contract is invalid","accepted,duplicate,report_id,severity","$expectedReportId","-cne $expectedReportId"):
        if directive not in windows_agent: errors.append(f"missing_windows_strict_ack:{directive}")
    try: collector_text=(downloads/"sentinel_collector.py").read_text()
    except OSError as exc: errors.append(f"invalid_collector:{type(exc).__name__}"); collector_text=""
    for directive in ("receipt_id=hashlib.sha256(body).hexdigest()[:20]",'"report_id":receipt_id'):
        if directive not in collector_text: errors.append(f"missing_collector_receipt_binding:{directive}")
    for directive in ("def device_credentials(path=None):","sentinel.device-credentials/v1","device_credentials_permissions",'report["device_id"]!=binding[0]',"X-Sentinel-Device-ID","credential_generation_mismatch","device_auth_state","credential_posture","generated_at=int(time.time())","COALESCE(a.last_seen,r.received_at)","parse_qs(parsed.query","1<=limit<=10000",'"complete":complete',"WITH fleet AS","agent_coverage","supported_agents=",'item.get("type")=="ai_agent"',"baseline_coverage",'item.get("type")=="agent_baseline"','"0.35.0"','"4.9.0"',"SentinelCollector/0.17"):
        if directive not in collector_text: errors.append(f"missing_device_identity_boundary:{directive}")
    try: openapi=json.loads((downloads/"sentinel-collector.openapi.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_collector_openapi:{type(exc).__name__}"); openapi={}
    paths=openapi.get("paths",{}) if isinstance(openapi,dict) else {}; components=openapi.get("components",{}) if isinstance(openapi,dict) else {}
    expected_methods={"/health":{"get"},"/v1/reports":{"post"},"/v1/summary":{"get"},"/v1/devices":{"get"},"/v1/audit":{"get"}}
    if openapi.get("openapi")!="3.1.0" or openapi.get("info",{}).get("version")!="0.17.0": errors.append("collector_openapi_version_drift")
    fleet_schema=components.get("schemas",{}).get("FleetSummary",{})
    if "baseline_coverage" not in fleet_schema.get("required",[]) or "baseline_coverage" not in fleet_schema.get("properties",{}): errors.append("collector_openapi_baseline_coverage_drift")
    if set(paths)!=set(expected_methods) or any(set(paths.get(path,{}))!=methods for path,methods in expected_methods.items()): errors.append("collector_openapi_route_drift")
    report_post=paths.get("/v1/reports",{}).get("post",{}); report_responses=report_post.get("responses",{})
    if report_post.get("x-sentinel-max-body-bytes")!=2_000_000 or report_post.get("x-sentinel-signature-input")!="<timestamp>.<device_id>.<raw-body>": errors.append("collector_openapi_signature_drift")
    if report_post.get("requestBody",{}).get("content",{}).get("application/json",{}).get("schema")!={"$ref":"sentinel-report.schema.json"}: errors.append("collector_openapi_report_schema_drift")
    if set(report_responses)!={"200","202","400","401","413","429","503"}: errors.append("collector_openapi_report_response_drift")
    if components.get("securitySchemes",{}).get("bearerAuth")!={"type":"http","scheme":"bearer"}: errors.append("collector_openapi_auth_drift")
    parameters=components.get("parameters",{}); expected_headers={"Timestamp":"X-Sentinel-Timestamp","Signature":"X-Sentinel-Signature","DeviceId":"X-Sentinel-Device-ID"}
    if any(parameters.get(key,{}).get("name")!=value or parameters.get(key,{}).get("in")!="header" for key,value in expected_headers.items()): errors.append("collector_openapi_header_drift")
    try: device_example=json.loads((downloads/"sentinel-device-credentials.example.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_device_credentials_example:{type(exc).__name__}"); device_example={}
    if device_example!={"schema":"sentinel.device-credentials/v1","devices":{"0123456789ab":{"tokens":[""],"signing_secrets":[""]}}}: errors.append("unsafe_device_credentials_example")
    try: provisioner=(downloads/"sentinel_device_credentials.py").read_text()
    except OSError as exc: errors.append(f"invalid_device_credential_provisioner:{type(exc).__name__}"); provisioner=""
    for directive in ("secrets.token_urlsafe(48)","os.fsync(handle.fileno())","os.replace(temp,path)","secrets_printed","--prune-old","enrollment_directory_symlink","preserve_metadata=True","os.chown(temp,metadata[1],metadata[2])","stat.S_IMODE(info.st_mode) not in {0o600,0o640}","activation_evidence_required","devices_not_on_current_credentials","--activation-evidence","activation_evidence_stale","now-generated_at<=max_age","generated_at-row[\"last_seen\"]<=active_window",'value.get("complete") is not True'):
        if directive not in provisioner: errors.append(f"unsafe_device_credential_provisioner:{directive}")
    try: probe=(downloads/"sentinel_collector_probe.py").read_text()
    except OSError as exc: errors.append(f"invalid_collector_probe:{type(exc).__name__}"); probe=""
    for directive in ('parser.add_argument("--write-test",action="store_true")','parsed.scheme!="https"','parsed.username or parsed.password or parsed.query or parsed.fragment','expected=(401,)','/v1/devices?limit=10000','X-Sentinel-Device-ID','digest[:20]','expected_duplicate','hmac.compare_digest(token,secret)','MAX_RESPONSE=1_000_000'):
        if directive not in probe: errors.append(f"unsafe_collector_probe:{directive}")
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
