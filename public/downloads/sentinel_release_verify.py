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
    "DEPLOYMENT-GUIDE.md","PRODUCTION-READINESS.md","RULE-UPDATE-GUIDE.md","ENTERPRISE-INTEGRATION-CONTRACT.md","CLIENT-ARCHITECTURE-ROADMAP.md","sentinel-client-control-policy.json","sentinel_client_update_planner.py","sentinel-service-health.schema.json","RELEASE-MANIFEST.sha256","sentinel-policy.json","sentinel-security-baseline.md","sentinel-report.schema.json",
    "sentinel_agent.py","sentinel_collector.py","sentinel-windows.ps1","install-sentinel.sh","intune-windows-detect.ps1",
    "intune-windows-remediate.ps1","intune-compliance-discovery.ps1","intune-compliance-policy.json","intune-macos-install.sh",
    "intune-macos-compliance.sh","intune-macos-compliance-policy.json","rollback-sentinel-windows.ps1","rollback-sentinel-macos.sh",
    "uninstall-sentinel-windows.ps1","uninstall-sentinel-macos.sh","CHECKSUMS.sha256","release.json","sentinel_adapter.py","sentinel_release_build.py",
    "sentinel-adapters.example.json","sentinel_release_verify.py","sentinel_collector_backup.py","sentinel_collector_restore.py","sentinel_4a_probe.py","sentinel_vendor_probe.py","sentinel_vendor_evidence_sign.py","sentinel_vendor_keyring.py","sentinel_production_preflight.py","sentinel_production_evidence_prepare.py","sentinel_production_evidence_sign.py","sentinel_production_keyring.py","production-acceptance-evidence.example.json",
    "sentinel-collector.service","sentinel-collector.env.example","sentinel-collector.nginx.conf","sentinel_collector_maintenance.py","sentinel-collector-maintenance.service","sentinel-collector-maintenance.timer",
    "sentinel-rule-sources.json","sentinel_rule_updater.py","sentinel-rule-update.service","sentinel-rule-update.timer",
    "sentinel_adapter_worker.py","sentinel-adapter-worker.service","sentinel-adapter.env.example","sentinel_4a_interface.py","sentinel_integration_registry.py","sentinel-integration-providers.example.json","sentinel-integration-registry.conf","sentinel_4a_receiver.py","sentinel-4a-receiver.service",
    "sentinel-configure-windows.ps1","sentinel-configure-macos.sh","sentinel-device-credentials.example.json","sentinel_device_credentials.py","sentinel_collector_probe.py","sentinel_deployment_preflight.py","deployment-platform-evidence.example.json","intune-deployment-manifest.json","sentinel_intune_preflight.py","sentinel_intune_evidence.py","sentinel_intune_graph_normalize.py","intune-rollout-evidence.example.json","intune-device-export.example.json","intune-graph-export.example.json","sentinel-collector.openapi.json","sentinel-vendor-contracts.json","sentinel-enterprise-4a.openapi.json","ENTERPRISE-4A-INTEGRATION.md","sentinel_vendor_preflight.py","vendor-acceptance-evidence.example.json","sentinel-sign-intune.ps1",
)
RELEASE_MANIFEST_FILES=tuple(name for name in BUNDLE_FILES if name!="RELEASE-MANIFEST.sha256")

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def parse_digest_manifest(path):
    result={}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not re.fullmatch(r"[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._-]{0,127}",line): raise ValueError("invalid_digest_line")
        value,name=line.split("  ",1)
        if name in result: raise ValueError("duplicate_digest_name")
        result[name]=value
    return result
def verify(downloads):
    downloads=Path(downloads); errors=[]
    for script in downloads.glob("*.ps1"):
        try: content=script.read_bytes()
        except OSError as exc: errors.append(f"invalid_powershell_encoding:{script.name}:{type(exc).__name__}"); continue
        if any(byte>=128 for byte in content) and not content.startswith(b"\xef\xbb\xbf"): errors.append(f"powershell_5_1_utf8_bom_missing:{script.name}")
    try: release=json.loads((downloads/"release.json").read_text())
    except (OSError,ValueError) as exc: return [f"invalid_release_json:{type(exc).__name__}"]
    if not re.fullmatch(r"\d+\.\d+\.\d+",str(release.get("release",""))): errors.append("invalid_release_version")
    if release.get("component_versions")!={"endpoint_agent":"0.43.0","policy":"5.1.0","collector":"0.20","adapter":"0.19"}: errors.append("release_component_version_drift")
    try: release_manifest=parse_digest_manifest(downloads/"RELEASE-MANIFEST.sha256")
    except (OSError,UnicodeError,ValueError) as exc: errors.append(f"invalid_release_manifest:{type(exc).__name__}"); release_manifest={}
    if set(release_manifest)!=set(RELEASE_MANIFEST_FILES): errors.append("release_manifest_file_set_mismatch")
    for name in RELEASE_MANIFEST_FILES:
        path=downloads/name
        if not path.is_file() or release_manifest.get(name)!=digest(path): errors.append(f"release_manifest_digest_mismatch:{name}")
    try: readiness=(downloads/"PRODUCTION-READINESS.md").read_text(encoding="utf-8")
    except (OSError,UnicodeError) as exc: errors.append(f"invalid_production_readiness:{type(exc).__name__}"); readiness=""
    for directive in ("Collector 上线","终端管理平台分阶段部署","企业 4A 标准接口","可选深信服 EDR 兼容边界","可选联软桌管兼容边界","失败回退","生产签署记录","未完成","不得用本地测试或 CI 替代"):
        if directive not in readiness: errors.append(f"incomplete_production_readiness:{directive}")
    try: production_preflight=(downloads/"sentinel_production_preflight.py").read_text(encoding="utf-8"); production_preparer=(downloads/"sentinel_production_evidence_prepare.py").read_text(encoding="utf-8"); production_signer=(downloads/"sentinel_production_evidence_sign.py").read_text(encoding="utf-8"); production_keyring=(downloads/"sentinel_production_keyring.py").read_text(encoding="utf-8"); production_example=json.loads((downloads/"production-acceptance-evidence.example.json").read_text(encoding="utf-8"))
    except (OSError,UnicodeError,ValueError) as exc: errors.append(f"invalid_production_acceptance:{type(exc).__name__}"); production_preflight=production_preparer=production_signer=production_keyring=""; production_example={}
    for directive in ("sentinel.production-acceptance/v3","MAX_EVIDENCE_BYTES=64*1024","MAX_SIGNING_KEYS_BYTES=64*1024","MAX_RECORD_BYTES=2*1024*1024","O_NOFOLLOW","dir_fd=root_fd","unsafe_evidence_root","evidence_record_mismatch:","approval_record_mismatch:","duplicate_evidence_record","unsafe_production_signing_keyring","hmac.compare_digest","SENTINEL_PRODUCTION_ACCEPTANCE_SIGNING_KEYS","evidence_digest_missing:","approval_digest_missing:","invalid_production_signature","--evidence-root","--expected-git-commit","--expected-site-version","--keyring","git_commit_mismatch","site_version_mismatch","release_manifest_mismatch","gate_failed:","approval_missing:","device_identifiers_must_not_be_embedded"):
        if directive not in production_preflight: errors.append(f"unsafe_production_preflight:{directive}")
    for directive in ("private_atomic_output","canonical_unsigned","validate_unsigned","release_binding_mismatch","git_commit_mismatch","site_version_mismatch","production_gate_not_approved","production_record_mismatch:","production_approval_record_mismatch:","stale_or_future_evidence","production_signing_key_unavailable","secrets_embedded","--evidence-root","--expected-git-commit","--expected-site-version","--keyring"):
        if directive not in production_signer: errors.append(f"unsafe_production_signer:{directive}")
    for directive in ("record_digest","private_atomic_output","signed_evidence_must_not_be_reprepared","duplicate_evidence_record","checks_changed","record_count\":14"):
        if directive not in production_preparer: errors.append(f"unsafe_production_preparer:{directive}")
    for directive in ("secrets.token_urlsafe(48)","private_atomic_output","verify_retirement_evidence","cannot_remove_last_production_acceptance_key","unsafe_production_key_retirement","secrets_printed"):
        if directive not in production_keyring: errors.append(f"unsafe_production_keyring:{directive}")
    expected_production_checks={"release_verified","ci_gates_passed","collector_probe_passed","collector_backup_restore_tested","deployment_platform_preflight_passed","windows_upgrade_rollback_tested","macos_upgrade_rollback_tested","enterprise_4a_interface_accepted","optional_adapters_disabled_or_accepted","console_read_only_connected"}; expected_production_approvals={"security_owner","endpoint_owner","platform_owner","business_owner"}
    integrity=production_example.get("integrity",{}); approvals=production_example.get("approvals",{}); evidence_files=production_example.get("evidence_files",{})
    approvals=approvals if isinstance(approvals,dict) else {}; evidence_files=evidence_files if isinstance(evidence_files,dict) else {}
    if production_example.get("schema")!="sentinel.production-acceptance/v3" or production_example.get("release_version")!=release.get("release") or production_example.get("secrets_embedded") is not False or production_example.get("device_identifiers_embedded") is not False or set(production_example.get("checks",{}))!=expected_production_checks or any(production_example.get("checks",{}).values()) or set(evidence_files)!=expected_production_checks or any(not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",value) for value in evidence_files.values()) or len(set(evidence_files.values()))!=len(expected_production_checks) or set(production_example.get("evidence_sha256",{}))!=expected_production_checks or set(production_example.get("evidence_sha256",{}).values())!={"REPLACE_WITH_SHA256"} or set(approvals)!=expected_production_approvals or any(not isinstance(value,dict) or set(value)!={"identity","evidence_file","evidence_sha256"} or value.get("identity")!="" or value.get("evidence_sha256")!="REPLACE_WITH_SHA256" or not isinstance(value.get("evidence_file"),str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",value["evidence_file"]) for value in approvals.values()) or integrity!={"algorithm":"hmac-sha256","key_id":"REPLACE_WITH_KEY_ID","signature":"REPLACE_WITH_HMAC_SHA256"}: errors.append("unsafe_production_acceptance_example")
    try: deployment_preflight=(downloads/"sentinel_deployment_preflight.py").read_text(); deployment_example=json.loads((downloads/"deployment-platform-evidence.example.json").read_text())
    except (OSError,ValueError,UnicodeError) as exc: errors.append(f"invalid_deployment_platform_gate:{type(exc).__name__}"); deployment_preflight=""; deployment_example={}
    for directive in ('sentinel.deployment-platform-acceptance/v1','PLATFORM_TYPES={"mdm","desktop_management","software_distribution","manual_controlled"}','RINGS=("lab","pilot","broad","production")','OBSERVATION_HOURS=(24,48,72,168)','ratio(installed,assigned)<0.95','ratio(reporting,assigned)<0.95','ratio(compliant,assigned)<0.95','ratio(failed,assigned)>0.02','secrets_embedded','device_identifiers_embedded','O_NOFOLLOW'):
        if directive not in deployment_preflight: errors.append(f"unsafe_deployment_platform_gate:{directive}")
    if deployment_example.get("schema")!="sentinel.deployment-platform-acceptance/v1" or deployment_example.get("release_version")!=release.get("release") or [item.get("name") for item in deployment_example.get("rings",[])]!=["lab","pilot","broad","production"] or deployment_example.get("secrets_embedded") is not False or deployment_example.get("device_identifiers_embedded") is not False: errors.append("unsafe_deployment_platform_example")
    try: policy=json.loads((downloads/"sentinel-policy.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_policy_json:{type(exc).__name__}"); policy={}
    patterns=policy.get("secret_patterns",[]) if isinstance(policy,dict) else []
    required_secret_patterns={"AKIA[0-9A-Z]{16}","sk-[A-Za-z0-9_-]{20,}","ghp_[A-Za-z0-9]{30,}","AIza[0-9A-Za-z_-]{35}","xox[baprs]-[0-9A-Za-z-]{10,}","glpat-[0-9A-Za-z_-]{20,}","npm_[0-9A-Za-z]{36}","-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"}
    if policy.get("version")!="5.1.0" or set(patterns)!=required_secret_patterns: errors.append("policy_secret_pattern_drift")
    for prefix,suffix in (("skill","skills"),("mcp","mcp_servers")):
        groups=[]
        for state in ("allowed","monitored","blocked"):
            values=policy.get(f"{state}_{suffix}",[])
            if not isinstance(values,list) or any(not isinstance(value,str) or not value for value in values): errors.append(f"invalid_{state}_{prefix}_disposition"); values=[]
            groups.append(set(values))
        if groups[0]&groups[1] or groups[0]&groups[2] or groups[1]&groups[2]: errors.append(f"conflicting_{prefix}_disposition")
    fingerprints=policy.get("blocked_mcp_fingerprints",[])
    if not isinstance(fingerprints,list) or any(not isinstance(value,str) or not re.fullmatch(r"sha256:[0-9a-f]{64}",value) for value in fingerprints): errors.append("invalid_blocked_mcp_fingerprints")
    try: integration_contract=(downloads/"ENTERPRISE-INTEGRATION-CONTRACT.md").read_text(encoding="utf-8"); integration_interface=(downloads/"sentinel_4a_interface.py").read_text(encoding="utf-8")
    except (OSError,UnicodeError) as exc: errors.append(f"invalid_enterprise_integration_contract:{type(exc).__name__}"); integration_contract=integration_interface=""
    for directive in ("能力而非厂商","Windows/macOS 上只新增 Sentinel Endpoint Agent","强制加载安全编码基线","allow / monitor / deny / unknown","SHA-256 指纹拉黑"):
        if directive not in integration_contract: errors.append(f"incomplete_enterprise_integration_contract:{directive}")
    try: client_roadmap=(downloads/"CLIENT-ARCHITECTURE-ROADMAP.md").read_text(encoding="utf-8")
    except (OSError,UnicodeError) as exc: errors.append(f"invalid_client_architecture_roadmap:{type(exc).__name__}"); client_roadmap=""
    for directive in ("外部平台部署 Sentinel","Sentinel 不安装、不升级、不卸载 MDM、EDR、4A、NAC 或桌管客户端","Windows Service","LaunchDaemon","allow / monitor / deny / unknown","为什么不让 Sentinel 推送其他客户端","何时允许 Sentinel 自更新","自动回滚 + 熔断本版本","不可变安全原则"):
        if directive not in client_roadmap: errors.append(f"incomplete_client_architecture_roadmap:{directive}")
    try: client_control=json.loads((downloads/"sentinel-client-control-policy.json").read_text(encoding="utf-8")); update_planner=(downloads/"sentinel_client_update_planner.py").read_text(encoding="utf-8")
    except (OSError,UnicodeError,ValueError) as exc: errors.append(f"invalid_client_control:{type(exc).__name__}"); client_control={}; update_planner=""
    if client_control.get("schema")!="sentinel.client-control/v1" or client_control.get("binary_delivery",{}).get("mode")!="external_managed" or client_control.get("binary_delivery",{}).get("self_update",{}).get("enabled") is not False: errors.append("unsafe_default_binary_delivery")
    for directive in ("external_deployment_required","software_lifecycle_owner","require_platform_signature","require_release_signature","require_dual_slot_rollback","maintenance_window","circuit_breaker","apply_content_atomically","keep_lkg"):
        if directive not in update_planner: errors.append(f"unsafe_client_update_planner:{directive}")
    try: health_schema=json.loads((downloads/"sentinel-service-health.schema.json").read_text(encoding="utf-8"))
    except (OSError,UnicodeError,ValueError) as exc: errors.append(f"invalid_service_health_schema:{type(exc).__name__}"); health_schema={}
    required_health={"schema","host_version","state","service_started_at","updated_at","last_scan_started_at","last_scan_exit_code","scanner","error","arbitrary_command_enabled"}
    if health_schema.get("additionalProperties") is not False or set(health_schema.get("required",[]))!=required_health or health_schema.get("properties",{}).get("arbitrary_command_enabled")!={"const":False}: errors.append("unsafe_service_health_schema")
    for directive in ("sentinel.integration/v1","IDENTITY_AUTHENTICATION","SOFTWARE_DISTRIBUTION","CONTAINMENT_REQUEST","privileged_capability_requires_approval","missing_capabilities"):
        if directive not in integration_interface: errors.append(f"unsafe_enterprise_integration_interface:{directive}")
    try: registry_source=(downloads/"sentinel_integration_registry.py").read_text(encoding="utf-8"); registry_example=json.loads((downloads/"sentinel-integration-providers.example.json").read_text(encoding="utf-8"))
    except (OSError,UnicodeError,ValueError) as exc: errors.append(f"invalid_integration_registry:{type(exc).__name__}"); registry_source=""; registry_example={}
    for directive in ("sentinel.integration-registry/v1","oauth2_client_credentials","mtls","unsafe_endpoint","credential_env","approval_enforced"):
        if directive not in registry_source: errors.append(f"unsafe_integration_registry:{directive}")
    if registry_example.get("schema")!="sentinel.integration-registry/v1" or not isinstance(registry_example.get("providers"),list) or len(registry_example["providers"])<2: errors.append("invalid_integration_registry_example")
    try: registry_dropin=(downloads/"sentinel-integration-registry.conf").read_text(encoding="utf-8")
    except (OSError,UnicodeError) as exc: errors.append(f"invalid_integration_registry_dropin:{type(exc).__name__}"); registry_dropin=""
    if registry_dropin!="[Service]\nExecStartPre=/usr/bin/python3 /opt/sentinel/sentinel_integration_registry.py /etc/sentinel/integration-providers.json\n": errors.append("unsafe_integration_registry_dropin")
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
    custom_rules=policy.get("custom_rules",[]) if isinstance(policy,dict) else []
    if not isinstance(custom_rules,list) or len(custom_rules)<20 or len(custom_rules)>500: errors.append("invalid_custom_rule_count")
    else:
        ids=set()
        for index,item in enumerate(custom_rules):
            if not isinstance(item,dict) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,79}",str(item.get("id",""))) or item.get("id") in ids or item.get("scope") not in {"all","code","skill","mcp"} or item.get("severity") not in {"critical","high","medium","low"}: errors.append(f"invalid_custom_rule:{index}"); continue
            try: re.compile(item.get("pattern",""))
            except (re.error,TypeError): errors.append(f"invalid_custom_rule_regex:{index}")
            ids.add(item["id"])
    sources=policy.get("rule_sources",[]) if isinstance(policy,dict) else []
    if not isinstance(sources,list) or {item.get("id") for item in sources if isinstance(item,dict)}!={"cisco-skill-scanner","cisco-mcp-scanner","semgrep-community","gitleaks-core","snyk-agent-scan","owasp-agentic-2026"}: errors.append("invalid_rule_sources")
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
    expected_evidence={"schema":"sentinel.intune-evidence/v3","release_version":release.get("release"),"manifest_sha256":digest(downloads/"intune-deployment-manifest.json"),"generated_at":0,"current_ring":"lab","current_ring_entered_at":0,"fleet_total_devices":0,"ring_assigned_devices":0,"reporting_devices":0,"compliant_devices":0,"installation_failures":0,"collector_probe_read_only_passed":False,"release_verifier_passed":False,"reporting_credentials_delivered_out_of_band":False,"rollback_tested_in_ring":False,"critical_findings":0,"reporting_healthy_since":0,"production_signature_verified":False}
    if evidence!=expected_evidence: errors.append("unsafe_intune_evidence_example")
    try: preflight=(downloads/"sentinel_intune_preflight.py").read_text()
    except OSError as exc: errors.append(f"invalid_intune_preflight:{type(exc).__name__}"); preflight=""
    for directive in ('script_signature_state")!="production_signed"','evidence.get("production_signature_verified") is not True','artifact_digest_mismatch','now-generated>86400','now-healthy<86400','RINGS.index(target_ring)!=RINGS.index(current)+1','now-entered<minimum*3600','MAX_INTUNE_EVIDENCE_BYTES=65_536','MAX_INTUNE_MANIFEST_BYTES=262_144','MAX_INTUNE_RELEASE_BYTES=65_536','MAX_INTUNE_ARTIFACT_BYTES=2_000_000','def read_bytes_bounded','before=path.lstat()','getattr(os,"O_NOFOLLOW",0)','os.fstat(fd)','(opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino)','handle.read(max_bytes+1)','Path(name).name!=name','set(item)!={"file","sha256"}','def valid_manifest_contract','EXPECTED_ARTIFACT_ROLES','EXPECTED_DEPLOYMENT_ORDER','EXPECTED_ROLLOUT_RINGS','EXPECTED_GATES','SIGNABLE_FILES','invalid_intune_manifest_contract','sentinel.intune-evidence/v3','evidence_release_version_mismatch','evidence_manifest_digest_mismatch','hmac.compare_digest(manifest_sha,hashlib.sha256(manifest_raw).hexdigest())','invalid_rollout_device_metrics','gate_failed:ring_assignment_scope','gate_failed:reporting_coverage_95pct','gate_failed:compliance_coverage_95pct','gate_failed:installation_failure_rate_2pct'):
        if directive not in preflight: errors.append(f"unsafe_intune_preflight:{directive}")
    try: evidence_generator=(downloads/"sentinel_intune_evidence.py").read_text(); intune_export=json.loads((downloads/"intune-device-export.example.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_intune_evidence_generator:{type(exc).__name__}"); evidence_generator=""; intune_export={}
    if intune_export!={"schema":"sentinel.intune-export/v1","generated_at":0,"current_ring":"lab","fleet_device_ids":[],"assigned_device_ids":[],"compliant_device_ids":[],"installation_failed_device_ids":[]}: errors.append("unsafe_intune_export_example")
    for directive in ('MAX_SNAPSHOT_BYTES=2_000_000','snapshot_not_current','collector.get("complete") is not True','invalid_intune_device_relationship','now-last_seen<=86400','manifest_sha256=hashlib.sha256(manifest).hexdigest()','fleet_total_devices=fleet_total','sentinel.intune-export/v2','device_id in collector_ids','credential_generation','report_count<1','reporting_devices=len(reporting)'):
        if directive not in evidence_generator: errors.append(f"unsafe_intune_evidence_generator:{directive}")
    try: graph_normalizer=(downloads/"sentinel_intune_graph_normalize.py").read_text(); graph_example=json.loads((downloads/"intune-graph-export.example.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_intune_graph_normalizer:{type(exc).__name__}"); graph_normalizer=""; graph_example={}
    if graph_example!={"schema":"sentinel.intune-graph-export/v1","generated_at":0,"current_ring":"lab","managed_devices":[],"assigned_device_ids":[],"install_states":[],"bindings":[]}: errors.append("unsafe_intune_graph_example")
    for directive in ('MAX_GRAPH_EXPORT_BYTES=2_000_000','sentinel.intune-graph-export/v1','COMPLIANCE_STATES','INSTALL_STATES','set(mapping)!=set(assigned)','incomplete_assigned_device_evidence','sentinel.intune-export/v2','fleet_total_devices'):
        if directive not in graph_normalizer: errors.append(f"unsafe_intune_graph_normalizer:{directive}")
    try: vendor_probe=(downloads/"sentinel_vendor_probe.py").read_text()
    except OSError as exc: errors.append(f"invalid_vendor_probe:{type(exc).__name__}"); vendor_probe=""
    for directive in ('sentinel.vendor-probe/v1','--live','probe_target["actions"]={"normal":"observe"}','adapter.validate_target','adapter.valid_payload','payload_sha256','idempotency_key','secrets_embedded','for _ in range(2)'):
        if directive not in vendor_probe: errors.append(f"unsafe_vendor_probe:{directive}")
    try: windows_remediation=(downloads/"intune-windows-remediate.ps1").read_text(); windows_detection=(downloads/"intune-windows-detect.ps1").read_text(); windows_compliance=(downloads/"intune-compliance-discovery.ps1").read_text(); macos_install=(downloads/"intune-macos-install.sh").read_text(); macos_compliance=(downloads/"intune-macos-compliance.sh").read_text()
    except OSError as exc: errors.append(f"invalid_endpoint_schedule:{type(exc).__name__}"); windows_remediation=windows_detection=windows_compliance=macos_install=macos_compliance=""
    for directive in ('New-ScheduledTaskTrigger -AtStartup',"Delay = 'PT2M'",'New-TimeSpan -Hours 1','-StartWhenAvailable','-MultipleInstances IgnoreNew','-ExecutionTimeLimit (New-TimeSpan -Minutes 30)','-RestartCount 3'):
        if directive not in windows_remediation: errors.append(f"unsafe_windows_schedule:{directive}")
    for directive in ('function Test-SentinelUserTarget','function Set-SentinelUserTextAtomic','$encoding.GetPreamble()','$stream.Write($preamble,0,$preamble.Length)','$stream.Flush($true)','Set-Acl -Path $temp -AclObject $acl','Move-Item -LiteralPath $temp -Destination $target -Force','Remove-Item -LiteralPath $temp -Force','Attributes -band [IO.FileAttributes]::ReparsePoint'):
        if directive not in windows_remediation: errors.append(f"unsafe_windows_user_baseline_write:{directive}")
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
    try: maintenance=(downloads/"sentinel_collector_maintenance.py").read_text(); maintenance_service=(downloads/"sentinel-collector-maintenance.service").read_text(); maintenance_timer=(downloads/"sentinel-collector-maintenance.timer").read_text()
    except OSError as exc: errors.append(f"invalid_collector_maintenance:{type(exc).__name__}"); maintenance=maintenance_service=maintenance_timer=""
    for directive in ('BEGIN IMMEDIATE','DELETE FROM reports WHERE received_at < ?','collector.prune_audit','PRAGMA quick_check','PRAGMA wal_checkpoint(PASSIVE)','unsafe_database_directory','unsafe_database_file','"secrets_printed":False'):
        if directive not in maintenance: errors.append(f"unsafe_collector_maintenance:{directive}")
    for directive in ('Type=oneshot','User=sentinel','RestrictAddressFamilies=AF_UNIX','NoNewPrivileges=true','ProtectSystem=strict','CapabilityBoundingSet='):
        if directive not in maintenance_service: errors.append(f"unsafe_collector_maintenance_service:{directive}")
    for directive in ('OnCalendar=daily','Persistent=true','RandomizedDelaySec=1h','Unit=sentinel-collector-maintenance.service'):
        if directive not in maintenance_timer: errors.append(f"unsafe_collector_maintenance_timer:{directive}")
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
    for directive in ("adapter_dispatches","adapter.validate_target","result_summary(outputs)","INSERT OR IGNORE INTO adapter_dispatches","def load_runtime_inputs","config,acceptance=load_runtime_inputs(adapter,args.config,args.acceptance)"):
        if directive not in worker: errors.append(f"unsafe_adapter_worker:{directive}")
    for directive in ("User=sentinel","EnvironmentFile=/etc/sentinel/adapter.env","--acceptance /etc/sentinel/vendor-acceptance.json","NoNewPrivileges=true","ProtectSystem=strict","CapabilityBoundingSet="):
        if directive not in worker_service: errors.append(f"unsafe_adapter_worker_service:{directive}")
    try: adapter_env=(downloads/"sentinel-adapter.env.example").read_text()
    except OSError as exc: errors.append(f"invalid_adapter_env:{type(exc).__name__}"); adapter_env=""
    for secret_name in ("SENTINEL_4A_ACCESS_TOKEN","SANGFOR_EDR_TOKEN","LEAGSOFT_TOKEN","SENTINEL_WEBHOOK_SECRET","SENTINEL_VENDOR_ACCEPTANCE_SIGNING_SECRET","SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS"):
        if not re.search(rf"(?m)^{secret_name}=$",adapter_env): errors.append(f"adapter_example_secret_not_empty:{secret_name}")
    try: adapter_text=(downloads/"sentinel_adapter.py").read_text()
    except OSError as exc: errors.append(f"invalid_adapter:{type(exc).__name__}"); adapter_text=""
    if '"Idempotency-Key":hashlib.sha256(body).hexdigest()' not in adapter_text: errors.append("missing_adapter_idempotency_key")
    for directive in ('SentinelAdapter/0.19','MAX_VENDOR_PAYLOAD_BYTES=2_000_000','MAX_VENDOR_QUEUE_FILE_BYTES=2_100_000','MAX_VENDOR_CONFIG_BYTES=65_536','MAX_VENDOR_ACCEPTANCE_BYTES=262_144','def read_json_bounded','before=path.lstat()','getattr(os,"O_NOFOLLOW",0)','os.fstat(fd)','(opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino)','handle.read(max_bytes+1)','raw.decode("utf-8")','adapter_payload_too_large','def validate_spool_directory','info.st_uid!=os.geteuid()','stat.S_IMODE(info.st_mode)&0o077','if not validate_spool_directory(spool): return []','def read_queued_event','handle.read(MAX_VENDOR_QUEUE_FILE_BYTES+1)','stat.S_ISREG','action not in SAFE_ACTIONS','set(compliance)!={"max_policy_age_hours","critical_allowed"}','not 1<=age<=168','critical!=0','max_age=config["compliance"]["max_policy_age_hours"]*3600','last_scan>now+300','"stale_policy"','isinstance(report["scanned_at"],bool)','invalid_adapter_payload','if len(files)>=keep: raise OSError("adapter_spool_full")','"result":"retained"','spool.is_symlink()','tempfile.mkstemp','os.fchmod(fd,0o600)','os.fsync(handle.fileno())','os.replace(temp,path)','os.fsync(directory_fd)'):
        if directive not in adapter_text: errors.append(f"missing_vendor_config_boundary:{directive}")
    try: vendor_contract=json.loads((downloads/"sentinel-vendor-contracts.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_vendor_contract:{type(exc).__name__}"); vendor_contract={}
    if vendor_contract.get("schema")!="sentinel.vendor-contracts/v1" or vendor_contract.get("adapter_version")!="0.19" or vendor_contract.get("secrets_embedded") is not False: errors.append("vendor_contract_version_drift")
    queue_contract=vendor_contract.get("delivery_queue",{})
    if queue_contract!={"overflow_behavior":"retain_source_report_and_retry","silent_eviction_allowed":False,"credentials_stored":False,"write_semantics":"private_fsync_atomic_replace_directory_fsync","read_semantics":"nofollow_regular_file_inode_bound_bounded_read","directory_owner":"effective_service_user","directory_mode_maximum":"0700","symlink_directory_allowed":False,"symlink_event_allowed":False,"maximum_queue_file_bytes":2100000}: errors.append("unsafe_vendor_queue_contract")
    if vendor_contract.get("transport",{}).get("maximum_payload_bytes")!=2000000: errors.append("unsafe_vendor_payload_limit")
    if vendor_contract.get("local_inputs")!={"read_semantics":"nofollow_regular_file_inode_bound_bounded_read","adapter_config_maximum_bytes":65536,"acceptance_evidence_maximum_bytes":262144,"report_maximum_bytes":2000000,"strict_utf8":True,"regular_file_required":True,"symlink_allowed":False}: errors.append("unsafe_vendor_local_inputs")
    transport=vendor_contract.get("transport",{}); boundaries=vendor_contract.get("credential_boundaries",{})
    if transport.get("scheme")!="https" or transport.get("timeout_seconds")!=15 or transport.get("idempotency_header")!="Idempotency-Key" or transport.get("credentials_in_url_allowed") is not False: errors.append("unsafe_vendor_transport_contract")
    if vendor_contract.get("sangfor",{}).get("safe_actions")!=["observe","alert","isolate_pending_approval","block_pending_approval"] or vendor_contract.get("sangfor",{}).get("direct_destructive_actions_allowed") is not False: errors.append("unsafe_sangfor_contract")
    if vendor_contract.get("leagsoft",{}).get("compliance_configuration")!={"max_policy_age_hours_min":1,"max_policy_age_hours_max":168,"critical_allowed":0}: errors.append("unsafe_leagsoft_contract")
    four_a=vendor_contract.get("enterprise_4a",{})
    if four_a.get("schema")!="sentinel.enterprise-4a.event/v1" or four_a.get("direct_access_enforcement_allowed") is not False or four_a.get("safe_actions")!=["observe","alert","access_review_pending","containment_pending_approval"]: errors.append("unsafe_enterprise_4a_contract")
    if [boundaries.get(name,{}).get("allowed_env_prefix") for name in ("enterprise_4a","sangfor","leagsoft","security_webhook")]!=["SENTINEL_4A_","SANGFOR_","LEAGSOFT_","SENTINEL_"]: errors.append("vendor_credential_boundary_drift")
    try: four_a_openapi=json.loads((downloads/"sentinel-enterprise-4a.openapi.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_enterprise_4a_openapi:{type(exc).__name__}"); four_a_openapi={}
    four_a_schema=four_a_openapi.get("components",{}).get("schemas",{}).get("SecurityEvent",{})
    if four_a_openapi.get("openapi")!="3.1.0" or "/api/v1/security-events" not in four_a_openapi.get("paths",{}) or four_a_schema.get("additionalProperties") is not False: errors.append("enterprise_4a_openapi_drift")
    try: four_a_probe=(downloads/"sentinel_4a_probe.py").read_text()
    except OSError as exc: errors.append(f"invalid_enterprise_4a_probe:{type(exc).__name__}"); four_a_probe=""
    for directive in ('sentinel.enterprise-4a-probe/v1','probe_target["actions"]={level:"observe"','for _ in range(2)','idempotent_replay_accepted','secrets_embedded','device_identifiers_embedded','adapter.deliver("enterprise_4a"'):
        if directive not in four_a_probe: errors.append(f"unsafe_enterprise_4a_probe:{directive}")
    enablement=vendor_contract.get("production_enablement",{})
    if enablement!={"evidence_schema":"sentinel.vendor-acceptance/v3","signing_input_schema":"sentinel.vendor-acceptance/v2","integrity_algorithm":"hmac-sha256","signing_secret_env":"SENTINEL_VENDOR_ACCEPTANCE_SIGNING_SECRET","offline_signing_keyring_argument":"--keyring","offline_signing_output_argument":"--output","offline_signing_output_semantics":"private_metadata_preserving_fsync_atomic_replace_directory_fsync","offline_keyring_manager":"sentinel_vendor_keyring.py","key_retirement_requires_current_acceptance_signed_by_retained_key":True,"verification_keyring_env":"SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS","verification_keyring_file_env":"SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS_FILE","maximum_verification_keys":5,"maximum_verification_keyring_bytes":65536,"live_probe_schema":"sentinel.vendor-probe/v1","maximum_probe_age_seconds":86400,"maximum_evidence_age_seconds":604800,"required_for":["sangfor","leagsoft"],"secrets_allowed":False}: errors.append("vendor_enablement_contract_drift")
    try: vendor_evidence=json.loads((downloads/"vendor-acceptance-evidence.example.json").read_text()); vendor_preflight=(downloads/"sentinel_vendor_preflight.py").read_text()
    except (OSError,ValueError) as exc: errors.append(f"invalid_vendor_preflight:{type(exc).__name__}"); vendor_evidence={}; vendor_preflight=""
    if vendor_evidence.get("schema")!="sentinel.vendor-acceptance/v2" or vendor_evidence.get("adapter_version")!="0.19" or vendor_evidence.get("secrets_embedded") is not False: errors.append("unsafe_vendor_acceptance_example")
    for directive in ('max_age_seconds=604800','vendor_endpoint_not_accepted','vendor_gate_failed','vendor_acceptance_must_be_secret_free','auth_scheme','sentinel.vendor-probe/v1','PROBE_FIELDS','vendor_probe_binding_failed','vendor_probe_not_current','now-probe_generated>86400','hmac.compare_digest(digest,key)','vendor_probe_replay_failed','before=path.lstat()','getattr(os,"O_NOFOLLOW",0)','os.fstat(fd)','(opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino)','handle.read(max_bytes+1)'):
        if directive not in vendor_preflight: errors.append(f"unsafe_vendor_preflight:{directive}")
    for directive in ('sentinel.vendor-acceptance/v3','UNSIGNED_SCHEMA="sentinel.vendor-acceptance/v2"','INTEGRITY_FIELDS','SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS','SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS_FILE','MAX_SIGNING_KEYS=5','MAX_SIGNING_KEYS_BYTES=65_536','private=True','opened.st_uid not in {0,os.geteuid()}','mode&0o007','parse_signing_keys','invalid_vendor_acceptance_signing_keys','vendor_acceptance_signing_key_unavailable','vendor_acceptance_signature_invalid','vendor_acceptance_signature_mismatch','canonical_unsigned(evidence)'):
        if directive not in vendor_preflight: errors.append(f"unsafe_vendor_signature_preflight:{directive}")
    if "SENTINEL_VENDOR_ACCEPTANCE_SIGNING_KEYS_FILE=/etc/sentinel/vendor-acceptance-keys.json" not in adapter_env: errors.append("missing_vendor_keyring_file")
    try: vendor_signer=(downloads/"sentinel_vendor_evidence_sign.py").read_text()
    except OSError as exc: errors.append(f"invalid_vendor_evidence_signer:{type(exc).__name__}"); vendor_signer=""
    for directive in ('SENTINEL_VENDOR_ACCEPTANCE_SIGNING_SECRET','--keyring','--output','load_signing_secret','private_atomic_output','preflight.read_json_bounded(keyring_path,preflight.MAX_SIGNING_KEYS_BYTES,private=True)','os.path.realpath(parent)!=os.path.abspath(parent)','stat.S_IMODE(info.st_mode)&0o022','mode not in {0o600,0o640}','metadata=(mode,existing.st_uid,existing.st_gid)','os.fchown(fd,metadata[1],metadata[2])','os.fchmod(fd,metadata[0] if metadata else 0o600)','os.fsync(handle.fileno())','os.replace(temp,path)','os.fsync(directory_fd)','vendor_acceptance_signing_key_unavailable','invalid_unsigned_vendor_acceptance','invalid_vendor_acceptance_signing_secret','hmac.new(secret.encode()','preflight.canonical_unsigned(signed)','"integrity"'):
        if directive not in vendor_signer: errors.append(f"unsafe_vendor_evidence_signer:{directive}")
    try: vendor_keyring=(downloads/"sentinel_vendor_keyring.py").read_text()
    except OSError as exc: errors.append(f"invalid_vendor_keyring:{type(exc).__name__}"); vendor_keyring=""
    for directive in ('secrets.token_urlsafe(48)','--add-key-id','--remove-key-id','--acceptance','MAX_SIGNING_KEYS','private_atomic_output','cannot_remove_last_vendor_acceptance_key','verify_retirement_evidence','key_id==removed_key_id','hmac.compare_digest(expected,signature)','not -300<=now-generated<=604800','"secrets_printed":False'):
        if directive not in vendor_keyring: errors.append(f"unsafe_vendor_keyring:{directive}")
    for directive in ('--acceptance','vendor_acceptance_failed','adapter_version="0.19"','now=now','adapter.read_json_bounded','length(CAST(r.body AS BLOB))','adapter.MAX_VENDOR_PAYLOAD_BYTES','hmac.compare_digest','rejected_stored_report_digest_mismatch','rejected_oversized_stored_report'):
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
    for directive in ('"gemini_cli"','"github_copilot_cli"','".gemini/settings.json"','".copilot/mcp-config.json"','".gemini/GEMINI.md"','".copilot/copilot-instructions.md"','cfg.get("httpUrl"','".gemini/skills"','".copilot/skills"','def verify_user_baselines','"agent_baseline_not_loaded"','"type":"agent_baseline"','SentinelAgent/0.43.0','not path.is_symlink()','if root.is_symlink(): return []','if home.is_symlink() or not home.is_dir(): continue','not marker.is_symlink()','def atomic_managed_write','atomic_managed_write(home,path,updated)','os.fchown','os.fsync(handle.fileno())','os.replace(temp,path)'):
        if directive not in python_agent: errors.append(f"missing_python_agent_coverage:{directive}")
    for directive in ("gemini_cli=@(","github_copilot_cli=@(",".gemini\\GEMINI.md","copilot-instructions.md","$cfg.httpUrl","'.gemini','.copilot'","Get-SentinelUserBaselineStatus","type='agent_baseline'","agent_baseline_not_loaded","agent_version='0.43.0'","foreach ($userHome in $userHomes)","function Get-SentinelUserBaselineStatus([string]$userHomePath","[string]$ManagedUsersRoot = 'C:\\Users'","Get-ChildItem $ManagedUsersRoot","Attributes -band [IO.FileAttributes]::ReparsePoint","function Set-SentinelManagedTextAtomic","$encoding.GetPreamble()","$stream.Write($preamble,0,$preamble.Length)","$stream.Flush($true)","Set-Acl -Path $temp -AclObject $existingAcl","Move-Item -LiteralPath $temp -Destination $target -Force","foreach($secretPattern in @($policy.secret_patterns))","[regex]::new([string]$secretPattern","[TimeSpan]::FromMilliseconds(250)","RegexMatchTimeoutException","scan_rule_timeout","Kind='credential_access'","Kind='dynamic_eval'"):
        if directive not in windows_agent: errors.append(f"missing_windows_agent_coverage:{directive}")
    for directive in ('$null=Set-SentinelManagedTextAtomic $repo $target $managed','$null=Set-SentinelManagedTextAtomic $repo $target $updated','$null=Set-SentinelManagedTextAtomic $repo $shared $managed'):
        if directive not in windows_agent: errors.append(f"unsafe_windows_repository_baseline_write:{directive}")
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
    for directive in ("def device_credentials(path=None):","sentinel.device-credentials/v1","device_credentials_permissions",'report["device_id"]!=binding[0]',"X-Sentinel-Device-ID","credential_generation_mismatch","device_auth_state","credential_posture","generated_at=int(time.time())","COALESCE(a.last_seen,r.received_at)","parse_qs(parsed.query",'set(query)-{"limit","view"}','view not in {"activation","console"}',"1<=limit<=10000",'"complete":complete','if view=="console"','"severity":rows[index][4]','"agent_version":rows[index][5]','"policy_version":rows[index][6]',"WITH fleet AS","agent_coverage","supported_agents=",'item.get("type")=="ai_agent"',"baseline_coverage",'item.get("type")=="agent_baseline"','"0.43.0"','"5.1.0"',"SentinelCollector/0.20"):
        if directive not in collector_text: errors.append(f"missing_device_identity_boundary:{directive}")
    try: openapi=json.loads((downloads/"sentinel-collector.openapi.json").read_text())
    except (OSError,ValueError) as exc: errors.append(f"invalid_collector_openapi:{type(exc).__name__}"); openapi={}
    paths=openapi.get("paths",{}) if isinstance(openapi,dict) else {}; components=openapi.get("components",{}) if isinstance(openapi,dict) else {}
    expected_methods={"/health":{"get"},"/v1/reports":{"post"},"/v1/summary":{"get"},"/v1/policy":{"get"},"/v1/devices":{"get"},"/v1/audit":{"get"}}
    if openapi.get("openapi")!="3.1.0" or openapi.get("info",{}).get("version")!="0.20.0": errors.append("collector_openapi_version_drift")
    fleet_schema=components.get("schemas",{}).get("FleetSummary",{})
    if "baseline_coverage" not in fleet_schema.get("required",[]) or "baseline_coverage" not in fleet_schema.get("properties",{}): errors.append("collector_openapi_baseline_coverage_drift")
    device_get=paths.get("/v1/devices",{}).get("get",{}); device_parameters={item.get("name"):item for item in device_get.get("parameters",[]) if isinstance(item,dict)}; console_schema=components.get("schemas",{}).get("ConsoleDevice",{}).get("allOf",[{},{}])
    if set(device_parameters)!={"limit","view"} or set(device_parameters.get("view",{}).get("schema",{}).get("enum",[]))!={"activation","console"}: errors.append("collector_openapi_device_view_drift")
    if not isinstance(console_schema,list) or len(console_schema)!=2 or set(console_schema[1].get("required",[]))!={"device_id","last_seen","report_count","credential_generation","severity","agent_version","policy_version"}: errors.append("collector_openapi_console_device_drift")
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
