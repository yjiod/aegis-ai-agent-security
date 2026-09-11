#!/usr/bin/env python3
"""Offline, secret-free Intune rollout promotion preflight."""
import argparse, hashlib, hmac, json, os, re, stat, sys, time
from pathlib import Path

RINGS=("lab","pilot","broad","production")
EVIDENCE_FIELDS={
    "schema","release_version","manifest_sha256","generated_at","current_ring","current_ring_entered_at","collector_probe_read_only_passed",
    "fleet_total_devices","ring_assigned_devices","reporting_devices","compliant_devices","installation_failures",
    "release_verifier_passed","reporting_credentials_delivered_out_of_band",
    "rollback_tested_in_ring","critical_findings","reporting_healthy_since",
    "production_signature_verified",
}
MAX_INTUNE_EVIDENCE_BYTES=65_536
MAX_INTUNE_MANIFEST_BYTES=262_144
MAX_INTUNE_RELEASE_BYTES=65_536
MAX_INTUNE_ARTIFACT_BYTES=2_000_000
EXPECTED_ARTIFACT_ROLES={"windows_detection","windows_remediation","windows_compliance_discovery","windows_compliance_rules","windows_reporting_configuration","windows_rollback","windows_uninstall","macos_install","macos_compliance_discovery","macos_compliance_rules","macos_reporting_configuration","macos_rollback","macos_uninstall"}
EXPECTED_DEPLOYMENT_ORDER=["collector_and_tls","reporting_credentials","endpoint_installation","reporting_configuration","custom_compliance","conditional_access"]
EXPECTED_ROLLOUT_RINGS=[{"name":"lab","maximum_percent":1,"minimum_observation_hours":24},{"name":"pilot","maximum_percent":5,"minimum_observation_hours":48},{"name":"broad","maximum_percent":25,"minimum_observation_hours":72},{"name":"production","maximum_percent":100,"minimum_observation_hours":168}]
EXPECTED_GATES=["collector_probe_read_only_passed","release_verifier_passed","reporting_credentials_delivered_out_of_band","rollback_tested_in_ring","no_critical_findings","reporting_healthy_24h"]
SIGNABLE_FILES={"intune-windows-detect.ps1","intune-windows-remediate.ps1","intune-compliance-discovery.ps1","aegis-configure-windows.ps1","rollback-aegis-windows.ps1","uninstall-aegis-windows.ps1"}

def read_bytes_bounded(path,max_bytes):
    path=Path(path); before=path.lstat()
    if not stat.S_ISREG(before.st_mode): raise ValueError("unsafe_intune_input")
    if before.st_size>max_bytes: raise ValueError("oversized_intune_input")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino): raise ValueError("unsafe_intune_input")
        if opened.st_size>max_bytes: raise ValueError("oversized_intune_input")
        with os.fdopen(fd,"rb") as handle: fd=-1; raw=handle.read(max_bytes+1)
    finally:
        if fd>=0: os.close(fd)
    if len(raw)>max_bytes: raise ValueError("oversized_intune_input")
    return raw
def read_json_bounded(path,max_bytes): return json.loads(read_bytes_bounded(path,max_bytes).decode("utf-8"))
def digest(path): return hashlib.sha256(read_bytes_bounded(path,MAX_INTUNE_ARTIFACT_BYTES)).hexdigest()
def valid_manifest_contract(manifest):
    if not isinstance(manifest,dict) or manifest.get("schema")!="aegis.intune-deployment/v1" or manifest.get("secrets_embedded") is not False: return False
    execution=manifest.get("execution"); state=execution.get("script_signature_state") if isinstance(execution,dict) else None
    expected_execution={"windows_run_as":"system","windows_run_as_32_bit":False,"macos_run_as":"root","macos_hide_notifications":True,"script_signature_state":state,"production_signature_required":True}
    if state not in {"pilot_unsigned","production_signed"} or execution!=expected_execution: return False
    expected_root={"schema","execution","artifacts","deployment_order","rollout_rings","gates","secrets_embedded"}|({"signing"} if state=="production_signed" else set())
    artifacts=manifest.get("artifacts")
    if set(manifest)!=expected_root or not isinstance(artifacts,dict) or set(artifacts)!=EXPECTED_ARTIFACT_ROLES: return False
    if manifest.get("deployment_order")!=EXPECTED_DEPLOYMENT_ORDER or manifest.get("rollout_rings")!=EXPECTED_ROLLOUT_RINGS or manifest.get("gates")!=EXPECTED_GATES: return False
    signing=manifest.get("signing")
    if state=="pilot_unsigned": return signing is None
    verified=signing.get("verified_files") if isinstance(signing,dict) else None
    return isinstance(signing,dict) and set(signing)=={"certificate_thumbprint","timestamp_server","signed_at","verified_files"} and isinstance(signing.get("certificate_thumbprint"),str) and bool(re.fullmatch(r"[0-9a-f]{40}",signing["certificate_thumbprint"])) and isinstance(signing.get("timestamp_server"),str) and signing["timestamp_server"].startswith("https://") and isinstance(signing.get("signed_at"),int) and not isinstance(signing["signed_at"],bool) and isinstance(verified,list) and set(verified)==SIGNABLE_FILES and len(verified)==len(SIGNABLE_FILES)

def evaluate(downloads,evidence,target_ring,now=None):
    downloads=Path(downloads); now=int(time.time() if now is None else now); blockers=[]
    if target_ring not in RINGS: return ["invalid_target_ring"]
    try:
        manifest_raw=read_bytes_bounded(downloads/"intune-deployment-manifest.json",MAX_INTUNE_MANIFEST_BYTES); manifest=json.loads(manifest_raw.decode("utf-8"))
        release=read_json_bounded(downloads/"release.json",MAX_INTUNE_RELEASE_BYTES)
    except (OSError,ValueError,UnicodeError,json.JSONDecodeError) as exc: return [f"invalid_intune_manifest:{type(exc).__name__}"]
    if not valid_manifest_contract(manifest): return ["invalid_intune_manifest_contract"]
    release_version=release.get("release") if isinstance(release,dict) else None
    if not isinstance(release_version,str) or not re.fullmatch(r"\d+\.\d+\.\d+",release_version): return ["invalid_release_metadata"]
    if not isinstance(evidence,dict) or set(evidence)!=EVIDENCE_FIELDS: blockers.append("invalid_evidence_contract"); return blockers
    if evidence.get("schema")!="aegis.intune-evidence/v3": blockers.append("invalid_evidence_schema")
    if evidence.get("release_version")!=release_version: blockers.append("evidence_release_version_mismatch")
    manifest_sha=evidence.get("manifest_sha256")
    if not isinstance(manifest_sha,str) or not re.fullmatch(r"[0-9a-f]{64}",manifest_sha) or not hmac.compare_digest(manifest_sha,hashlib.sha256(manifest_raw).hexdigest()): blockers.append("evidence_manifest_digest_mismatch")
    generated=evidence.get("generated_at")
    if isinstance(generated,bool) or not isinstance(generated,int) or generated>now+300 or now-generated>86400: blockers.append("evidence_not_current")
    current=evidence.get("current_ring")
    if current not in RINGS or RINGS.index(target_ring)!=RINGS.index(current)+1: blockers.append("invalid_ring_promotion")
    else:
        entered=evidence.get("current_ring_entered_at"); rings=manifest.get("rollout_rings",[])
        ring=next((item for item in rings if isinstance(item,dict) and item.get("name")==current),{})
        minimum=ring.get("minimum_observation_hours")
        if isinstance(entered,bool) or not isinstance(entered,int) or entered>now or isinstance(minimum,bool) or not isinstance(minimum,int) or minimum<1 or now-entered<minimum*3600:
            blockers.append("ring_observation_incomplete")
    metrics=[evidence.get(name) for name in ("fleet_total_devices","ring_assigned_devices","reporting_devices","compliant_devices","installation_failures")]
    if any(isinstance(value,bool) or not isinstance(value,int) or value<0 for value in metrics) or metrics[0]<1 or metrics[1]<1 or metrics[1]>metrics[0] or metrics[2]>metrics[1] or metrics[3]>metrics[2] or metrics[4]>metrics[1] or metrics[2]+metrics[4]>metrics[1]:
        blockers.append("invalid_rollout_device_metrics")
    else:
        total,assigned,reporting,compliant,failures=metrics
        if current in RINGS:
            maximum=EXPECTED_ROLLOUT_RINGS[RINGS.index(current)]["maximum_percent"]
            if assigned>max(1,total*maximum//100): blockers.append("gate_failed:ring_assignment_scope")
        if reporting*100<assigned*95: blockers.append("gate_failed:reporting_coverage_95pct")
        if compliant*100<assigned*95: blockers.append("gate_failed:compliance_coverage_95pct")
        if failures*100>assigned*2: blockers.append("gate_failed:installation_failure_rate_2pct")
    artifacts=manifest.get("artifacts",{})
    if not isinstance(artifacts,dict): blockers.append("invalid_artifact_manifest")
    else:
        for item in artifacts.values():
            if not isinstance(item,dict) or set(item)!={"file","sha256"}: blockers.append("invalid_artifact_manifest"); continue
            name=item.get("file","")
            if not isinstance(name,str) or not 1<=len(name)<=128 or Path(name).name!=name: blockers.append("invalid_artifact_manifest"); continue
            path=downloads/name
            try: matches=isinstance(item.get("sha256"),str) and item["sha256"]==digest(path)
            except (OSError,ValueError): matches=False
            if not matches: blockers.append(f"artifact_digest_mismatch:{name}")
    for field in ("collector_probe_read_only_passed","release_verifier_passed","reporting_credentials_delivered_out_of_band"):
        if evidence.get(field) is not True: blockers.append(f"gate_failed:{field}")
    critical=evidence.get("critical_findings")
    if isinstance(critical,bool) or not isinstance(critical,int) or critical<0: blockers.append("invalid_critical_findings")
    elif critical: blockers.append("gate_failed:no_critical_findings")
    if target_ring in ("broad","production") and evidence.get("rollback_tested_in_ring") is not True: blockers.append("gate_failed:rollback_tested_in_ring")
    if target_ring in ("broad","production"):
        healthy=evidence.get("reporting_healthy_since")
        if isinstance(healthy,bool) or not isinstance(healthy,int) or healthy>now or now-healthy<86400: blockers.append("gate_failed:reporting_healthy_24h")
    execution=manifest.get("execution",{})
    if target_ring=="production":
        if execution.get("production_signature_required") is not True or execution.get("script_signature_state")!="production_signed" or evidence.get("production_signature_verified") is not True:
            blockers.append("gate_failed:production_signature")
    return list(dict.fromkeys(blockers))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--downloads",default=str(Path(__file__).parent))
    parser.add_argument("--evidence",required=True)
    parser.add_argument("--target-ring",required=True,choices=RINGS)
    args=parser.parse_args()
    try: evidence=read_json_bounded(args.evidence,MAX_INTUNE_EVIDENCE_BYTES)
    except (OSError,ValueError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"target_ring":args.target_ring,"blockers":[f"invalid_evidence:{type(exc).__name__}"]},separators=(",",":"))); return 1
    blockers=evaluate(args.downloads,evidence,args.target_ring)
    print(json.dumps({"ok":not blockers,"target_ring":args.target_ring,"blockers":blockers},separators=(",",":")))
    return 1 if blockers else 0

if __name__=="__main__": sys.exit(main())
