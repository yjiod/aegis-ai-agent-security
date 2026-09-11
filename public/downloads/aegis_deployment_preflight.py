#!/usr/bin/env python3
"""Vendor-neutral production gate for endpoint deployment platforms."""
import argparse, hashlib, json, os, re, stat, sys, time
from pathlib import Path

SCHEMA="aegis.deployment-platform-acceptance/v1"
MAX_EVIDENCE_BYTES=64*1024
RINGS=("lab","pilot","broad","production")
OBSERVATION_HOURS=(24,48,72,168)
PLATFORM_TYPES={"mdm","desktop_management","software_distribution","manual_controlled"}
TOP={"schema","release_version","release_manifest_sha256","generated_at","platform","rings","controls","approved_by","secrets_embedded","device_identifiers_embedded"}
CONTROLS={"privileged_execution","artifact_digest_pinning","protected_secret_delivery","scheduled_scan_enabled","rollback_available"}
RING_FIELDS={"name","assigned","installed","reporting","compliant","failed","observation_hours","rollback_tested","approved"}

def read_json_bounded(path):
    path=Path(path); before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_EVIDENCE_BYTES: raise ValueError("unsafe_deployment_evidence")
    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino) or opened.st_size>MAX_EVIDENCE_BYTES: raise ValueError("unsafe_deployment_evidence")
        with os.fdopen(descriptor,"rb") as handle: descriptor=-1; raw=handle.read(MAX_EVIDENCE_BYTES+1)
    finally:
        if descriptor>=0: os.close(descriptor)
    if len(raw)>MAX_EVIDENCE_BYTES: raise ValueError("oversized_deployment_evidence")
    return json.loads(raw.decode("utf-8"))

def ratio(numerator,denominator): return numerator/denominator if denominator else 0.0

def evaluate(downloads,evidence,now=None):
    downloads=Path(downloads); now=int(time.time() if now is None else now); errors=[]
    try: release=json.loads((downloads/"release.json").read_text(encoding="utf-8"))
    except (OSError,ValueError,UnicodeError): return ["release_unavailable"]
    if not isinstance(evidence,dict) or set(evidence)!=TOP: return ["invalid_deployment_evidence_contract"]
    if evidence.get("schema")!=SCHEMA: errors.append("invalid_deployment_evidence_schema")
    if evidence.get("release_version")!=release.get("release"): errors.append("deployment_release_mismatch")
    expected=hashlib.sha256((downloads/"RELEASE-MANIFEST.sha256").read_bytes()).hexdigest()
    if not isinstance(evidence.get("release_manifest_sha256"),str) or not re.fullmatch(r"[0-9a-f]{64}",evidence["release_manifest_sha256"]) or evidence["release_manifest_sha256"]!=expected: errors.append("deployment_manifest_mismatch")
    generated=evidence.get("generated_at")
    if isinstance(generated,bool) or not isinstance(generated,int) or not -300<=now-generated<=86400: errors.append("stale_or_future_deployment_evidence")
    platform=evidence.get("platform")
    if not isinstance(platform,dict) or set(platform)!={"name","type","evidence_export_id"} or not isinstance(platform.get("name"),str) or not 1<=len(platform["name"])<=128 or platform.get("type") not in PLATFORM_TYPES or not isinstance(platform.get("evidence_export_id"),str) or not 1<=len(platform["evidence_export_id"])<=128: errors.append("invalid_deployment_platform")
    controls=evidence.get("controls")
    if not isinstance(controls,dict) or set(controls)!=CONTROLS or any(value is not True for value in controls.values()): errors.append("deployment_controls_incomplete")
    rings=evidence.get("rings")
    if not isinstance(rings,list) or len(rings)!=4 or [item.get("name") if isinstance(item,dict) else None for item in rings]!=list(RINGS): errors.append("invalid_deployment_ring_order")
    else:
        previous=0
        for index,item in enumerate(rings):
            name=RINGS[index]
            if set(item)!=RING_FIELDS: errors.append(f"invalid_deployment_ring_contract:{name}"); continue
            counts=[item.get(key) for key in ("assigned","installed","reporting","compliant","failed")]
            if any(isinstance(value,bool) or not isinstance(value,int) or value<0 or value>1_000_000 for value in counts): errors.append(f"invalid_deployment_ring_counts:{name}"); continue
            assigned,installed,reporting,compliant,failed=counts
            if assigned<1 or assigned<previous or any(value>assigned for value in (installed,reporting,compliant,failed)): errors.append(f"invalid_deployment_ring_scope:{name}")
            if ratio(installed,assigned)<0.95: errors.append(f"deployment_installation_below_gate:{name}")
            if ratio(reporting,assigned)<0.95: errors.append(f"deployment_reporting_below_gate:{name}")
            if ratio(compliant,assigned)<0.95: errors.append(f"deployment_compliance_below_gate:{name}")
            if ratio(failed,assigned)>0.02: errors.append(f"deployment_failure_above_gate:{name}")
            if item.get("observation_hours")!=OBSERVATION_HOURS[index]: errors.append(f"deployment_observation_incomplete:{name}")
            if item.get("rollback_tested") is not True or item.get("approved") is not True: errors.append(f"deployment_ring_not_approved:{name}")
            previous=assigned
    if not isinstance(evidence.get("approved_by"),str) or not 1<=len(evidence["approved_by"])<=128: errors.append("deployment_approval_missing")
    if evidence.get("secrets_embedded") is not False: errors.append("deployment_secrets_must_not_be_embedded")
    if evidence.get("device_identifiers_embedded") is not False: errors.append("deployment_device_identifiers_must_not_be_embedded")
    return errors

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("evidence"); parser.add_argument("--downloads",default=str(Path(__file__).parent)); args=parser.parse_args()
    try: errors=evaluate(args.downloads,read_json_bounded(args.evidence)); print(json.dumps({"ok":not errors,"errors":errors},separators=(",",":"))); return 0 if not errors else 1
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc: print(json.dumps({"ok":False,"errors":[type(exc).__name__]},separators=(",",":"))); return 1
if __name__=="__main__": raise SystemExit(main())
