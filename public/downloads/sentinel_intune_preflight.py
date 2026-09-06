#!/usr/bin/env python3
"""Offline, secret-free Intune rollout promotion preflight."""
import argparse, hashlib, json, sys, time
from pathlib import Path

RINGS=("lab","pilot","broad","production")
EVIDENCE_FIELDS={
    "schema","generated_at","current_ring","current_ring_entered_at","collector_probe_read_only_passed",
    "release_verifier_passed","reporting_credentials_delivered_out_of_band",
    "rollback_tested_in_ring","critical_findings","reporting_healthy_since",
    "production_signature_verified",
}

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def evaluate(downloads,evidence,target_ring,now=None):
    downloads=Path(downloads); now=int(time.time() if now is None else now); blockers=[]
    if target_ring not in RINGS: return ["invalid_target_ring"]
    try: manifest=json.loads((downloads/"intune-deployment-manifest.json").read_text())
    except (OSError,ValueError) as exc: return [f"invalid_intune_manifest:{type(exc).__name__}"]
    if not isinstance(evidence,dict) or set(evidence)!=EVIDENCE_FIELDS: blockers.append("invalid_evidence_contract"); return blockers
    if evidence.get("schema")!="sentinel.intune-evidence/v1": blockers.append("invalid_evidence_schema")
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
    artifacts=manifest.get("artifacts",{})
    if not isinstance(artifacts,dict): blockers.append("invalid_artifact_manifest")
    else:
        for item in artifacts.values():
            if not isinstance(item,dict): blockers.append("invalid_artifact_manifest"); continue
            name=item.get("file",""); path=downloads/name
            if not path.is_file() or item.get("sha256")!=digest(path): blockers.append(f"artifact_digest_mismatch:{name}")
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
    try: evidence=json.loads(Path(args.evidence).read_text())
    except (OSError,ValueError) as exc:
        print(json.dumps({"ok":False,"target_ring":args.target_ring,"blockers":[f"invalid_evidence:{type(exc).__name__}"]},separators=(",",":"))); return 1
    blockers=evaluate(args.downloads,evidence,args.target_ring)
    print(json.dumps({"ok":not blockers,"target_ring":args.target_ring,"blockers":blockers},separators=(",",":")))
    return 1 if blockers else 0

if __name__=="__main__": sys.exit(main())
