#!/usr/bin/env python3
"""Prepare unsigned production acceptance evidence from original local records."""
import argparse, json, sys
import aegis_production_preflight as preflight
from aegis_vendor_evidence_sign import private_atomic_output

def prepare(evidence,evidence_root):
    if type(evidence) is not dict or set(evidence)!=preflight.TOP or evidence.get("schema")!="aegis.production-acceptance/v3": raise ValueError("invalid_production_acceptance")
    if evidence.get("integrity")!={"algorithm":"hmac-sha256","key_id":"","signature":""}: raise ValueError("signed_evidence_must_not_be_reprepared")
    files=evidence.get("evidence_files"); approvals=evidence.get("approvals")
    if type(files) is not dict or set(files)!=preflight.CHECKS or type(approvals) is not dict or set(approvals)!=preflight.APPROVALS: raise ValueError("invalid_production_record_contract")
    approval_files=[]
    for name in sorted(preflight.APPROVALS):
        value=approvals[name]
        if type(value) is not dict or set(value)!={"identity","evidence_file","evidence_sha256"}: raise ValueError("invalid_production_record_contract")
        approval_files.append(value["evidence_file"])
    all_files=list(files.values())+approval_files
    if any(not isinstance(value,str) for value in all_files) or len(all_files)!=len(set(all_files)): raise ValueError("duplicate_evidence_record")
    result=json.loads(json.dumps(evidence)); result["evidence_sha256"]={}
    for name in sorted(preflight.CHECKS): result["evidence_sha256"][name]=preflight.record_digest(evidence_root,files[name])
    for name in sorted(preflight.APPROVALS): result["approvals"][name]["evidence_sha256"]=preflight.record_digest(evidence_root,approvals[name]["evidence_file"])
    return result

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--evidence",required=True); ap.add_argument("--evidence-root",required=True); ap.add_argument("--output",required=True); args=ap.parse_args()
    try:
        evidence=json.loads(preflight.read_regular_bounded(args.evidence,preflight.MAX_EVIDENCE_BYTES)); result=prepare(evidence,args.evidence_root); private_atomic_output(args.output,result)
        print(json.dumps({"ok":True,"output":args.output,"record_count":14,"checks_changed":False,"secrets_embedded":False},separators=(",",":"))); return 0
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
