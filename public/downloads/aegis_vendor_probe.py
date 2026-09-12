#!/usr/bin/env python3
"""Secret-free, non-destructive staging probe for VendorEdr and VendorMdm adapters."""
import argparse, hashlib, json, os, sys, time
from pathlib import Path
import aegis_adapter as adapter

SCHEMA="aegis.vendor-probe/v1"
VENDORS=("vendor_edr","vendor_mdm")

def synthetic_report(now):
    return {"schema":"aegis.report/v1","agent_version":"probe","policy_version":"probe","device_id":"aegis-probe","scanned_at":now,"summary":{"critical":0,"high":0,"medium":0,"low":0},"findings":[]}

def run_probe(config,vendor,live=False,sender=adapter.send,now=None):
    now=int(time.time() if now is None else now)
    adapter.validate_config(config)
    if vendor not in VENDORS: raise ValueError("invalid_probe_vendor")
    target=config.get(vendor,{})
    if not isinstance(target,dict) or target.get("enabled") is not True: raise ValueError("probe_vendor_not_enabled")
    probe_target=dict(target)
    if vendor=="vendor_edr": probe_target["actions"]={"normal":"observe"}
    adapter.validate_target(vendor,probe_target,config,dry_run=not live)
    report=synthetic_report(now)
    payload=adapter.vendor_edr_event(report,probe_target) if vendor=="vendor_edr" else adapter.vendor_mdm_posture(report,probe_target,now)
    if not adapter.valid_payload(vendor,payload): raise ValueError("invalid_probe_payload")
    body=json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode(); digest=hashlib.sha256(body).hexdigest()
    statuses=[]
    if live:
        for _ in range(2): statuses.append(adapter.deliver(vendor,probe_target,payload,sender))
    return {"schema":SCHEMA,"generated_at":now,"adapter_version":"0.19","vendor":vendor,"endpoint_url":target["url"],"payload_sha256":digest,"idempotency_key":digest,"safe_action":"observe" if vendor=="vendor_edr" else "compliance_posture_only","live":live,"statuses":statuses,"idempotent_replay_accepted":live and len(statuses)==2 and all(200<=value<300 for value in statuses),"secrets_embedded":False}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--config",required=True); ap.add_argument("--vendor",required=True,choices=VENDORS); ap.add_argument("--live",action="store_true"); args=ap.parse_args()
    try:
        config=adapter.read_json_bounded(args.config,adapter.MAX_VENDOR_CONFIG_BYTES)
        result=run_probe(config,args.vendor,args.live)
        print(json.dumps(result,ensure_ascii=False,separators=(",",":"),sort_keys=True)); return 0
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
