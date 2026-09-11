#!/usr/bin/env python3
"""Secret-free, non-destructive acceptance probe for the enterprise 4A boundary."""
import argparse, hashlib, json, sys, time
import aegis_adapter as adapter

SCHEMA="aegis.enterprise-4a-probe/v1"

def synthetic_report(now):
    return {"schema":"aegis.report/v1","agent_version":"probe","policy_version":"probe","device_id":"aegis-probe","scanned_at":now,"summary":{"critical":0,"high":0,"medium":0,"low":0},"findings":[]}

def run_probe(config,live=False,sender=adapter.send,now=None):
    now=int(time.time() if now is None else now); adapter.validate_config(config)
    target=config.get("enterprise_4a",{})
    if not isinstance(target,dict) or target.get("enabled") is not True: raise ValueError("enterprise_4a_not_enabled")
    probe_target=dict(target); probe_target["actions"]={level:"observe" for level in ("critical","high","medium","low","normal")}
    adapter.validate_target("enterprise_4a",probe_target,config,dry_run=not live)
    payload=adapter.enterprise_4a_event(synthetic_report(now),probe_target)
    if payload["authorization"]!={"decision":"observe","enforcement":"external_approval_required"} or not adapter.valid_payload("enterprise_4a",payload): raise ValueError("unsafe_enterprise_4a_probe_payload")
    body=json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode(); digest=hashlib.sha256(body).hexdigest(); statuses=[]
    if live:
        for _ in range(2): statuses.append(adapter.deliver("enterprise_4a",probe_target,payload,sender))
    return {"schema":SCHEMA,"generated_at":now,"adapter_version":"0.19","endpoint_url":target["url"],"tenant":target["tenant"],"payload_sha256":digest,"idempotency_key":digest,"safe_action":"observe","live":live,"statuses":statuses,"idempotent_replay_accepted":live and len(statuses)==2 and all(200<=value<300 for value in statuses),"secrets_embedded":False,"device_identifiers_embedded":False}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--config",required=True); parser.add_argument("--live",action="store_true"); args=parser.parse_args()
    try:
        config=adapter.read_json_bounded(args.config,adapter.MAX_VENDOR_CONFIG_BYTES); result=run_probe(config,args.live)
        print(json.dumps(result,ensure_ascii=False,separators=(",",":"),sort_keys=True)); return 0
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
