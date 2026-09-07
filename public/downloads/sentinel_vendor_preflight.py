#!/usr/bin/env python3
"""Secret-free production enablement gate for Sangfor and Leagsoft adapters."""
import argparse, json, sys, time
from pathlib import Path

SCHEMA="sentinel.vendor-acceptance/v1"
VENDORS=("sangfor","leagsoft")
ROOT_FIELDS={"schema","generated_at","adapter_version","vendors","secrets_embedded"}
VENDOR_FIELDS={
    "product_version","api_document_id","endpoint_url","auth_scheme",
    "field_mapping_approved","idempotency_verified","non_2xx_retry_verified",
    "safe_action_mapping_verified","dry_run_payload_approved","approved_by",
}

def evaluate(config,evidence,adapter_version="0.10",now=None,max_age_seconds=604800):
    now=int(time.time() if now is None else now); blockers=[]
    if not isinstance(config,dict): return ["invalid_adapter_config"]
    if not any(isinstance(config.get(name),dict) and config[name].get("enabled") for name in VENDORS): return []
    if not isinstance(evidence,dict) or set(evidence)!=ROOT_FIELDS: return ["invalid_vendor_acceptance_contract"]
    if evidence.get("schema")!=SCHEMA: blockers.append("invalid_vendor_acceptance_schema")
    if evidence.get("adapter_version")!=adapter_version: blockers.append("vendor_acceptance_version_mismatch")
    if evidence.get("secrets_embedded") is not False: blockers.append("vendor_acceptance_must_be_secret_free")
    generated=evidence.get("generated_at")
    if isinstance(generated,bool) or not isinstance(generated,int) or generated>now+300 or now-generated>max_age_seconds:
        blockers.append("vendor_acceptance_not_current")
    vendors=evidence.get("vendors")
    if not isinstance(vendors,dict) or not set(vendors).issubset(VENDORS):
        blockers.append("invalid_vendor_acceptance_targets"); return list(dict.fromkeys(blockers))
    for name in VENDORS:
        target=config.get(name,{})
        if not isinstance(target,dict) or not target.get("enabled"): continue
        item=vendors.get(name)
        if not isinstance(item,dict) or set(item)!=VENDOR_FIELDS:
            blockers.append(f"missing_vendor_acceptance:{name}"); continue
        for field in ("product_version","api_document_id","endpoint_url","approved_by"):
            if not isinstance(item.get(field),str) or not item[field].strip() or len(item[field])>512:
                blockers.append(f"invalid_vendor_acceptance_field:{name}:{field}")
        if item.get("endpoint_url")!=target.get("url"): blockers.append(f"vendor_endpoint_not_accepted:{name}")
        if item.get("auth_scheme")!="bearer": blockers.append(f"vendor_auth_not_accepted:{name}")
        for field in ("field_mapping_approved","idempotency_verified","non_2xx_retry_verified","safe_action_mapping_verified","dry_run_payload_approved"):
            if item.get(field) is not True: blockers.append(f"vendor_gate_failed:{name}:{field}")
    return list(dict.fromkeys(blockers))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--config",required=True); parser.add_argument("--evidence",required=True)
    parser.add_argument("--adapter-version",default="0.10")
    args=parser.parse_args()
    try:
        config=json.loads(Path(args.config).read_text()); evidence=json.loads(Path(args.evidence).read_text())
    except (OSError,ValueError,TypeError,RecursionError) as exc:
        print(json.dumps({"ok":False,"blockers":[f"invalid_vendor_preflight_input:{type(exc).__name__}"]},separators=(",",":"))); return 1
    blockers=evaluate(config,evidence,args.adapter_version)
    print(json.dumps({"ok":not blockers,"blockers":blockers},ensure_ascii=False,separators=(",",":")))
    return 1 if blockers else 0

if __name__=="__main__": sys.exit(main())
