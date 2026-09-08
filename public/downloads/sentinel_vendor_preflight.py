#!/usr/bin/env python3
"""Secret-free production enablement gate for Sangfor and Leagsoft adapters."""
import argparse, hmac, json, os, re, stat, sys, time
from pathlib import Path

SCHEMA="sentinel.vendor-acceptance/v3"
UNSIGNED_SCHEMA="sentinel.vendor-acceptance/v2"
VENDORS=("sangfor","leagsoft")
ROOT_FIELDS={"schema","generated_at","adapter_version","vendors","secrets_embedded","integrity"}
UNSIGNED_ROOT_FIELDS=ROOT_FIELDS-{"integrity"}
INTEGRITY_FIELDS={"algorithm","key_id","signature"}
VENDOR_FIELDS={
    "product_version","api_document_id","endpoint_url","auth_scheme",
    "field_mapping_approved","idempotency_verified","non_2xx_retry_verified",
    "safe_action_mapping_verified","dry_run_payload_approved","approved_by","probe",
}
PROBE_FIELDS={"schema","generated_at","adapter_version","vendor","endpoint_url","payload_sha256","idempotency_key","safe_action","live","statuses","idempotent_replay_accepted","secrets_embedded"}
MAX_PREFLIGHT_INPUT_BYTES=262_144

def canonical_unsigned(evidence):
    unsigned={key:value for key,value in evidence.items() if key!="integrity"}; unsigned["schema"]=UNSIGNED_SCHEMA
    return json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()

def read_json_bounded(path,max_bytes=MAX_PREFLIGHT_INPUT_BYTES):
    path=Path(path)
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode): raise ValueError("unsafe_json_input")
    if before.st_size>max_bytes: raise ValueError("oversized_json_input")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino): raise ValueError("unsafe_json_input")
        if opened.st_size>max_bytes: raise ValueError("oversized_json_input")
        with os.fdopen(fd,"rb") as handle: fd=-1; raw=handle.read(max_bytes+1)
    finally:
        if fd>=0: os.close(fd)
    if len(raw)>max_bytes: raise ValueError("oversized_json_input")
    return json.loads(raw.decode("utf-8"))

def evaluate(config,evidence,adapter_version="0.18",now=None,max_age_seconds=604800,signing_secret=None):
    now=int(time.time() if now is None else now); blockers=[]
    if not isinstance(config,dict): return ["invalid_adapter_config"]
    if not any(isinstance(config.get(name),dict) and config[name].get("enabled") for name in VENDORS): return []
    if not isinstance(evidence,dict) or set(evidence)!=ROOT_FIELDS: return ["invalid_vendor_acceptance_contract"]
    if evidence.get("schema")!=SCHEMA: blockers.append("invalid_vendor_acceptance_schema")
    if evidence.get("adapter_version")!=adapter_version: blockers.append("vendor_acceptance_version_mismatch")
    if evidence.get("secrets_embedded") is not False: blockers.append("vendor_acceptance_must_be_secret_free")
    integrity=evidence.get("integrity"); secret=os.getenv("SENTINEL_VENDOR_ACCEPTANCE_SIGNING_SECRET","") if signing_secret is None else signing_secret
    if not isinstance(secret,str) or not 32<=len(secret)<=4096: blockers.append("vendor_acceptance_signing_secret_invalid")
    if not isinstance(integrity,dict) or set(integrity)!=INTEGRITY_FIELDS or integrity.get("algorithm")!="hmac-sha256" or not isinstance(integrity.get("key_id"),str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}",integrity["key_id"]) or not isinstance(integrity.get("signature"),str) or not re.fullmatch(r"[0-9a-f]{64}",integrity["signature"]):
        blockers.append("vendor_acceptance_signature_invalid")
    elif isinstance(secret,str) and 32<=len(secret)<=4096:
        expected=hmac.new(secret.encode(),canonical_unsigned(evidence),"sha256").hexdigest()
        if not hmac.compare_digest(expected,integrity["signature"]): blockers.append("vendor_acceptance_signature_mismatch")
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
        probe=item.get("probe")
        if not isinstance(probe,dict) or set(probe)!=PROBE_FIELDS:
            blockers.append(f"invalid_vendor_probe:{name}"); continue
        probe_generated=probe.get("generated_at"); statuses=probe.get("statuses"); digest=probe.get("payload_sha256"); key=probe.get("idempotency_key")
        expected_action="observe" if name=="sangfor" else "compliance_posture_only"
        if probe.get("schema")!="sentinel.vendor-probe/v1" or probe.get("adapter_version")!=adapter_version or probe.get("vendor")!=name or probe.get("endpoint_url")!=target.get("url") or probe.get("safe_action")!=expected_action or probe.get("live") is not True or probe.get("secrets_embedded") is not False:
            blockers.append(f"vendor_probe_binding_failed:{name}")
        if isinstance(probe_generated,bool) or not isinstance(probe_generated,int) or probe_generated>now+300 or now-probe_generated>86400 or (isinstance(generated,int) and probe_generated>generated): blockers.append(f"vendor_probe_not_current:{name}")
        if not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{64}",digest) or not isinstance(key,str) or not hmac.compare_digest(digest,key): blockers.append(f"vendor_probe_idempotency_invalid:{name}")
        if not isinstance(statuses,list) or len(statuses)!=2 or any(isinstance(value,bool) or not isinstance(value,int) or not 200<=value<300 for value in statuses) or probe.get("idempotent_replay_accepted") is not True: blockers.append(f"vendor_probe_replay_failed:{name}")
    return list(dict.fromkeys(blockers))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--config",required=True); parser.add_argument("--evidence",required=True)
    parser.add_argument("--adapter-version",default="0.18")
    args=parser.parse_args()
    try:
        config=read_json_bounded(args.config); evidence=read_json_bounded(args.evidence)
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"blockers":[f"invalid_vendor_preflight_input:{type(exc).__name__}"]},separators=(",",":"))); return 1
    blockers=evaluate(config,evidence,args.adapter_version)
    print(json.dumps({"ok":not blockers,"blockers":blockers},ensure_ascii=False,separators=(",",":")))
    return 1 if blockers else 0

if __name__=="__main__": sys.exit(main())
