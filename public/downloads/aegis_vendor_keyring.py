#!/usr/bin/env python3
"""Create and rotate the vendor-acceptance HMAC keyring without printing secrets."""
import argparse, hmac, json, re, secrets, sys, time
from pathlib import Path
import aegis_vendor_preflight as preflight
import aegis_vendor_evidence_sign as signer

def valid_key_id(value): return isinstance(value,str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}",value) is not None

def load_keyring(path,allow_missing=False):
    source=Path(path)
    if allow_missing and not source.exists(): return {}
    raw=preflight.read_json_bounded(source,preflight.MAX_SIGNING_KEYS_BYTES,private=True)
    return preflight.parse_signing_keys(json.dumps(raw,separators=(",",":")))

def verify_retirement_evidence(path,keys,removed_key_id,now=None):
    evidence=preflight.read_json_bounded(path)
    if not isinstance(evidence,dict) or set(evidence)!=preflight.ROOT_FIELDS or evidence.get("schema")!=preflight.SCHEMA: raise ValueError("invalid_vendor_retirement_evidence")
    integrity=evidence.get("integrity")
    if not isinstance(integrity,dict) or set(integrity)!=preflight.INTEGRITY_FIELDS or integrity.get("algorithm")!="hmac-sha256": raise ValueError("invalid_vendor_retirement_evidence")
    key_id=integrity.get("key_id"); signature=integrity.get("signature"); secret=keys.get(key_id)
    if key_id==removed_key_id or not valid_key_id(key_id) or not isinstance(secret,str) or not isinstance(signature,str) or not re.fullmatch(r"[0-9a-f]{64}",signature): raise ValueError("unsafe_vendor_key_retirement")
    expected=hmac.new(secret.encode(),preflight.canonical_unsigned(evidence),"sha256").hexdigest()
    if not hmac.compare_digest(expected,signature): raise ValueError("unsafe_vendor_key_retirement")
    generated=evidence.get("generated_at"); now=int(time.time() if now is None else now)
    if isinstance(generated,bool) or not isinstance(generated,int) or not -300<=now-generated<=604800: raise ValueError("stale_vendor_retirement_evidence")

def update_keyring(path,add_key_id=None,remove_key_id=None,acceptance=None,now=None):
    if bool(add_key_id)==bool(remove_key_id): raise ValueError("exactly_one_keyring_operation_required")
    key_id=add_key_id or remove_key_id
    if not valid_key_id(key_id): raise ValueError("invalid_vendor_acceptance_key_id")
    keys=load_keyring(path,allow_missing=bool(add_key_id))
    if add_key_id:
        if key_id in keys: raise ValueError("vendor_acceptance_key_already_exists")
        if len(keys)>=preflight.MAX_SIGNING_KEYS: raise ValueError("vendor_acceptance_signing_key_limit")
        keys[key_id]=secrets.token_urlsafe(48); action="added"
    else:
        if key_id not in keys: raise ValueError("vendor_acceptance_signing_key_unavailable")
        if len(keys)<=1: raise ValueError("cannot_remove_last_vendor_acceptance_key")
        verify_retirement_evidence(acceptance,keys,key_id,now=now); del keys[key_id]; action="removed"
    signer.private_atomic_output(path,keys)
    return {"ok":True,"action":action,"key_id":key_id,"key_count":len(keys),"secrets_printed":False}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--keyring",required=True); group=ap.add_mutually_exclusive_group(required=True); group.add_argument("--add-key-id"); group.add_argument("--remove-key-id"); ap.add_argument("--acceptance"); args=ap.parse_args()
    try:
        result=update_keyring(args.keyring,args.add_key_id,args.remove_key_id,args.acceptance); print(json.dumps(result,separators=(",",":"))); return 0
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1

if __name__=="__main__": raise SystemExit(main())
