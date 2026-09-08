#!/usr/bin/env python3
"""Sign a reviewed Sentinel vendor acceptance record without exposing its HMAC key."""
import argparse, hmac, json, os, re, sys
import sentinel_vendor_preflight as preflight

SECRET_ENV="SENTINEL_VENDOR_ACCEPTANCE_SIGNING_SECRET"

def load_signing_secret(keyring_path,key_id):
    raw=preflight.read_json_bounded(keyring_path,preflight.MAX_SIGNING_KEYS_BYTES,private=True)
    keys=preflight.parse_signing_keys(json.dumps(raw,separators=(",",":")))
    if key_id not in keys: raise ValueError("vendor_acceptance_signing_key_unavailable")
    return keys[key_id]

def sign(evidence,secret,key_id):
    if not isinstance(evidence,dict) or set(evidence)!=preflight.UNSIGNED_ROOT_FIELDS or evidence.get("schema")!=preflight.UNSIGNED_SCHEMA: raise ValueError("invalid_unsigned_vendor_acceptance")
    if not isinstance(secret,str) or not 32<=len(secret)<=4096: raise ValueError("invalid_vendor_acceptance_signing_secret")
    if not isinstance(key_id,str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}",key_id): raise ValueError("invalid_vendor_acceptance_key_id")
    signed=dict(evidence); signed["schema"]=preflight.SCHEMA
    signature=hmac.new(secret.encode(),preflight.canonical_unsigned(signed),"sha256").hexdigest()
    signed["integrity"]={"algorithm":"hmac-sha256","key_id":key_id,"signature":signature}
    return signed

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--evidence",required=True); ap.add_argument("--key-id",required=True); ap.add_argument("--keyring"); args=ap.parse_args()
    try:
        secret=load_signing_secret(args.keyring,args.key_id) if args.keyring else os.getenv(SECRET_ENV,"")
        evidence=preflight.read_json_bounded(args.evidence); signed=sign(evidence,secret,args.key_id)
        print(json.dumps(signed,ensure_ascii=False,sort_keys=True,separators=(",",":"))); return 0
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
