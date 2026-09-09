#!/usr/bin/env python3
"""Sign reviewed Sentinel production acceptance evidence to a private atomic output."""
import argparse, hashlib, hmac, json, os, re, sys
import sentinel_production_preflight as preflight
from sentinel_vendor_evidence_sign import private_atomic_output

def sign(evidence,keys,key_id):
    if type(evidence) is not dict or set(evidence)!=preflight.TOP or evidence.get("schema")!="sentinel.production-acceptance/v2": raise ValueError("invalid_production_acceptance")
    if key_id not in keys: raise ValueError("production_signing_key_unavailable")
    value=json.loads(json.dumps(evidence));value["integrity"]={"algorithm":"hmac-sha256","key_id":key_id,"signature":"0"*64}
    signature=hmac.new(keys[key_id].encode(),preflight.canonical_unsigned(value),hashlib.sha256).hexdigest();value["integrity"]["signature"]=signature
    return value

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--evidence",required=True);parser.add_argument("--key-id",required=True);parser.add_argument("--output",required=True);args=parser.parse_args()
    try:
        evidence=json.loads(preflight.read_regular_bounded(args.evidence,preflight.MAX_EVIDENCE_BYTES));keys=preflight.parse_signing_keys(os.getenv(preflight.SIGNING_KEYS_ENV,""));result=sign(evidence,keys,args.key_id);private_atomic_output(args.output,result)
        print(json.dumps({"ok":True,"output":args.output,"key_id":args.key_id,"secrets_embedded":False},separators=(",",":")));return 0
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":str(exc)},separators=(",",":")),file=sys.stderr);return 2
if __name__=="__main__": sys.exit(main())
