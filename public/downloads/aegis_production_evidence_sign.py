#!/usr/bin/env python3
"""Sign reviewed Aegis production acceptance evidence to a private atomic output."""
import argparse, hashlib, hmac, json, os, re, sys, time
import aegis_production_preflight as preflight
from aegis_vendor_evidence_sign import private_atomic_output

def validate_unsigned(evidence,evidence_root,downloads,expected_git_commit,expected_site_version,now=None):
    if type(evidence) is not dict or set(evidence)!=preflight.TOP or evidence.get("schema")!="aegis.production-acceptance/v3": raise ValueError("invalid_production_acceptance")
    if evidence.get("integrity")!={"algorithm":"hmac-sha256","key_id":"","signature":""}: raise ValueError("production_evidence_already_signed")
    if evidence.get("secrets_embedded") is not False or evidence.get("device_identifiers_embedded") is not False: raise ValueError("unsafe_production_acceptance")
    if not isinstance(evidence.get("release_version"),str) or not re.fullmatch(r"\d+\.\d+\.\d+",evidence["release_version"]) or not isinstance(evidence.get("release_manifest_sha256"),str) or not re.fullmatch(r"[0-9a-f]{64}",evidence["release_manifest_sha256"]) or not isinstance(evidence.get("git_commit_sha"),str) or not re.fullmatch(r"[0-9a-f]{40}",evidence["git_commit_sha"]) or type(evidence.get("site_version")) is not int or evidence["site_version"]<1: raise ValueError("incomplete_production_binding")
    try: release=json.loads(preflight.read_regular_bounded(os.path.join(downloads,"release.json"),64*1024)); manifest=preflight.digest(os.path.join(downloads,"RELEASE-MANIFEST.sha256"))
    except (OSError,ValueError,json.JSONDecodeError): raise ValueError("invalid_release_metadata")
    if evidence["release_version"]!=release.get("release") or not hmac.compare_digest(evidence["release_manifest_sha256"],manifest): raise ValueError("release_binding_mismatch")
    if not isinstance(expected_git_commit,str) or not re.fullmatch(r"[0-9a-f]{40}",expected_git_commit) or not hmac.compare_digest(evidence["git_commit_sha"],expected_git_commit): raise ValueError("git_commit_mismatch")
    if type(expected_site_version) is not int or expected_site_version<1 or evidence["site_version"]!=expected_site_version: raise ValueError("site_version_mismatch")
    generated=evidence.get("generated_at"); now=int(time.time() if now is None else now)
    if type(generated) is not int or generated>now+300 or generated<now-86400: raise ValueError("stale_or_future_evidence")
    checks=evidence.get("checks"); files=evidence.get("evidence_files"); digests=evidence.get("evidence_sha256"); approvals=evidence.get("approvals")
    if type(checks) is not dict or set(checks)!=preflight.CHECKS or any(value is not True for value in checks.values()): raise ValueError("production_gate_not_approved")
    if type(files) is not dict or set(files)!=preflight.CHECKS or type(digests) is not dict or set(digests)!=preflight.CHECKS or type(approvals) is not dict or set(approvals)!=preflight.APPROVALS: raise ValueError("invalid_production_record_contract")
    used=[]
    for name in sorted(preflight.CHECKS):
        filename=files[name]; supplied=digests[name]; used.append(filename)
        if not isinstance(supplied,str) or not re.fullmatch(r"[0-9a-f]{64}",supplied) or not hmac.compare_digest(preflight.record_digest(evidence_root,filename),supplied): raise ValueError("production_record_mismatch:"+name)
    for name in sorted(preflight.APPROVALS):
        value=approvals[name]
        if type(value) is not dict or set(value)!={"identity","evidence_file","evidence_sha256"} or not isinstance(value["identity"],str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}",value["identity"]): raise ValueError("production_approval_missing:"+name)
        used.append(value["evidence_file"]); supplied=value["evidence_sha256"]
        if not isinstance(supplied,str) or not re.fullmatch(r"[0-9a-f]{64}",supplied) or not hmac.compare_digest(preflight.record_digest(evidence_root,value["evidence_file"]),supplied): raise ValueError("production_approval_record_mismatch:"+name)
    if len(used)!=len(set(used)): raise ValueError("duplicate_evidence_record")

def sign(evidence,keys,key_id,evidence_root,downloads,expected_git_commit,expected_site_version,now=None):
    validate_unsigned(evidence,evidence_root,downloads,expected_git_commit,expected_site_version,now=now)
    if key_id not in keys: raise ValueError("production_signing_key_unavailable")
    value=json.loads(json.dumps(evidence));value["integrity"]={"algorithm":"hmac-sha256","key_id":key_id,"signature":"0"*64}
    signature=hmac.new(keys[key_id].encode(),preflight.canonical_unsigned(value),hashlib.sha256).hexdigest();value["integrity"]["signature"]=signature
    return value

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--evidence",required=True);parser.add_argument("--evidence-root",required=True);parser.add_argument("--downloads",default=os.path.dirname(__file__));parser.add_argument("--expected-git-commit",required=True);parser.add_argument("--expected-site-version",required=True,type=int);parser.add_argument("--key-id",required=True);parser.add_argument("--output",required=True);parser.add_argument("--keyring");args=parser.parse_args()
    try:
        evidence=json.loads(preflight.read_regular_bounded(args.evidence,preflight.MAX_EVIDENCE_BYTES));keys=preflight.load_signing_keys(args.keyring) if args.keyring else preflight.parse_signing_keys(os.getenv(preflight.SIGNING_KEYS_ENV,""));result=sign(evidence,keys,args.key_id,args.evidence_root,args.downloads,args.expected_git_commit,args.expected_site_version);private_atomic_output(args.output,result)
        print(json.dumps({"ok":True,"output":args.output,"key_id":args.key_id,"secrets_embedded":False},separators=(",",":")));return 0
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":str(exc)},separators=(",",":")),file=sys.stderr);return 2
if __name__=="__main__": sys.exit(main())
