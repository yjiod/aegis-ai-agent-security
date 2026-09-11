#!/usr/bin/env python3
"""Create, rotate and safely retire production-acceptance HMAC keys."""
import argparse, hashlib, hmac, json, re, secrets, sys, time
from pathlib import Path
import aegis_production_preflight as preflight
from aegis_vendor_evidence_sign import private_atomic_output

def valid_key_id(value): return isinstance(value,str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}",value) is not None

def load_keyring(path,allow_missing=False):
    source=Path(path)
    if allow_missing and not source.exists(): return {}
    return preflight.load_signing_keys(source)

def verify_retirement_evidence(path,keys,removed_key_id,now=None):
    evidence=json.loads(preflight.read_regular_bounded(path,preflight.MAX_EVIDENCE_BYTES))
    if type(evidence) is not dict or set(evidence)!=preflight.TOP or evidence.get("schema")!="aegis.production-acceptance/v3": raise ValueError("invalid_production_retirement_evidence")
    checks=evidence.get("checks",{}); files=evidence.get("evidence_files",{}); digests=evidence.get("evidence_sha256",{}); approvals=evidence.get("approvals",{})
    if type(checks) is not dict or set(checks)!=preflight.CHECKS or any(value is not True for value in checks.values()) or type(files) is not dict or set(files)!=preflight.CHECKS or any(not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",value) for value in files.values()) or type(digests) is not dict or set(digests)!=preflight.CHECKS or any(not isinstance(value,str) or not re.fullmatch(r"[0-9a-f]{64}",value) for value in digests.values()): raise ValueError("invalid_production_retirement_evidence")
    if type(approvals) is not dict or set(approvals)!=preflight.APPROVALS or any(type(value) is not dict or set(value)!={"identity","evidence_file","evidence_sha256"} or not isinstance(value["identity"],str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}",value["identity"]) or not isinstance(value["evidence_file"],str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",value["evidence_file"]) or not isinstance(value["evidence_sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",value["evidence_sha256"]) for value in approvals.values()): raise ValueError("invalid_production_retirement_evidence")
    if evidence.get("secrets_embedded") is not False or evidence.get("device_identifiers_embedded") is not False or not isinstance(evidence.get("release_version"),str) or not re.fullmatch(r"\d+\.\d+\.\d+",evidence["release_version"]) or not isinstance(evidence.get("release_manifest_sha256"),str) or not re.fullmatch(r"[0-9a-f]{64}",evidence["release_manifest_sha256"]) or not isinstance(evidence.get("git_commit_sha"),str) or not re.fullmatch(r"[0-9a-f]{40}",evidence["git_commit_sha"]) or type(evidence.get("site_version")) is not int or evidence["site_version"]<1: raise ValueError("invalid_production_retirement_evidence")
    integrity=evidence.get("integrity",{}); key_id=integrity.get("key_id"); signature=integrity.get("signature"); secret=keys.get(key_id)
    if key_id==removed_key_id or not valid_key_id(key_id) or not isinstance(secret,str) or not isinstance(signature,str) or not re.fullmatch(r"[0-9a-f]{64}",signature): raise ValueError("unsafe_production_key_retirement")
    expected=hmac.new(secret.encode(),preflight.canonical_unsigned(evidence),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,signature): raise ValueError("unsafe_production_key_retirement")
    generated=evidence.get("generated_at"); now=int(time.time() if now is None else now)
    if type(generated) is not int or not -300<=now-generated<=86400: raise ValueError("stale_production_retirement_evidence")

def update_keyring(path,add_key_id=None,remove_key_id=None,acceptance=None,now=None):
    if bool(add_key_id)==bool(remove_key_id): raise ValueError("exactly_one_keyring_operation_required")
    key_id=add_key_id or remove_key_id
    if not valid_key_id(key_id): raise ValueError("invalid_production_acceptance_key_id")
    keys=load_keyring(path,allow_missing=bool(add_key_id))
    if add_key_id:
        if key_id in keys: raise ValueError("production_acceptance_key_already_exists")
        if len(keys)>=preflight.MAX_SIGNING_KEYS: raise ValueError("production_acceptance_signing_key_limit")
        keys[key_id]=secrets.token_urlsafe(48); action="added"
    else:
        if key_id not in keys: raise ValueError("production_acceptance_signing_key_unavailable")
        if len(keys)<=1: raise ValueError("cannot_remove_last_production_acceptance_key")
        if not acceptance: raise ValueError("production_retirement_evidence_required")
        verify_retirement_evidence(acceptance,keys,key_id,now=now); del keys[key_id]; action="removed"
    private_atomic_output(path,keys)
    return {"ok":True,"action":action,"key_id":key_id,"key_count":len(keys),"secrets_printed":False}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--keyring",required=True); group=ap.add_mutually_exclusive_group(required=True); group.add_argument("--add-key-id"); group.add_argument("--remove-key-id"); ap.add_argument("--acceptance"); args=ap.parse_args()
    try: print(json.dumps(update_keyring(args.keyring,args.add_key_id,args.remove_key_id,args.acceptance),separators=(",",":"))); return 0
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError) as exc: print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
