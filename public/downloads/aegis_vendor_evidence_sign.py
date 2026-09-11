#!/usr/bin/env python3
"""Sign a reviewed Aegis vendor acceptance record without exposing its HMAC key."""
import argparse, hmac, json, os, re, stat, sys, tempfile
from pathlib import Path
import aegis_vendor_preflight as preflight

SECRET_ENV="AEGIS_VENDOR_ACCEPTANCE_SIGNING_SECRET"

def load_signing_secret(keyring_path,key_id):
    raw=preflight.read_json_bounded(keyring_path,preflight.MAX_SIGNING_KEYS_BYTES,private=True)
    keys=preflight.parse_signing_keys(json.dumps(raw,separators=(",",":")))
    if key_id not in keys: raise ValueError("vendor_acceptance_signing_key_unavailable")
    return keys[key_id]

def private_atomic_output(path,value):
    path=Path(path); parent=path.parent
    if os.path.realpath(parent)!=os.path.abspath(parent): raise ValueError("unsafe_signing_output_directory")
    info=parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0,os.geteuid()} or stat.S_IMODE(info.st_mode)&0o022: raise ValueError("unsafe_signing_output_directory")
    if path.is_symlink(): raise ValueError("signing_output_symlink")
    metadata=None
    if path.exists():
        existing=path.lstat()
        mode=stat.S_IMODE(existing.st_mode); allowed_gids={os.getegid(),*os.getgroups()}
        if not stat.S_ISREG(existing.st_mode) or existing.st_uid not in {0,os.geteuid()} or mode not in {0o600,0o640} or (existing.st_uid!=0 and mode&0o040 and existing.st_gid not in allowed_gids): raise ValueError("unsafe_signing_output")
        metadata=(mode,existing.st_uid,existing.st_gid)
    fd,temp_name=tempfile.mkstemp(prefix="."+path.name+".",suffix=".tmp",dir=parent); temp=Path(temp_name)
    try:
        if metadata and (os.fstat(fd).st_uid,os.fstat(fd).st_gid)!=(metadata[1],metadata[2]): os.fchown(fd,metadata[1],metadata[2])
        os.fchmod(fd,metadata[0] if metadata else 0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            fd=-1; json.dump(value,handle,ensure_ascii=False,sort_keys=True,separators=(",",":")); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp,path)
        directory_fd=os.open(parent,os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if fd>=0: os.close(fd)
        temp.unlink(missing_ok=True)
    return path

def sign(evidence,secret,key_id):
    if not isinstance(evidence,dict) or set(evidence)!=preflight.UNSIGNED_ROOT_FIELDS or evidence.get("schema")!=preflight.UNSIGNED_SCHEMA: raise ValueError("invalid_unsigned_vendor_acceptance")
    if not isinstance(secret,str) or not 32<=len(secret)<=4096: raise ValueError("invalid_vendor_acceptance_signing_secret")
    if not isinstance(key_id,str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}",key_id): raise ValueError("invalid_vendor_acceptance_key_id")
    signed=dict(evidence); signed["schema"]=preflight.SCHEMA
    signature=hmac.new(secret.encode(),preflight.canonical_unsigned(signed),"sha256").hexdigest()
    signed["integrity"]={"algorithm":"hmac-sha256","key_id":key_id,"signature":signature}
    return signed

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--evidence",required=True); ap.add_argument("--key-id",required=True); ap.add_argument("--keyring"); ap.add_argument("--output"); args=ap.parse_args()
    try:
        secret=load_signing_secret(args.keyring,args.key_id) if args.keyring else os.getenv(SECRET_ENV,"")
        evidence=preflight.read_json_bounded(args.evidence); signed=sign(evidence,secret,args.key_id)
        if args.output:
            result=private_atomic_output(args.output,signed); print(json.dumps({"ok":True,"output":str(result),"key_id":args.key_id,"secrets_embedded":False},separators=(",",":")))
        else: print(json.dumps(signed,ensure_ascii=False,sort_keys=True,separators=(",",":")))
        return 0
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
