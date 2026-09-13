#!/usr/bin/env python3
"""Safely stage and retire Collector policy-signing keys without printing secrets."""
import argparse, hashlib, json, os, secrets, stat, sys, tempfile, time
from pathlib import Path

SCHEMA="sentinel.policy-signing-keys/v1"
MAX_KEYS=5
MAX_FILE_BYTES=65_536
MAX_EVIDENCE_BYTES=65_536

def key_id(key): return hashlib.sha256(key.encode()).hexdigest()[:16]

def read_private_json(path,max_bytes=MAX_FILE_BYTES):
    source=Path(path)
    if source.is_symlink(): raise ValueError("policy_keyring_symlink")
    before=source.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) not in {0o600,0o640} or before.st_uid not in {0,os.geteuid()} or before.st_size>max_bytes: raise ValueError("policy_keyring_permissions")
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0); fd=os.open(source,flags)
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino): raise ValueError("policy_keyring_changed")
        with os.fdopen(fd,"r",encoding="utf-8") as handle: fd=-1; raw=handle.read(max_bytes+1)
    finally:
        if fd>=0: os.close(fd)
    if len(raw.encode())>max_bytes: raise ValueError("policy_keyring_too_large")
    return json.loads(raw)

def validate(value):
    keys=value.get("keys") if isinstance(value,dict) else None
    if not isinstance(value,dict) or set(value)!={"schema","keys"} or value.get("schema")!=SCHEMA or not isinstance(keys,list) or not 1<=len(keys)<=MAX_KEYS or any(not isinstance(key,str) or not 32<=len(key)<=4096 for key in keys) or len(keys)!=len(set(keys)): raise ValueError("policy_keyring_contract")
    ids=[key_id(key) for key in keys]
    if len(ids)!=len(set(ids)): raise ValueError("policy_key_id_collision")
    return keys

def load_keyring(path): return validate(read_private_json(path))

def private_atomic(path,value):
    path=Path(path); before=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode): raise ValueError("policy_keyring_output_invalid")
    fd,temp_name=tempfile.mkstemp(prefix="."+path.name+".",suffix=".tmp",dir=path.parent); temp=Path(temp_name)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            json.dump(value,handle,separators=(",",":")); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.chown(temp,before.st_uid,before.st_gid); os.chmod(temp,stat.S_IMODE(before.st_mode)); os.replace(temp,path)
        directory_fd=os.open(path.parent,os.O_RDONLY); os.fsync(directory_fd); os.close(directory_fd)
    except Exception: temp.unlink(missing_ok=True); raise

def verify_retirement_evidence(path,current_key_id,now=None):
    try: evidence=read_private_json(path,MAX_EVIDENCE_BYTES)
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError) as exc: raise ValueError("invalid_policy_retirement_evidence") from exc
    now=int(time.time()) if now is None else int(now)
    required={"generated_at","total_devices","active_devices","stale_devices","policy_trust_posture","active_policy_key_id"}
    if not isinstance(evidence,dict) or not required.issubset(evidence) or type(evidence.get("generated_at")) is not int or not -60<=now-evidence["generated_at"]<=900: raise ValueError("stale_policy_retirement_evidence")
    total=evidence.get("total_devices"); active=evidence.get("active_devices"); stale=evidence.get("stale_devices"); posture=evidence.get("policy_trust_posture")
    if any(type(value) is not int or value<0 for value in (total,active,stale)) or total<1 or active!=total or stale!=0 or not isinstance(posture,dict) or set(posture)!={"current","overlap","legacy","unrecognized"} or any(type(value) is not int or value<0 for value in posture.values()) or posture["current"]!=total or posture["legacy"]!=0 or posture["unrecognized"]!=0 or evidence.get("active_policy_key_id")!=current_key_id: raise ValueError("unsafe_policy_key_retirement")

def verify_approval(path,removed_key_id,current_key_id,now=None):
    try: approval=read_private_json(path,16_384)
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError) as exc: raise ValueError("invalid_policy_retirement_approval") from exc
    required={"schema","remove_key_id","active_key_id","issued_at","expires_at","approved_by_ref"}
    now=int(time.time()) if now is None else int(now)
    if not isinstance(approval,dict) or set(approval)!=required or approval.get("schema")!="sentinel.policy-key-retirement-approval/v1" or approval.get("remove_key_id")!=removed_key_id or approval.get("active_key_id")!=current_key_id or type(approval.get("issued_at")) is not int or type(approval.get("expires_at")) is not int or not -60<=now-approval["issued_at"]<=900 or not now<=approval["expires_at"]<=approval["issued_at"]+900 or not isinstance(approval.get("approved_by_ref"),str) or not 1<=len(approval["approved_by_ref"])<=128: raise ValueError("invalid_policy_retirement_approval")

def update_keyring(path,add=False,remove_key_id=None,evidence=None,approval=None,now=None):
    if bool(add)==bool(remove_key_id): raise ValueError("exactly_one_policy_keyring_operation_required")
    keys=load_keyring(path)
    if add:
        if len(keys)>=MAX_KEYS: raise ValueError("policy_signing_key_limit")
        keys=[secrets.token_urlsafe(48),*keys]; action="added"; changed_id=key_id(keys[0])
    else:
        ids=[key_id(key) for key in keys]
        if remove_key_id not in ids: raise ValueError("policy_signing_key_unavailable")
        if len(keys)<=1: raise ValueError("cannot_remove_last_policy_signing_key")
        if remove_key_id==ids[0]: raise ValueError("cannot_remove_active_policy_signing_key")
        verify_retirement_evidence(evidence,ids[0],now=now); verify_approval(approval,remove_key_id,ids[0],now=now); keys=[key for key in keys if key_id(key)!=remove_key_id]; action="removed"; changed_id=remove_key_id
    private_atomic(path,{"schema":SCHEMA,"keys":keys})
    if action=="removed": Path(approval).unlink()
    return {"ok":True,"action":action,"key_id":changed_id,"key_count":len(keys),"secrets_printed":False}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--keyring",required=True); group=ap.add_mutually_exclusive_group(required=True); group.add_argument("--add",action="store_true"); group.add_argument("--remove-key-id"); ap.add_argument("--evidence"); ap.add_argument("--approval"); args=ap.parse_args()
    try: print(json.dumps(update_keyring(args.keyring,args.add,args.remove_key_id,args.evidence,args.approval),separators=(",",":"))); return 0
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError) as exc: print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1

if __name__=="__main__": raise SystemExit(main())
