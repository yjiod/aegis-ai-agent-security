#!/usr/bin/env python3
"""Generate and rotate per-device Collector credentials without printing secrets."""
import argparse, json, os, re, secrets, stat, tempfile, time
from pathlib import Path

SCHEMA="aegis.device-credentials/v1"
ENROLLMENT_SCHEMA="aegis.device-enrollment/v1"

def private_atomic(path,value,mode=0o600,preserve_metadata=False):
    path=Path(path)
    if path.is_symlink(): raise ValueError("output_symlink")
    parent_existed=path.parent.exists(); path.parent.mkdir(parents=True,exist_ok=True); parent=path.parent.resolve(strict=True)
    if not parent_existed: os.chmod(parent,0o700)
    path=parent/path.name; metadata=None
    if path.exists():
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode): raise ValueError("output_not_regular")
        if preserve_metadata: metadata=(stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid)
    fd,temp_name=tempfile.mkstemp(prefix="."+path.name+".",suffix=".tmp",dir=parent); temp=Path(temp_name)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            json.dump(value,handle,ensure_ascii=False,sort_keys=True,separators=(",",":")); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        target_mode=metadata[0] if metadata else mode
        if metadata:
            temp_info=temp.stat()
            if (temp_info.st_uid,temp_info.st_gid)!=(metadata[1],metadata[2]): os.chown(temp,metadata[1],metadata[2])
        os.chmod(temp,target_mode); os.replace(temp,path)
    except Exception:
        try: os.close(fd)
        except OSError: pass
        temp.unlink(missing_ok=True); raise
    return path

def valid_secret_list(values):
    return isinstance(values,list) and 1<=len(values)<=5 and all(isinstance(item,str) and 32<=len(item)<=4096 for item in values) and len(values)==len(set(values))

def load_manifest(path):
    path=Path(path)
    if not path.exists(): return {"schema":SCHEMA,"devices":{}}
    if path.is_symlink(): raise ValueError("manifest_symlink")
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o600,0o640}: raise ValueError("manifest_permissions")
    value=json.loads(path.read_text(encoding="utf-8")); devices=value.get("devices") if isinstance(value,dict) else None
    if set(value)!={"schema","devices"} or value.get("schema")!=SCHEMA or not isinstance(devices,dict) or len(devices)>10000: raise ValueError("manifest_contract")
    all_tokens=set(); all_signing=set()
    for device_id,credential in devices.items():
        if not re.fullmatch(r"[0-9a-f]{12}",device_id) or not isinstance(credential,dict) or set(credential)!={"tokens","signing_secrets"}: raise ValueError("manifest_contract")
        tokens=credential["tokens"]; signing=credential["signing_secrets"]
        if not valid_secret_list(tokens) or not valid_secret_list(signing) or set(tokens)&set(signing) or all_tokens.intersection(tokens) or all_signing.intersection(signing) or all_tokens.intersection(signing) or all_signing.intersection(tokens): raise ValueError("manifest_secrets")
        all_tokens.update(tokens); all_signing.update(signing)
    return value

def verify_activation_evidence(path,device_ids,now=None,max_age=900,active_window=86400):
    if not path: raise ValueError("activation_evidence_required")
    source=Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size>2_000_000: raise ValueError("activation_evidence_invalid")
    value=json.loads(source.read_text(encoding="utf-8")); rows=value.get("devices") if isinstance(value,dict) else None
    if not isinstance(value,dict) or set(value)!={"generated_at","complete","devices"} or value.get("complete") is not True or type(value.get("generated_at")) is not int or not isinstance(rows,list) or len(rows)>10000: raise ValueError("activation_evidence_invalid")
    now=int(time.time()) if now is None else int(now); generated_at=value["generated_at"]
    if not -60<=now-generated_at<=max_age: raise ValueError("activation_evidence_stale")
    generations={}
    for row in rows:
        if not isinstance(row,dict) or set(row)!={"device_id","last_seen","report_count","credential_generation"} or not re.fullmatch(r"[0-9a-f]{12}",str(row.get("device_id",""))) or type(row.get("last_seen")) is not int or type(row.get("report_count")) is not int or not 0<=generated_at-row["last_seen"]<=active_window or row["report_count"]<1 or row.get("credential_generation") not in {"current","previous","legacy"} or row["device_id"] in generations: raise ValueError("activation_evidence_invalid")
        generations[row["device_id"]]=row["credential_generation"]
    if any(generations.get(device_id)!="current" for device_id in device_ids): raise ValueError("devices_not_on_current_credentials")

def provision(device_ids,output,enrollment_dir,rotate=False,prune_old=False,activation_evidence=None,evidence_now=None):
    if rotate and prune_old: raise ValueError("conflicting_operation")
    ids=sorted(set(device_ids))
    if not ids or any(not isinstance(item,str) or not re.fullmatch(r"[0-9a-f]{12}",item) for item in ids): raise ValueError("invalid_device_id")
    if prune_old: verify_activation_evidence(activation_evidence,ids,now=evidence_now)
    manifest=load_manifest(output); devices=manifest["devices"]
    if len(set(devices)|set(ids))>10000: raise ValueError("device_limit")
    created=[]; rotated=[]; pruned=[]
    for device_id in ids:
        current=devices.get(device_id)
        if current is None:
            current=devices[device_id]={"tokens":[secrets.token_urlsafe(48)],"signing_secrets":[secrets.token_urlsafe(48)]}; created.append(device_id)
        elif rotate:
            current["tokens"]=[secrets.token_urlsafe(48),*current["tokens"][:1]]; current["signing_secrets"]=[secrets.token_urlsafe(48),*current["signing_secrets"][:1]]; rotated.append(device_id)
        elif prune_old:
            if len(current["tokens"])>1 or len(current["signing_secrets"])>1: pruned.append(device_id)
            current["tokens"]=current["tokens"][:1]; current["signing_secrets"]=current["signing_secrets"][:1]
    enrollment_dir=Path(enrollment_dir)
    if enrollment_dir.is_symlink(): raise ValueError("enrollment_directory_symlink")
    enrollment_dir.mkdir(parents=True,exist_ok=True); enrollment_dir=enrollment_dir.resolve(strict=True); os.chmod(enrollment_dir,0o700)
    for device_id in ids:
        credential=devices[device_id]
        private_atomic(enrollment_dir/(device_id+".json"),{"schema":ENROLLMENT_SCHEMA,"device_id":device_id,"report_token":credential["tokens"][0],"signing_secret":credential["signing_secrets"][0]})
    private_atomic(output,manifest,preserve_metadata=True)
    return {"ok":True,"device_count":len(devices),"created":created,"rotated":rotated,"pruned":pruned,"secrets_printed":False}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("device_ids",nargs="+"); ap.add_argument("--output",required=True); ap.add_argument("--enrollment-dir",required=True); ap.add_argument("--activation-evidence"); group=ap.add_mutually_exclusive_group(); group.add_argument("--rotate",action="store_true"); group.add_argument("--prune-old",action="store_true"); args=ap.parse_args()
    result=provision(args.device_ids,args.output,args.enrollment_dir,args.rotate,args.prune_old,args.activation_evidence); print(json.dumps(result,separators=(",",":")))

if __name__=="__main__": main()
