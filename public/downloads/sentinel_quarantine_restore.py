#!/usr/bin/env python3
"""Restore one macOS/Linux quarantine event using externally delivered approval evidence."""
import argparse, hashlib, json, os, re, stat, sys, time
from pathlib import Path
from sentinel_agent import _append_enforcement_audit

APPROVAL_SCHEMA="sentinel.quarantine-approval/v1"
def private_json(path,max_bytes=65536):
    path=Path(path); info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_size>max_bytes: raise ValueError("unsafe_private_input")
    if hasattr(os,"geteuid") and info.st_uid not in {0,os.geteuid()}: raise ValueError("unsafe_private_owner")
    return json.loads(path.read_text(encoding="utf-8"))
def validate_chain(events):
    previous="0"*64
    for event in events:
        if not isinstance(event,dict) or event.get("previous_hash")!=previous or not re.fullmatch(r"[0-9a-f]{64}",str(event.get("event_hash",""))): raise ValueError("invalid_audit_chain")
        body={key:value for key,value in event.items() if key not in {"previous_hash","event_hash"}}
        expected=hashlib.sha256((previous+json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False)).encode()).hexdigest()
        if event["event_hash"]!=expected: raise ValueError("invalid_audit_chain")
        previous=expected
def restore(audit_path,approval_path,now=None):
    audit=private_json(audit_path,4_000_000); approval=private_json(approval_path); events=audit.get("events") if isinstance(audit,dict) and audit.get("schema")=="sentinel.quarantine-audit/v1" else None
    if not isinstance(events,list) or not events: raise ValueError("invalid_quarantine_audit")
    validate_chain(events); expected={"schema","event_hash","decision","approved_by_ref","issued_at","expires_at"}
    if not isinstance(approval,dict) or set(approval)!=expected or approval.get("schema")!=APPROVAL_SCHEMA or approval.get("decision")!="restore" or not re.fullmatch(r"[0-9a-f]{16,64}",str(approval.get("approved_by_ref",""))): raise ValueError("invalid_restore_approval")
    now=int(time.time()) if now is None else int(now)
    if type(approval.get("issued_at")) is not int or type(approval.get("expires_at")) is not int or not -300<=now-approval["issued_at"]<=3600 or not 0<=approval["expires_at"]-now<=3600: raise ValueError("stale_restore_approval")
    event=next((item for item in events if item.get("event_hash")==approval.get("event_hash") and item.get("action")=="disable"),None)
    if not event: raise ValueError("approved_event_not_found")
    original=Path(event["original_path"]); disabled=Path(event["disabled_path"])
    if disabled.parent!=original.parent or disabled.name!=original.name+".sentinel-disabled" or disabled.is_symlink() or not disabled.is_file() or original.exists() or original.is_symlink(): raise ValueError("unsafe_restore_target")
    disabled.rename(original)
    try: _append_enforcement_audit(Path(audit_path).parent,{"action":"restore","kind":event["kind"],"object_ref":event["object_ref"],"original_path":str(original),"disabled_path":str(disabled),"occurred_at":now,"approval_event_hash":event["event_hash"],"approved_by_ref":approval["approved_by_ref"]})
    except Exception:
        original.rename(disabled); raise
    Path(approval_path).unlink(); return {"ok":True,"restored":True,"event_hash":event["event_hash"]}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--audit",required=True); ap.add_argument("--approval",required=True); args=ap.parse_args()
    if hasattr(os,"geteuid") and os.geteuid()!=0: raise SystemExit("root is required")
    try: print(json.dumps(restore(args.audit,args.approval),separators=(",",":"))); return 0
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc: print(json.dumps({"ok":False,"error":str(exc)},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
