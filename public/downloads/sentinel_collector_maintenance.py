#!/usr/bin/env python3
"""Run bounded retention and integrity maintenance for the Sentinel Collector."""
import argparse, json, os, sqlite3, stat, sys, time
from pathlib import Path

import sentinel_collector as collector

def validate_database(path):
    path=Path(path)
    parent=path.parent
    if parent.is_symlink() or not parent.is_dir(): raise ValueError("unsafe_database_directory")
    parent_info=parent.stat()
    if parent_info.st_uid not in {0,os.geteuid()} or stat.S_IMODE(parent_info.st_mode)&0o022: raise ValueError("unsafe_database_directory")
    if path.is_symlink(): raise ValueError("unsafe_database_file")
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0,os.geteuid()} or stat.S_IMODE(info.st_mode) not in {0o600,0o640}: raise ValueError("unsafe_database_file")
    return path

def maintain(path,now=None,report_days=None,audit_days=None,audit_limit=None):
    path=validate_database(path); now=int(time.time()) if now is None else int(now)
    report_days=collector.retention_days(report_days); audit_days=collector.audit_retention_days(audit_days); audit_limit=collector.audit_max_events(audit_limit)
    with collector.db_open(path) as db:
        before_reports=db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]; before_audit=db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM reports WHERE received_at < ?",(now-report_days*86400,))
        collector.prune_audit(db,now,audit_days,audit_limit)
        db.execute("INSERT INTO audit_events(event,occurred_at,detail) VALUES(?,?,?)",("maintenance_completed",now,"retention_enforced")); collector.prune_audit(db,now,audit_days,audit_limit); db.commit()
        after_reports=db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]; after_audit=db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        integrity=db.execute("PRAGMA quick_check").fetchone()[0]
        if integrity!="ok": raise sqlite3.DatabaseError("database_quick_check_failed")
        checkpoint=db.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        db.execute("PRAGMA optimize")
    return {"ok":True,"reports_deleted":before_reports-after_reports,"audit_events_deleted":max(0,before_audit+1-after_audit),"reports_retained":after_reports,"audit_events_retained":after_audit,"wal_busy":int(checkpoint[0]),"secrets_printed":False}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--db",default="sentinel.db"); args=parser.parse_args()
    try: print(json.dumps(maintain(args.db),separators=(",",":"),sort_keys=True)); return 0
    except (OSError,ValueError,sqlite3.Error) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
