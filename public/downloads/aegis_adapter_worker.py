#!/usr/bin/env python3
"""Dispatch accepted collector reports through the fail-safe vendor adapter."""
import argparse, importlib.util, json, os, sqlite3, time
from contextlib import contextmanager
from pathlib import Path

def load_adapter(path=None):
    path=Path(path or Path(__file__).with_name("aegis_adapter.py"))
    spec=importlib.util.spec_from_file_location("aegis_adapter_runtime",path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

def retention_days(value=None):
    raw=os.getenv("AEGIS_ADAPTER_DISPATCH_RETENTION_DAYS","90") if value is None else value
    try: return min(max(int(raw),1),3650)
    except (TypeError,ValueError): return 90

def batch_size(value=None):
    raw=os.getenv("AEGIS_ADAPTER_BATCH_SIZE","50") if value is None else value
    try: return min(max(int(raw),1),500)
    except (TypeError,ValueError): return 50

def poll_seconds(value=None):
    raw=os.getenv("AEGIS_ADAPTER_POLL_SECONDS","10") if value is None else value
    try: return min(max(float(raw),1),3600)
    except (TypeError,ValueError): return 10

def preflight(config,adapter):
    adapter.validate_config(config)
    enabled=0
    for name in adapter.ADAPTERS:
        target=config.get(name,{})
        if not target.get("enabled"): continue
        enabled+=1; adapter.validate_target(name,target,config)
        if name=="vendor_edr":
            for action in target.get("actions",{}).values():
                if action not in adapter.SAFE_ACTIONS: raise ValueError(f"unsafe_vendor_edr_action:{action}")
    if not enabled: raise ValueError("no_enabled_adapters")

@contextmanager
def open_db(path):
    db=sqlite3.connect(path,timeout=5)
    try:
        db.execute("PRAGMA busy_timeout=5000"); db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS adapter_dispatches(report_id INTEGER PRIMARY KEY, report_hash TEXT NOT NULL, processed_at INTEGER NOT NULL, result TEXT NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_adapter_dispatch_time ON adapter_dispatches(processed_at)"); db.commit(); yield db
    finally: db.close()

def result_summary(outputs):
    allowed=("adapter","result","status","queue_id","error")
    return [{key:item[key] for key in allowed if key in item} for item in outputs]

def dispatch_once(db_path,config,spool,adapter=None,sender=None,limit=None,now=None):
    adapter=adapter or load_adapter(); preflight(config,adapter); now=int(time.time()) if now is None else int(now)
    spool=Path(spool); adapter.flush_spool(config,spool,sender=sender or adapter.send)
    with open_db(db_path) as db:
        db.execute("DELETE FROM adapter_dispatches WHERE processed_at < ? AND report_id NOT IN (SELECT id FROM reports)",(now-retention_days()*86400,)); db.commit()
        rows=db.execute("SELECT r.id,COALESCE(r.report_hash,''),r.body FROM reports r LEFT JOIN adapter_dispatches d ON d.report_id=r.id WHERE d.report_id IS NULL ORDER BY r.id LIMIT ?",(batch_size(limit),)).fetchall()
    completed=[]
    for report_id,report_hash,body in rows:
        try: report=json.loads(body)
        except (TypeError,ValueError,RecursionError):
            encoded='[{"adapter":"boundary","result":"rejected_invalid_stored_report"}]'
            with open_db(db_path) as db:
                db.execute("INSERT OR IGNORE INTO adapter_dispatches(report_id,report_hash,processed_at,result) VALUES(?,?,?,?)",(report_id,report_hash[:64],now,encoded)); db.commit()
            completed.append({"report_id":report_id,"result":"rejected_invalid_stored_report"}); continue
        outputs=adapter.process(report,config,spool_dir=spool,sender=sender or adapter.send)
        accepted=bool(outputs) and all(item.get("result") in {"sent","queued"} for item in outputs)
        summary=result_summary(outputs)
        if not accepted: completed.append({"report_id":report_id,"result":"retained","outputs":summary}); continue
        encoded=json.dumps(summary,ensure_ascii=False,separators=(",",":"))
        if len(encoded)>16384: encoded='[{"result":"accepted_result_truncated"}]'
        with open_db(db_path) as db:
            db.execute("INSERT OR IGNORE INTO adapter_dispatches(report_id,report_hash,processed_at,result) VALUES(?,?,?,?)",(report_id,report_hash[:64],now,encoded)); db.commit()
        completed.append({"report_id":report_id,"result":"dispatched","outputs":summary})
    return completed

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--db",default="/var/lib/aegis/aegis.db"); ap.add_argument("--config",default="/etc/aegis/adapters.json"); ap.add_argument("--spool",default="/var/lib/aegis/adapter-spool"); ap.add_argument("--once",action="store_true"); args=ap.parse_args()
    adapter=load_adapter()
    try: config=json.loads(Path(args.config).read_text()); preflight(config,adapter)
    except (OSError,ValueError,TypeError,RecursionError) as exc: raise SystemExit("invalid adapter worker configuration: "+str(exc))
    while True:
        results=dispatch_once(args.db,config,args.spool,adapter=adapter)
        if args.once: print(json.dumps(results,ensure_ascii=False,indent=2)); return
        time.sleep(poll_seconds())

if __name__=="__main__": main()
