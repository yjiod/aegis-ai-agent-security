#!/usr/bin/env python3
"""Create and verify an atomic online backup of the Aegis collector database."""
import argparse, json, os, sqlite3, tempfile, time, uuid
from contextlib import closing
from pathlib import Path

def keep_count(value):
    try: return min(max(int(value),1),365)
    except (TypeError,ValueError): return 14

def quick_check(path):
    with closing(sqlite3.connect(path,timeout=5)) as db:
        return db.execute("PRAGMA quick_check").fetchone()==("ok",)

def backup_database(source,directory,keep=14,now=None):
    source=Path(source).resolve(strict=True)
    if not source.is_file(): raise ValueError("source_not_file")
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True); directory=directory.resolve(strict=True)
    stamp=time.strftime("%Y%m%dT%H%M%SZ",time.gmtime(time.time() if now is None else now))
    final=directory/f"aegis-backup-{stamp}-{uuid.uuid4().hex[:8]}.sqlite"
    fd,temp_name=tempfile.mkstemp(prefix=".aegis-backup-",suffix=".tmp",dir=directory); os.close(fd); temp=Path(temp_name)
    try:
        with closing(sqlite3.connect(source,timeout=5)) as src,closing(sqlite3.connect(temp,timeout=5)) as dst: src.backup(dst)
        if not quick_check(temp): raise sqlite3.DatabaseError("backup_integrity_failed")
        os.chmod(temp,0o600); os.replace(temp,final)
    except Exception:
        temp.unlink(missing_ok=True); raise
    backups=sorted(directory.glob("aegis-backup-*.sqlite"),key=lambda item:item.stat().st_mtime,reverse=True)
    for old in backups[keep_count(keep):]:
        if old.is_file() and not old.is_symlink(): old.unlink()
    return final

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--db",default="aegis.db"); ap.add_argument("--output",required=True); ap.add_argument("--keep",default=14,type=int); args=ap.parse_args()
    path=backup_database(args.db,args.output,args.keep)
    print(json.dumps({"ok":True,"backup":str(path),"integrity":"ok"},ensure_ascii=False,separators=(",",":")))

if __name__=="__main__": main()
