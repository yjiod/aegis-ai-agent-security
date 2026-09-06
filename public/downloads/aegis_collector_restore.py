#!/usr/bin/env python3
"""Verify a Aegis backup and create a non-overwriting restore candidate."""
import argparse, json, os, sqlite3, tempfile
from contextlib import closing
from pathlib import Path

def quick_check(path):
    with closing(sqlite3.connect(path,timeout=5)) as db:
        return db.execute("PRAGMA quick_check").fetchone()==("ok",)

def restore_candidate(backup,output):
    backup=Path(backup).resolve(strict=True)
    if not backup.is_file(): raise ValueError("backup_not_file")
    if not quick_check(backup): raise sqlite3.DatabaseError("backup_integrity_failed")
    output=Path(output)
    if output.exists() or output.is_symlink(): raise FileExistsError("output_exists")
    parent=output.parent; parent.mkdir(parents=True,exist_ok=True); parent=parent.resolve(strict=True); output=parent/output.name
    fd,temp_name=tempfile.mkstemp(prefix=".aegis-restore-",suffix=".tmp",dir=parent); os.close(fd); temp=Path(temp_name)
    try:
        with closing(sqlite3.connect(backup,timeout=5)) as src,closing(sqlite3.connect(temp,timeout=5)) as dst: src.backup(dst)
        if not quick_check(temp): raise sqlite3.DatabaseError("restore_integrity_failed")
        os.chmod(temp,0o600); os.link(temp,output); temp.unlink()
    except Exception:
        temp.unlink(missing_ok=True); raise
    return output

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--backup",required=True); ap.add_argument("--output",required=True); args=ap.parse_args()
    path=restore_candidate(args.backup,args.output)
    print(json.dumps({"ok":True,"restore_candidate":str(path),"integrity":"ok","activation":"manual_change_control_required"},ensure_ascii=False,separators=(",",":")))

if __name__=="__main__": main()
