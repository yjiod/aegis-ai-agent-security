#!/usr/bin/env python3
"""Minimal report collector reference. Put behind enterprise TLS/reverse proxy."""
import argparse, hashlib, hmac, json, os, sqlite3, time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

@contextmanager
def db_open(path):
    db=sqlite3.connect(path)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, report_hash TEXT, device_id TEXT NOT NULL, received_at INTEGER NOT NULL, severity TEXT NOT NULL, body TEXT NOT NULL)")
        columns={row[1] for row in db.execute("PRAGMA table_info(reports)")}
        if "report_hash" not in columns: db.execute("ALTER TABLE reports ADD COLUMN report_hash TEXT")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_hash ON reports(report_hash) WHERE report_hash IS NOT NULL")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_device_time ON reports(device_id, received_at DESC)"); db.commit()
        yield db
    finally: db.close()
def valid_report(d,now=None):
    """Validate the published v1 contract without a third-party JSON Schema runtime."""
    if not isinstance(d,dict): return False
    required={"schema","agent_version","policy_version","device_id","scanned_at","summary","findings"}
    allowed=required|{"scan_root","inventory"}
    if not required.issubset(d) or not set(d).issubset(allowed): return False
    if d.get("schema")!="sentinel.report/v1": return False
    if not all(isinstance(d.get(k),str) and d[k] for k in ("agent_version","policy_version")): return False
    if not isinstance(d.get("device_id"),str) or not 8<=len(d["device_id"])<=128: return False
    if "scan_root" in d and not isinstance(d["scan_root"],str): return False
    if "inventory" in d and (not isinstance(d["inventory"],list) or any(not isinstance(x,dict) for x in d["inventory"])): return False
    if not isinstance(d.get("scanned_at"),int) or isinstance(d["scanned_at"],bool): return False
    now=int(time.time()) if now is None else now
    if abs(now-d["scanned_at"])>7*86400: return False
    summary=d.get("summary")
    levels=("critical","high","medium","low")
    if not isinstance(summary,dict) or set(summary)!=set(levels): return False
    if any(not isinstance(summary[x],int) or isinstance(summary[x],bool) or summary[x]<0 for x in levels): return False
    findings=d.get("findings")
    if not isinstance(findings,list) or len(findings)>10000: return False
    counts={x:0 for x in levels}
    for finding in findings:
        if not isinstance(finding,dict) or not {"kind","severity","path","message"}.issubset(finding): return False
        if not set(finding).issubset({"kind","severity","path","message","evidence"}): return False
        if finding.get("severity") not in counts: return False
        if any(not isinstance(finding.get(k),str) for k in ("kind","path","message")): return False
        if "evidence" in finding and not isinstance(finding["evidence"],str): return False
        counts[finding["severity"]]+=1
    return counts==summary
class Handler(BaseHTTPRequestHandler):
    server_version="SentinelCollector/0.1"
    def reply(self,status,data):
        body=json.dumps(data,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def authorized(self):
        expected=os.getenv("SENTINEL_COLLECTOR_TOKEN",""); supplied=self.headers.get("Authorization","").removeprefix("Bearer "); return bool(expected) and hmac.compare_digest(expected,supplied)
    def do_GET(self):
        if self.path=="/health": return self.reply(200,{"status":"ok"})
        if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
        if self.path=="/v1/devices":
            with db_open(self.server.db_path) as db: rows=db.execute("SELECT device_id, MAX(received_at), COUNT(*) FROM reports GROUP BY device_id ORDER BY MAX(received_at) DESC LIMIT 500").fetchall()
            return self.reply(200,{"devices":[{"device_id":r[0],"last_seen":r[1],"report_count":r[2]} for r in rows]})
        self.reply(404,{"error":"not_found"})
    def do_POST(self):
        if self.path!="/v1/reports": return self.reply(404,{"error":"not_found"})
        if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
        try:
            length=int(self.headers.get("Content-Length","0"));
            if length<2 or length>2_000_000: return self.reply(413,{"error":"invalid_size"})
            body=self.rfile.read(length); report=json.loads(body)
            if not valid_report(report): return self.reply(400,{"error":"invalid_report"})
            severity="critical" if report["summary"].get("critical",0) else "high" if report["summary"].get("high",0) else "normal"; digest=hashlib.sha256(body).hexdigest(); report_id=digest[:20]
            with db_open(self.server.db_path) as db:
                cursor=db.execute("INSERT OR IGNORE INTO reports(report_hash,device_id,received_at,severity,body) VALUES(?,?,?,?,?)",(digest,report["device_id"],int(time.time()),severity,body.decode())); db.commit(); duplicate=cursor.rowcount==0
            self.reply(200 if duplicate else 202,{"accepted":True,"duplicate":duplicate,"report_id":report_id,"severity":severity})
        except Exception: self.reply(400,{"error":"invalid_json"})
    def log_message(self,fmt,*args): pass
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--listen",default="127.0.0.1"); ap.add_argument("--port",type=int,default=8788); ap.add_argument("--db",default="sentinel.db"); args=ap.parse_args()
    if not os.getenv("SENTINEL_COLLECTOR_TOKEN"): raise SystemExit("SENTINEL_COLLECTOR_TOKEN is required")
    server=ThreadingHTTPServer((args.listen,args.port),Handler); server.db_path=args.db; server.serve_forever()
if __name__=="__main__": main()
