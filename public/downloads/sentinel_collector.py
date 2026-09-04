#!/usr/bin/env python3
"""Minimal report collector reference. Put behind enterprise TLS/reverse proxy."""
import argparse, hashlib, hmac, json, os, sqlite3, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def db_open(path):
    db=sqlite3.connect(path); db.execute("CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, received_at INTEGER NOT NULL, severity TEXT NOT NULL, body TEXT NOT NULL)"); db.execute("CREATE INDEX IF NOT EXISTS idx_reports_device_time ON reports(device_id, received_at DESC)"); db.commit(); return db
def valid_report(d): return isinstance(d,dict) and d.get("schema")=="sentinel.report/v1" and isinstance(d.get("device_id"),str) and isinstance(d.get("findings"),list) and isinstance(d.get("summary"),dict)
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
            severity="critical" if report["summary"].get("critical",0) else "high" if report["summary"].get("high",0) else "normal"; report_id=hashlib.sha256(body).hexdigest()[:20]
            with db_open(self.server.db_path) as db: db.execute("INSERT INTO reports(device_id,received_at,severity,body) VALUES(?,?,?,?)",(report["device_id"],int(time.time()),severity,body.decode())); db.commit()
            self.reply(202,{"accepted":True,"report_id":report_id,"severity":severity})
        except Exception: self.reply(400,{"error":"invalid_json"})
    def log_message(self,fmt,*args): pass
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--listen",default="127.0.0.1"); ap.add_argument("--port",type=int,default=8788); ap.add_argument("--db",default="sentinel.db"); args=ap.parse_args()
    if not os.getenv("SENTINEL_COLLECTOR_TOKEN"): raise SystemExit("SENTINEL_COLLECTOR_TOKEN is required")
    server=ThreadingHTTPServer((args.listen,args.port),Handler); server.db_path=args.db; server.serve_forever()
if __name__=="__main__": main()
