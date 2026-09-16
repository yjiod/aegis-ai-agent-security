#!/usr/bin/env python3
"""Minimal report collector reference. Put behind enterprise TLS/reverse proxy."""
import argparse, hashlib, hmac, json, os, re, sqlite3, stat, threading, time
from collections import deque
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

@contextmanager
def db_open(path):
    db=sqlite3.connect(path,timeout=5)
    try:
        db.execute("PRAGMA busy_timeout=5000"); db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, report_hash TEXT, device_id TEXT NOT NULL, received_at INTEGER NOT NULL, severity TEXT NOT NULL, body TEXT NOT NULL)")
        columns={row[1] for row in db.execute("PRAGMA table_info(reports)")}
        if "report_hash" not in columns: db.execute("ALTER TABLE reports ADD COLUMN report_hash TEXT")
        if "agent_version" not in columns: db.execute("ALTER TABLE reports ADD COLUMN agent_version TEXT")
        if "policy_version" not in columns: db.execute("ALTER TABLE reports ADD COLUMN policy_version TEXT")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_hash ON reports(report_hash) WHERE report_hash IS NOT NULL")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_device_time ON reports(device_id, received_at DESC)"); db.commit()
        db.execute("CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY,event TEXT NOT NULL,occurred_at INTEGER NOT NULL,device_id TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '')")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(occurred_at DESC)"); db.commit()
        db.execute("CREATE TABLE IF NOT EXISTS device_auth_state(device_id TEXT PRIMARY KEY,last_seen INTEGER NOT NULL,generation INTEGER NOT NULL)"); db.commit()
        # 每设备上报令牌（批4）：token 以 sha256 哈希存储（不落明文），signing_secret 与
        # 凭据文件同待遇（服务端受控存储）。report_authentication 双接受：全局令牌 ∪ 每设备令牌。
        db.execute("CREATE TABLE IF NOT EXISTS device_tokens(device_id TEXT NOT NULL,token_hash TEXT NOT NULL,signing_secret TEXT NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(device_id,token_hash))"); db.commit()
        # 企业级 MD（用户自有基线）：控制台发布时推送至此；按灰度范围下发给终端。
        # 与上游同步基线完全分离（独立表/独立文件），互不影响。
        db.execute("CREATE TABLE IF NOT EXISTS enterprise_baseline(id INTEGER PRIMARY KEY CHECK(id=1),content TEXT NOT NULL,version INTEGER NOT NULL,rollout_json TEXT NOT NULL,updated_at INTEGER NOT NULL)"); db.commit()
        yield db
    finally: db.close()
def enterprise_in_scope(device_id, department, rollout):
    """企业级 MD 灰度范围判定：all=全量；percent=按 device_id 哈希百分比；department=部门白名单。"""
    if not isinstance(rollout,dict): return False
    mode=rollout.get("mode","all")
    if mode=="all": return True
    if mode=="percent":
        try: p=int(rollout.get("percent",0))
        except (TypeError,ValueError): return False
        p=max(0,min(100,p))
        return (int(hashlib.sha256((device_id or "").encode()).hexdigest(),16)%100) < p
    if mode=="department":
        deps=rollout.get("departments")
        if not isinstance(deps,list): return False
        return (department or "") in [x for x in deps if isinstance(x,str)]
    return False
def valid_signal_matches(sm):
    """有界校验 Agent 回收的能力命中证据（可选字段，向后兼容旧 Agent）。
    形状：{counts:{exec,cred,network,filewrite}, score:0..6, samples:[{cap,file,line,text}]}。
    只放宽到必要边界，任何越界/类型不符一律拒绝，防止报告被用来撑爆存储或注入。"""
    if not isinstance(sm,dict) or not set(sm)<={"counts","score","samples"}: return False
    counts=sm.get("counts")
    if counts is not None:
        if not isinstance(counts,dict) or not set(counts)<={"exec","cred","network","filewrite"}: return False
        if any(not isinstance(v,int) or isinstance(v,bool) or v<0 or v>1000000 for v in counts.values()): return False
    if "score" in sm:
        sc=sm["score"]
        if not isinstance(sc,int) or isinstance(sc,bool) or not 0<=sc<=6: return False
    samples=sm.get("samples")
    if samples is not None:
        if not isinstance(samples,list) or len(samples)>64: return False
        for m in samples:
            if not isinstance(m,dict) or not set(m)<={"cap","file","line","text"}: return False
            if m.get("cap") not in {"exec","cred","network","filewrite"}: return False
            if not isinstance(m.get("file"),str) or not 1<=len(m["file"])<=512: return False
            ln=m.get("line")
            if not isinstance(ln,int) or isinstance(ln,bool) or ln<1: return False
            if not isinstance(m.get("text"),str) or len(m["text"])>200: return False
    return True
def valid_report(d,now=None):
    """Validate the published v1 contract without a third-party JSON Schema runtime."""
    if not isinstance(d,dict): return False
    required={"schema","agent_version","policy_version","device_id","scanned_at","summary","findings"}
    allowed=required|{"scan_root","inventory","hostname","os_user","owner","os","serial","enterprise_baseline_version"}
    if not required.issubset(d) or not set(d).issubset(allowed): return False
    if d.get("schema")!="aegis.report/v1": return False
    if "owner" in d and not (isinstance(d["owner"],str) and len(d["owner"])<=64): return False
    if "enterprise_baseline_version" in d and not (isinstance(d["enterprise_baseline_version"],str) and len(d["enterprise_baseline_version"])<=32): return False
    if "os" in d and not (isinstance(d["os"],str) and 1<=len(d["os"])<=16): return False
    if "serial" in d and not (isinstance(d["serial"],str) and len(d["serial"])<=64): return False
    if not all(isinstance(d.get(k),str) and 1<=len(d[k])<=64 for k in ("agent_version","policy_version")): return False
    if not isinstance(d.get("device_id"),str) or not 8<=len(d["device_id"])<=128: return False
    if "scan_root" in d and (not isinstance(d["scan_root"],str) or len(d["scan_root"])>1024): return False
    if "inventory" in d and (not isinstance(d["inventory"],list) or len(d["inventory"])>5000 or any(not isinstance(x,dict) for x in d["inventory"])): return False
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
        if not set(finding).issubset({"kind","severity","path","message","evidence","signal_matches","asset_type","asset_key"}): return False
        if finding.get("severity") not in counts: return False
        if any(not isinstance(finding.get(k),str) for k in ("kind","path","message")): return False
        if not 1<=len(finding["kind"])<=128 or len(finding["path"])>2048 or not 1<=len(finding["message"])<=2048: return False
        if "evidence" in finding and (not isinstance(finding["evidence"],str) or len(finding["evidence"])>512): return False
        # 同源键(终端 0.34.1+)：显式上报资产身份，供控制台按"名字"精确匹配加白标签→抑制告警/自动消除。
        # 必须纳入 finding 字段白名单，否则新终端上报恒被判 invalid_report → 400 拒收（级联漏改）。
        if "asset_type" in finding and not (isinstance(finding["asset_type"],str) and finding["asset_type"] in {"skill","mcp"}): return False
        if "asset_key" in finding and not (isinstance(finding["asset_key"],str) and 1<=len(finding["asset_key"])<=128): return False
        if "signal_matches" in finding and not valid_signal_matches(finding["signal_matches"]): return False
        counts[finding["severity"]]+=1
    return counts==summary
def signature_index(headers,body,secrets,now=None,max_skew=300):
    if not secrets: return -1 if allow_unsigned_reports() else None
    def header(name): return headers.get(name) or headers.get(name.lower())
    timestamp=header("X-Aegis-Timestamp"); supplied=header("X-Aegis-Signature") or ""
    try: request_time=int(timestamp)
    except (TypeError,ValueError): return None
    now=int(time.time()) if now is None else now
    if abs(now-request_time)>max_skew: return None
    device_id=header("X-Aegis-Device-ID") or ""; prefix=timestamp.encode()+b"."+(device_id.encode()+b"." if device_id else b"")
    matches=[]
    for candidate in secrets:
        expected="sha256="+hmac.new(candidate.encode(),prefix+body,hashlib.sha256).hexdigest(); matches.append(hmac.compare_digest(expected,supplied))
    return next((index for index,matched in enumerate(matches) if matched),None)
def valid_signature(headers,body,now=None,secret=None,max_skew=300):
    secrets=secret_values("AEGIS_REPORT_SIGNING_SECRET","AEGIS_REPORT_SIGNING_SECRETS") if secret is None else (secret if isinstance(secret,list) else ([secret] if secret else []))
    return signature_index(headers,body,secrets,now,max_skew) is not None
def secret_values(single_name,multiple_name,env=None):
    env=os.environ if env is None else env; raw=env.get(multiple_name,"")
    if raw:
        try: values=json.loads(raw)
        except (TypeError,ValueError): return []
        if not isinstance(values,list) or not 1<=len(values)<=5: return []
        if any(not isinstance(value,str) or not value or len(value)>4096 for value in values): return []
        return values
    value=env.get(single_name,""); return [value] if value and len(value)<=4096 else []
def allow_unsigned_reports(value=None):
    raw=os.getenv("AEGIS_ALLOW_UNSIGNED_REPORTS","") if value is None else value
    return str(raw).strip().lower() in {"1","true","yes"}
def device_credentials(path=None):
    path=os.getenv("AEGIS_DEVICE_CREDENTIALS_FILE","") if path is None else path
    if not path: return {}
    source=Path(path)
    if source.is_symlink(): raise ValueError("device_credentials_symlink")
    info=source.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o600,0o640} or info.st_uid not in {0,os.geteuid()}: raise ValueError("device_credentials_permissions")
    value=json.loads(source.read_text(encoding="utf-8")); devices=value.get("devices") if isinstance(value,dict) else None
    if set(value)!={"schema","devices"} or value.get("schema")!="aegis.device-credentials/v1" or not isinstance(devices,dict) or not 1<=len(devices)<=10000: raise ValueError("device_credentials_contract")
    normalized={}; all_tokens=set(); all_signing=set()
    for device_id,credential in devices.items():
        if not isinstance(device_id,str) or not re.fullmatch(r"[0-9a-f]{12}",device_id) or not isinstance(credential,dict) or set(credential)!={"tokens","signing_secrets"}: raise ValueError("device_credentials_contract")
        tokens=credential.get("tokens"); signing=credential.get("signing_secrets")
        if any(not isinstance(values,list) or not 1<=len(values)<=5 or any(not isinstance(item,str) or not 32<=len(item)<=4096 for item in values) or len(values)!=len(set(values)) for values in (tokens,signing)) or set(tokens)&set(signing): raise ValueError("device_credentials_secrets")
        if all_tokens.intersection(tokens) or all_signing.intersection(signing) or all_tokens.intersection(signing) or all_signing.intersection(tokens): raise ValueError("device_credentials_not_independent")
        all_tokens.update(tokens); all_signing.update(signing); normalized[device_id]={"tokens":tokens,"signing_secrets":signing}
    return normalized
def runtime_secret_errors(env=None):
    env=os.environ if env is None else env
    tokens=secret_values("AEGIS_COLLECTOR_TOKEN","AEGIS_COLLECTOR_TOKENS",env)
    signing=secret_values("AEGIS_REPORT_SIGNING_SECRET","AEGIS_REPORT_SIGNING_SECRETS",env)
    errors=[]
    if not tokens: errors.append("collector_token_missing_or_invalid")
    if any(len(value)<32 for value in tokens): errors.append("collector_token_too_short")
    if len(tokens)!=len(set(tokens)): errors.append("collector_token_duplicate")
    unsigned=str(env.get("AEGIS_ALLOW_UNSIGNED_REPORTS","")).strip().lower() in {"1","true","yes"}
    credentials_path=env.get("AEGIS_DEVICE_CREDENTIALS_FILE","")
    credentials={}
    if credentials_path:
        try: credentials=device_credentials(credentials_path)
        except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): errors.append("device_credentials_missing_or_invalid")
        device_secrets={item for credential in credentials.values() for values in credential.values() for item in values}
        if set(tokens)&device_secrets or set(signing)&device_secrets: errors.append("global_and_device_secret_reused")
    if not signing and not unsigned and not credentials_path: errors.append("signing_secret_missing_or_invalid")
    if any(len(value)<32 for value in signing): errors.append("signing_secret_too_short")
    if len(signing)!=len(set(signing)): errors.append("signing_secret_duplicate")
    if set(tokens)&set(signing): errors.append("authentication_and_signing_secret_reused")
    return errors
def retention_days(value=None):
    raw=os.getenv("AEGIS_RETENTION_DAYS","30") if value is None else value
    try: return min(max(int(raw),1),3650)
    except (TypeError,ValueError): return 30
def requests_per_minute(value=None):
    raw=os.getenv("AEGIS_REQUESTS_PER_MINUTE","120") if value is None else value
    try: return min(max(int(raw),1),10000)
    except (TypeError,ValueError): return 120
def audit_retention_days(value=None):
    raw=os.getenv("AEGIS_AUDIT_RETENTION_DAYS","90") if value is None else value
    try: return min(max(int(raw),1),3650)
    except (TypeError,ValueError): return 90
def audit_max_events(value=None):
    raw=os.getenv("AEGIS_AUDIT_MAX_EVENTS","100000") if value is None else value
    try: return min(max(int(raw),1000),1000000)
    except (TypeError,ValueError): return 100000
def required_version(name,default,env=None):
    env=os.environ if env is None else env; value=env.get(name,default)
    return value if isinstance(value,str) and 1<=len(value)<=64 else default
def semver_gte(a,b):
    """semver 比较 a>=b：高于 required 属正常升级(非漂移)，仅低于才算 mismatch。"""
    pa=[int(x) if x.isdigit() else 0 for x in str(a).split(".")[:3]]; pb=[int(x) if x.isdigit() else 0 for x in str(b).split(".")[:3]]
    pa+=( [0]*(3-len(pa)) ); pb+=( [0]*(3-len(pb)) )
    for x,y in zip(pa,pb):
        if x!=y: return x>y
    return True
class RateLimiter:
    """Bounded per-source sliding-window limiter for defense in depth."""
    def __init__(self,limit=None,window=60,max_sources=10000,clock=None):
        self.limit=requests_per_minute(limit); self.window=max(float(window),1); self.max_sources=max(int(max_sources),1)
        self.clock=time.monotonic if clock is None else clock; self.events={}; self.lock=threading.Lock()
    def check(self,source):
        now=self.clock(); source=str(source)[:128]
        with self.lock:
            queue=self.events.get(source)
            if queue is None:
                if len(self.events)>=self.max_sources:
                    oldest=min(self.events,key=lambda key:self.events[key][-1] if self.events[key] else 0); self.events.pop(oldest,None)
                queue=self.events[source]=deque()
            cutoff=now-self.window
            while queue and queue[0]<=cutoff: queue.popleft()
            if len(queue)>=self.limit: return False,max(1,int(self.window-(now-queue[0])+0.999))
            queue.append(now); return True,0
def store_report(db_path,body,report,now=None,days=None,credential_generation=None):
    now=int(time.time()) if now is None else now; days=retention_days(days)
    severity="critical" if report["summary"].get("critical",0) else "high" if report["summary"].get("high",0) else "normal"
    canonical=json.dumps(report,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode(); digest=hashlib.sha256(canonical).hexdigest(); receipt_id=hashlib.sha256(body).hexdigest()[:20]
    with db_open(db_path) as db:
        db.execute("DELETE FROM reports WHERE received_at < ?",(now-days*86400,))
        cursor=db.execute("INSERT OR IGNORE INTO reports(report_hash,device_id,received_at,severity,body,agent_version,policy_version) VALUES(?,?,?,?,?,?,?)",(digest,report["device_id"],now,severity,canonical.decode(),report.get("agent_version"),report.get("policy_version"))); duplicate=cursor.rowcount==0
        if credential_generation is not None: db.execute("INSERT INTO device_auth_state(device_id,last_seen,generation) VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen,generation=excluded.generation",(report["device_id"],now,int(credential_generation)))
        generation="legacy" if credential_generation is None else "g"+str(int(credential_generation)); db.execute("INSERT INTO audit_events(event,occurred_at,device_id,detail) VALUES(?,?,?,?)",("report_duplicate" if duplicate else "report_accepted",now,report["device_id"],digest[:20]+":"+severity+":"+generation)); prune_audit(db,now); db.commit()
    return {"accepted":True,"duplicate":duplicate,"report_id":receipt_id,"severity":severity}
def prune_audit(db,now=None,days=None,max_events=None):
    now=int(time.time()) if now is None else int(now); days=audit_retention_days(days); max_events=audit_max_events(max_events)
    db.execute("DELETE FROM audit_events WHERE occurred_at < ?",(now-days*86400,))
    db.execute("DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)",(max_events,))
def audit_event(db_path,event,device_id="",detail="",now=None):
    now=int(time.time()) if now is None else int(now)
    if not event or len(event)>64 or len(device_id)>128 or len(detail)>256: raise ValueError("invalid_audit_event")
    with db_open(db_path) as db:
        db.execute("INSERT INTO audit_events(event,occurred_at,device_id,detail) VALUES(?,?,?,?)",(event,now,device_id,detail)); prune_audit(db,now); db.commit()
def recent_audit(db_path,limit=200):
    limit=min(max(int(limit),1),500)
    with db_open(db_path) as db: rows=db.execute("SELECT event,occurred_at,device_id,detail FROM audit_events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [{"event":event,"occurred_at":occurred,"device_id":device,"detail":detail} for event,occurred,device,detail in rows]
def collector_summary(db_path,now=None,active_window=86400,required_agent=None,required_policy=None):
    """Return fleet posture from only the newest accepted report per device."""
    now=int(time.time()) if now is None else int(now); active_window=min(max(int(active_window),60),30*86400)
    with db_open(db_path) as db:
        rows=db.execute("SELECT r.received_at,r.severity,r.agent_version,r.policy_version,a.generation FROM reports r JOIN (SELECT device_id,MAX(id) AS id FROM reports GROUP BY device_id) latest ON latest.id=r.id LEFT JOIN device_auth_state a ON a.device_id=r.device_id").fetchall()
    by_severity={"critical":0,"high":0,"normal":0}
    versions={"current":0,"agent_mismatch":0,"policy_mismatch":0,"both_mismatch":0,"unknown":0}; required_agent=required_agent or required_version("AEGIS_REQUIRED_AGENT_VERSION","0.33.0"); required_policy=required_policy or required_version("AEGIS_REQUIRED_POLICY_VERSION","4.8.0")
    credential_posture={"current":0,"previous":0,"legacy":0}
    for _,severity,agent,policy,generation in rows:
        by_severity[severity if severity in by_severity else "normal"]+=1
        if not agent or not policy: versions["unknown"]+=1
        elif not semver_gte(agent,required_agent) and not semver_gte(policy,required_policy): versions["both_mismatch"]+=1
        elif not semver_gte(agent,required_agent): versions["agent_mismatch"]+=1
        elif not semver_gte(policy,required_policy): versions["policy_mismatch"]+=1
        else: versions["current"]+=1
        credential_posture["legacy" if generation is None else "current" if generation==0 else "previous"]+=1
    active=sum(received>=now-active_window for received,_,_,_,_ in rows)
    return {"generated_at":now,"active_window_seconds":active_window,"required_agent_version":required_agent,"required_policy_version":required_policy,"total_devices":len(rows),"active_devices":active,"stale_devices":len(rows)-active,"latest_severity":by_severity,"version_posture":versions,"credential_posture":credential_posture}
class Handler(BaseHTTPRequestHandler):
    server_version="AegisCollector/0.15"
    def reply(self,status,data,headers=None):
        body=json.dumps(data,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff")
        for name,value in (headers or {}).items(): self.send_header(name,str(value))
        self.end_headers(); self.wfile.write(body)
    def rate_limited(self):
        limiter=getattr(self.server,"rate_limiter",None)
        if limiter is None: return False
        allowed,retry=limiter.check(self.client_address[0])
        if allowed: return False
        self.reply(429,{"error":"rate_limited"},{"Retry-After":retry}); return True
    def authorized(self):
        expected=secret_values("AEGIS_COLLECTOR_TOKEN","AEGIS_COLLECTOR_TOKENS"); supplied=self.headers.get("Authorization","").removeprefix("Bearer "); matched=False
        for candidate in expected: matched |= hmac.compare_digest(candidate,supplied)
        return bool(expected) and matched
    def report_authentication(self):
        device_id=self.headers.get("X-Aegis-Device-ID","")
        supplied=self.headers.get("Authorization","").removeprefix("Bearer ")
        # 1) 每设备上报令牌（批4，DB 存储 sha256 哈希）：命中即通过（双接受过渡期）。
        if device_id and supplied:
            th=hashlib.sha256(supplied.encode()).hexdigest()
            try:
                with db_open(self.server.db_path) as db:
                    row=db.execute("SELECT signing_secret FROM device_tokens WHERE device_id=? AND token_hash=?",(device_id,th)).fetchone()
                if row: return (True,(device_id,[row[0]],0))
            except sqlite3.Error: pass
        # 2) 每设备凭据文件（既有机制）
        path=os.getenv("AEGIS_DEVICE_CREDENTIALS_FILE","")
        if not path: return (self.authorized(),None)
        try: credentials=device_credentials(path)
        except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): return (False,None)
        credential=credentials.get(device_id)
        if not credential: return (False,None)
        matched=False
        matches=[]
        for candidate in credential["tokens"]: matches.append(hmac.compare_digest(candidate,supplied))
        token_index=next((index for index,value in enumerate(matches) if value),None)
        return (token_index is not None,(device_id,credential["signing_secrets"],token_index))
    def do_GET(self):
        if self.path=="/health":
            try:
                with db_open(self.server.db_path) as db: db.execute("SELECT 1").fetchone()
                return self.reply(200,{"status":"ok","database":"ok"})
            except sqlite3.Error: return self.reply(503,{"status":"degraded","database":"unavailable"})
        if self.rate_limited(): return
        parsed=urlsplit(self.path)
        if parsed.path=="/v1/enterprise-baseline":
            # 终端拉取企业级 MD：用每设备令牌鉴权（report_authentication 亦回落接受管理令牌）。
            # 此分支必须置于下方全局管理令牌门 authorized() **之前**——终端持每设备上报令牌而非
            # 管理令牌，若先过 authorized() 会恒 401，令企业 MD 永远推不到终端（历史缺陷）。
            authenticated,binding=self.report_authentication()
            if not authenticated: return self.reply(401,{"error":"unauthorized"})
            q2=parse_qs(parsed.query,keep_blank_values=True)
            # 灰度分桶绑定"已认证"的 device_id（binding[0]），不信任可伪造的 query 值，
            # 防终端自报任意 device_id 挑选有利的 percent 分桶绕过灰度。
            did=(binding[0] if binding else (q2.get("device_id",[""])[0] or "").strip())
            dept=(q2.get("department",[""])[0] or "").strip()
            try:
                with db_open(self.server.db_path) as db:
                    row=db.execute("SELECT content,version,rollout_json FROM enterprise_baseline WHERE id=1").fetchone()
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            if not row: return self.reply(404,{"error":"not_published"})
            try: rollout=json.loads(row[2])
            except (ValueError,TypeError): rollout={}
            if not enterprise_in_scope(did,dept,rollout): return self.reply(404,{"error":"not_in_scope"})
            return self.reply(200,{"version":row[1],"content":row[0],"sha256":hashlib.sha256(row[0].encode()).hexdigest()})
        if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
        if parsed.path=="/v1/devices":
            query=parse_qs(parsed.query,keep_blank_values=True)
            if set(query)-{"limit"} or any(len(values)!=1 for values in query.values()): return self.reply(400,{"error":"invalid_query"})
            try: limit=int(query.get("limit",["500"])[0])
            except ValueError: return self.reply(400,{"error":"invalid_limit"})
            if not 1<=limit<=10000: return self.reply(400,{"error":"invalid_limit"})
            try:
                generated_at=int(time.time())
                with db_open(self.server.db_path) as db: rows=db.execute("WITH fleet AS (SELECT device_id,MAX(id) AS id,COUNT(*) AS report_count FROM reports GROUP BY device_id) SELECT r.device_id,COALESCE(a.last_seen,r.received_at),fleet.report_count,a.generation,r.body FROM fleet JOIN reports r ON r.id=fleet.id LEFT JOIN device_auth_state a ON a.device_id=r.device_id ORDER BY r.device_id LIMIT ?",(limit+1,)).fetchall()
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            complete=len(rows)<=limit; rows=rows[:limit]; audit_event(self.server.db_path,"devices_read",detail=str(len(rows))+":"+("complete" if complete else "partial"))
            devices_out=[]
            for r in rows:
                dev={"device_id":r[0],"last_seen":r[1],"report_count":r[2],"credential_generation":"legacy" if r[3] is None else "current" if r[3]==0 else "previous"}
                try:
                    body=json.loads(r[4]) if r[4] else {}
                    if isinstance(body,dict):
                        if isinstance(body.get("hostname"),str): dev["hostname"]=body["hostname"][:128]
                        if isinstance(body.get("os_user"),str): dev["os_user"]=body["os_user"][:64]
                        if isinstance(body.get("owner"),str): dev["owner"]=body["owner"][:64]
                        if isinstance(body.get("enterprise_baseline_version"),str): dev["enterprise_baseline_version"]=body["enterprise_baseline_version"][:32]
                        if isinstance(body.get("os"),str): dev["os"]=body["os"][:16]
                        if isinstance(body.get("serial"),str): dev["serial"]=body["serial"][:64]
                        if isinstance(body.get("agent_version"),str): dev["agent_version"]=body["agent_version"][:32]
                        if isinstance(body.get("policy_version"),str): dev["policy_version"]=body["policy_version"][:32]
                        inv=body.get("inventory")
                        if isinstance(inv,list):
                            dev["tools"]=sorted({x.get("name") for x in inv if isinstance(x,dict) and x.get("type")=="ai_agent" and isinstance(x.get("name"),str)})[:20]
                            dev["latest_severity"]={"critical":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="critical"),"high":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="high"),"medium":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="medium"),"low":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="low")}
                except (ValueError,TypeError): pass
                devices_out.append(dev)
            return self.reply(200,{"generated_at":generated_at,"complete":complete,"devices":devices_out})
        if parsed.path=="/v1/findings":
            query=parse_qs(parsed.query,keep_blank_values=True)
            if set(query)-{"device_id","limit"} or any(len(values)!=1 for values in query.values()): return self.reply(400,{"error":"invalid_query"})
            device_id=(query.get("device_id",[""])[0] or "").strip()
            if not device_id or len(device_id)>128: return self.reply(400,{"error":"invalid_device_id"})
            try: limit=int(query.get("limit",["200"])[0])
            except ValueError: return self.reply(400,{"error":"invalid_limit"})
            if not 1<=limit<=1000: return self.reply(400,{"error":"invalid_limit"})
            try:
                with db_open(self.server.db_path) as db: row=db.execute("SELECT body FROM reports WHERE device_id=? ORDER BY id DESC LIMIT 1",(device_id,)).fetchone()
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            if row is None: return self.reply(404,{"error":"device_not_found"})
            try: body=json.loads(row[0]) if row[0] else {}
            except (ValueError,TypeError): body={}
            findings=body.get("findings") if isinstance(body,dict) else None
            if not isinstance(findings,list): findings=[]
            audit_event(self.server.db_path,"findings_read",detail=device_id+":"+str(len(findings)))
            return self.reply(200,{"device_id":device_id,"scanned_at":body.get("scanned_at") if isinstance(body,dict) else None,"total":len(findings),"findings":findings[:limit]})
        if parsed.path=="/v1/summary" and not parsed.query:
            try:
                summary=collector_summary(self.server.db_path); audit_event(self.server.db_path,"summary_read",detail=str(summary["total_devices"])); return self.reply(200,summary)
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
        if parsed.path=="/v1/audit" and not parsed.query:
            try:
                audit_event(self.server.db_path,"audit_read"); return self.reply(200,{"events":recent_audit(self.server.db_path)})
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
        self.reply(404,{"error":"not_found"})
    def do_POST(self):
        # 控制台发布企业级 MD → 推送至此（仅管理令牌）；终端经 GET /v1/enterprise-baseline 按灰度拉取。
        if self.path=="/v1/enterprise-baseline":
            if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
            try: length=int(self.headers.get("Content-Length","0"))
            except ValueError: return self.reply(400,{"error":"invalid_size"})
            if length<2 or length>4_000_000: return self.reply(413,{"error":"invalid_size"})
            try: payload=json.loads(self.rfile.read(length))
            except (json.JSONDecodeError,UnicodeDecodeError,RecursionError,ValueError): return self.reply(400,{"error":"invalid_json"})
            content=payload.get("content"); version=payload.get("version"); rollout=payload.get("rollout")
            if not isinstance(content,str) or not (1<=len(content)<=2_000_000): return self.reply(400,{"error":"invalid_content"})
            if not isinstance(version,int) or isinstance(version,bool) or not (1<=version<=1_000_000): return self.reply(400,{"error":"invalid_version"})
            if not isinstance(rollout,dict): return self.reply(400,{"error":"invalid_rollout"})
            try:
                with db_open(self.server.db_path) as db:
                    db.execute("INSERT INTO enterprise_baseline(id,content,version,rollout_json,updated_at) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET content=excluded.content,version=excluded.version,rollout_json=excluded.rollout_json,updated_at=excluded.updated_at",(content,version,json.dumps(rollout,ensure_ascii=False),int(time.time())))
                    db.commit()
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            return self.reply(200,{"ok":True,"version":version})
        # 注册每设备上报令牌（批4，仅管理令牌）：存 sha256 哈希，不落明文。
        if self.path=="/v1/device-tokens":
            if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
            try: length=int(self.headers.get("Content-Length","0"))
            except ValueError: return self.reply(400,{"error":"invalid_size"})
            if length<2 or length>65536: return self.reply(413,{"error":"invalid_size"})
            try: payload=json.loads(self.rfile.read(length))
            except (json.JSONDecodeError,UnicodeDecodeError,RecursionError,ValueError): return self.reply(400,{"error":"invalid_json"})
            did=payload.get("device_id"); tok=payload.get("report_token"); sec=payload.get("signing_secret")
            if not isinstance(did,str) or not re.fullmatch(r"[0-9a-f]{12}",did): return self.reply(400,{"error":"invalid_device_id"})
            if not isinstance(tok,str) or not 32<=len(tok)<=4096: return self.reply(400,{"error":"invalid_token"})
            if not isinstance(sec,str) or not 32<=len(sec)<=4096: return self.reply(400,{"error":"invalid_signing_secret"})
            th=hashlib.sha256(tok.encode()).hexdigest()
            try:
                with db_open(self.server.db_path) as db:
                    db.execute("INSERT OR REPLACE INTO device_tokens(device_id,token_hash,signing_secret,created_at) VALUES(?,?,?,?)",(did,th,sec,int(time.time()))); db.commit()
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            return self.reply(201,{"ok":True,"device_id":did})
        if self.path!="/v1/reports": return self.reply(404,{"error":"not_found"})
        if self.rate_limited(): return
        authenticated,binding=self.report_authentication()
        if not authenticated: return self.reply(401,{"error":"unauthorized"})
        try: length=int(self.headers.get("Content-Length","0"))
        except ValueError: return self.reply(400,{"error":"invalid_size"})
        if length<2 or length>2_000_000: return self.reply(413,{"error":"invalid_size"})
        body=self.rfile.read(length)
        if binding:
            signing_index=signature_index(self.headers,body,binding[1])
            if signing_index is None or signing_index!=binding[2]: return self.reply(401,{"error":"credential_generation_mismatch"})
        elif not valid_signature(self.headers,body): return self.reply(401,{"error":"invalid_signature"})
        try: report=json.loads(body)
        except (json.JSONDecodeError,UnicodeDecodeError,RecursionError,ValueError): return self.reply(400,{"error":"invalid_json"})
        if not valid_report(report): return self.reply(400,{"error":"invalid_report"})
        if binding and report["device_id"]!=binding[0]: return self.reply(401,{"error":"device_identity_mismatch"})
        try: result=store_report(self.server.db_path,body,report,credential_generation=binding[2] if binding else None)
        except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
        self.reply(200 if result["duplicate"] else 202,result)
    def do_DELETE(self):
        parsed=urlsplit(self.path); query=parse_qs(parsed.query,keep_blank_values=True)
        # 退役/清除某设备（硬件ID化后清理旧 hostname 派生的重复设备）：删除其报告、
        # 每设备令牌与认证代次。仅管理令牌。设备若仍在线会继续上报并重新出现。
        if parsed.path=="/v1/devices":
            if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
            did=(query.get("device_id",[""])[0] or "").strip()
            if not re.fullmatch(r"[0-9a-f]{12}",did): return self.reply(400,{"error":"invalid_device_id"})
            try:
                with db_open(self.server.db_path) as db:
                    db.execute("DELETE FROM reports WHERE device_id=?",(did,))
                    db.execute("DELETE FROM device_tokens WHERE device_id=?",(did,))
                    db.execute("DELETE FROM device_auth_state WHERE device_id=?",(did,))
                    db.commit()
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            return self.reply(200,{"ok":True,"purged":did})
        # 吊销某设备全部每设备令牌（批4）：该设备下次上报 401 → Agent 自愈重入网取新令牌。
        if parsed.path!="/v1/device-tokens": return self.reply(404,{"error":"not_found"})
        if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
        did=(query.get("device_id",[""])[0] or "").strip()
        if not re.fullmatch(r"[0-9a-f]{12}",did): return self.reply(400,{"error":"invalid_device_id"})
        try:
            with db_open(self.server.db_path) as db:
                cur=db.execute("DELETE FROM device_tokens WHERE device_id=?",(did,)); db.commit(); n=cur.rowcount
        except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
        return self.reply(200,{"ok":True,"revoked":n})
    def log_message(self,fmt,*args): pass
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--listen",default="127.0.0.1"); ap.add_argument("--port",type=int,default=8788); ap.add_argument("--db",default="aegis.db"); args=ap.parse_args()
    errors=runtime_secret_errors()
    if errors: raise SystemExit("invalid secret configuration: "+",".join(errors))
    server=ThreadingHTTPServer((args.listen,args.port),Handler); server.db_path=args.db; server.rate_limiter=RateLimiter(); server.serve_forever()
if __name__=="__main__": main()
