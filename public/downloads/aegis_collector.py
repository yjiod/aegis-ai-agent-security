#!/usr/bin/env python3
"""Minimal report collector reference. Put behind enterprise TLS/reverse proxy."""
import argparse, hashlib, hmac, json, os, re, sqlite3, stat, threading, time
from collections import deque
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import urllib.request

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
        # 互联网出口 IP：Collector 在收报时记录请求源 IP（nginx 经 X-Real-IP/XFF 透传真实客户端）。
        # 独立列而非写进 body——body 是终端签名的 canonical 正文，掺入服务端观测值会破坏
        # 签名一致性, 也会让 report_hash(去重键)随出口 IP 漂移。
        if "egress_ip" not in columns: db.execute("ALTER TABLE reports ADD COLUMN egress_ip TEXT")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_hash ON reports(report_hash) WHERE report_hash IS NOT NULL")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_device_time ON reports(device_id, received_at DESC)")
        # 30k 规模修复(P0-1)：保留期清理 `DELETE FROM reports WHERE received_at < ?` 若无
        # received_at 前导索引即全表扫描，且在**每次上报**的写事务内执行——表越大写延迟越高，
        # 单写 sqlite 下会雪崩到 busy_timeout→503。加此索引后稳态下每次只删「刚跨过保留窗口」的
        # 极少行(O(log n + matched))，把清理留在写路径但使其廉价，语义完全不变。
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_received ON reports(received_at)"); db.commit()
        db.execute("CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY,event TEXT NOT NULL,occurred_at INTEGER NOT NULL,device_id TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL DEFAULT '')")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(occurred_at DESC)"); db.commit()
        db.execute("CREATE TABLE IF NOT EXISTS device_auth_state(device_id TEXT PRIMARY KEY,last_seen INTEGER NOT NULL,generation INTEGER NOT NULL)"); db.commit()
        # 30k 规模修复(P0-3)：device_state = 「每设备最新报告」物化表，由 store_report 在同一写
        # 事务内增量维护(latest_id/report_count 及最新报告的关键列)。舰队视图(/v1/devices)与首页
        # 汇总(collector_summary)据此定位每设备最新报告(PK join)，**不再**对 reports 全表
        # `GROUP BY device_id`(2160 万行上是秒级全表聚合，且被首页/角标(60s)/告警(5m)反复触发)。
        # ensure_device_state() 用高水位线增量回填历史/直插/迁移缺口，读路径始终 O(设备数)。
        db.execute("CREATE TABLE IF NOT EXISTS device_state(device_id TEXT PRIMARY KEY,latest_id INTEGER NOT NULL,received_at INTEGER NOT NULL,severity TEXT NOT NULL,agent_version TEXT,policy_version TEXT,report_count INTEGER NOT NULL DEFAULT 0)"); db.commit()
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
def _valid_network(n):
    """network = 终端物理网卡采集 {physical_nics:[{name,mac,ips[]}], macs[], local_ips[]}。
    egress_ip(互联网出口)由 Collector 在收报时以独立列记录, 不来自终端、也不进签名正文。
    结构宽松校验: 形态不符只拒该字段所在报告(契约问题), 但绝不因采集为空而拒收。"""
    if not isinstance(n,dict): return False
    for key in ("macs","local_ips"):
        v=n.get(key)
        if v is not None and not (isinstance(v,list) and len(v)<=64 and all(isinstance(x,str) and 1<=len(x)<=64 for x in v)): return False
    pn=n.get("physical_nics")
    if pn is not None:
        if not (isinstance(pn,list) and len(pn)<=64): return False
        for x in pn:
            if not isinstance(x,dict): return False
            if not (isinstance(x.get("name"),str) and 1<=len(x["name"])<=64): return False
            if not (isinstance(x.get("mac"),str) and 1<=len(x["mac"])<=64): return False
            ips=x.get("ips")
            if ips is not None and not (isinstance(ips,list) and len(ips)<=64 and all(isinstance(i,str) and 1<=len(i)<=64 for i in ips)): return False
    return True
def _valid_enforcement(e):
    """enforcement = 终端执行器回执列表 [{asset_type,asset_key,action,target,backup,reason,ok,at}]。"""
    if not isinstance(e,list) or len(e)>64: return False
    for x in e:
        if not isinstance(x,dict): return False
        for k in ("asset_type","asset_key","action"):
            if not (isinstance(x.get(k),str) and 1<=len(x[k])<=64): return False
        for k in ("target","backup","reason"):
            if k in x and not (isinstance(x[k],str) and len(x[k])<=512): return False
        if "ok" in x and not isinstance(x["ok"],bool): return False
    return True
def _valid_self_update(su):
    """self_update = 终端最近一次自更新的非例行结果 {updated,reason[,from,to,latest,at]}。
    仅非例行结果上报（preflight_failed/rolled_back:*/apply_failed:*/updated），例行不上报。"""
    if not isinstance(su,dict): return False
    if not isinstance(su.get("updated"),bool): return False
    if not (isinstance(su.get("reason"),str) and 1<=len(su["reason"])<=64): return False
    for k in ("from","to","latest"):
        if k in su and not (isinstance(su[k],str) and len(su[k])<=32): return False
    if "at" in su and not (isinstance(su["at"],int) and not isinstance(su["at"],bool)): return False
    return True
def valid_report(d,now=None):
    """Validate the published v1 contract without a third-party JSON Schema runtime."""
    if not isinstance(d,dict): return False
    required={"schema","agent_version","policy_version","device_id","scanned_at","summary","findings"}
    allowed=required|{"scan_root","inventory","hostname","os_user","owner","os","serial","enterprise_baseline_version","network","enforcement","run_mode","capabilities","self_update"}
    if not required.issubset(d) or not set(d).issubset(allowed): return False
    if d.get("schema")!="aegis.report/v1": return False
    if "owner" in d and not (isinstance(d["owner"],str) and len(d["owner"])<=64): return False
    if "run_mode" in d and not (isinstance(d["run_mode"],str) and 1<=len(d["run_mode"])<=16): return False
    cap=d.get("capabilities")
    if cap is not None and not (isinstance(cap,dict) and all(isinstance(cap.get(k),bool) for k in cap if k in ("pf","es"))): return False
    if "network" in d and not _valid_network(d["network"]): return False
    if "enforcement" in d and not _valid_enforcement(d["enforcement"]): return False
    if "self_update" in d and not _valid_self_update(d["self_update"]): return False
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
def audit_prune_interval(value=None):
    """30k 规模修复(P0-1)：审计封顶子查询的最小执行间隔(秒)。默认 3600。"""
    raw=os.getenv("AEGIS_AUDIT_PRUNE_INTERVAL_SECONDS","3600") if value is None else value
    try: return min(max(int(raw),1),86400)
    except (TypeError,ValueError): return 3600
# P1-1：/v1/findings/aggregate 单页发现条数硬上限（按设备原子纳入，超限则停在上一台并给游标）。
# 与 limit(每页设备数≤1000) 双重设防，杜绝单页巨响应打爆控制台 worker 内存。
MAX_AGGREGATE_FINDINGS=20000
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
def store_report(db_path,body,report,now=None,days=None,credential_generation=None,egress_ip=None):
    now=int(time.time()) if now is None else now; days=retention_days(days)
    severity="critical" if report["summary"].get("critical",0) else "high" if report["summary"].get("high",0) else "normal"
    canonical=json.dumps(report,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode(); digest=hashlib.sha256(canonical).hexdigest(); receipt_id=hashlib.sha256(body).hexdigest()[:20]
    with db_open(db_path) as db:
        db.execute("DELETE FROM reports WHERE received_at < ?",(now-days*86400,))
        cursor=db.execute("INSERT OR IGNORE INTO reports(report_hash,device_id,received_at,severity,body,agent_version,policy_version,egress_ip) VALUES(?,?,?,?,?,?,?,?)",(digest,report["device_id"],now,severity,canonical.decode(),report.get("agent_version"),report.get("policy_version"),egress_ip)); duplicate=cursor.rowcount==0
        if not duplicate:
            # P0-3：同事务增量维护 device_state 物化表(每设备最新报告)。report_count 用设备级
            # 索引 COUNT(idx_reports_device_time)在保留清理之后重算，故为「本次写入时刻的精确值」；
            # 只扫该设备自己的行(稳态 ~每天24×保留天)，绝非全表 GROUP BY。
            cnt=db.execute("SELECT COUNT(*) FROM reports WHERE device_id=?",(report["device_id"],)).fetchone()[0]
            db.execute("INSERT INTO device_state(device_id,latest_id,received_at,severity,agent_version,policy_version,report_count) VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET latest_id=excluded.latest_id,received_at=excluded.received_at,severity=excluded.severity,agent_version=excluded.agent_version,policy_version=excluded.policy_version,report_count=excluded.report_count",(report["device_id"],cursor.lastrowid,now,severity,report.get("agent_version"),report.get("policy_version"),cnt))
        if credential_generation is not None: db.execute("INSERT INTO device_auth_state(device_id,last_seen,generation) VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET last_seen=excluded.last_seen,generation=excluded.generation",(report["device_id"],now,int(credential_generation)))
        generation="legacy" if credential_generation is None else "g"+str(int(credential_generation)); db.execute("INSERT INTO audit_events(event,occurred_at,device_id,detail) VALUES(?,?,?,?)",("report_duplicate" if duplicate else "report_accepted",now,report["device_id"],digest[:20]+":"+severity+":"+generation)); maybe_prune_audit(db,now); db.commit()
    return {"accepted":True,"duplicate":duplicate,"report_id":receipt_id,"severity":severity}
def prune_audit(db,now=None,days=None,max_events=None):
    now=int(time.time()) if now is None else int(now); days=audit_retention_days(days); max_events=audit_max_events(max_events)
    db.execute("DELETE FROM audit_events WHERE occurred_at < ?",(now-days*86400,))
    db.execute("DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)",(max_events,))
# 30k 规模修复(P0-1)：审计封顶 DELETE 含 `id NOT IN (SELECT id ... ORDER BY id DESC LIMIT 100000)`
# 子查询，成本随审计表增大而上升；此前每次 store_report / audit_event 都跑一遍 → 8.3 上报/秒时
# 每秒数十万行读。改为按单调时钟限频(默认每小时一次)，把封顶维护移出写热路径。审计仍持续 INSERT，
# 只是封顶/保留清理不再每写触发；显式 prune_audit()（备份/测试/维护路径）语义不变。
_AUDIT_PRUNE_LOCK=threading.Lock(); _LAST_AUDIT_PRUNE=[0.0]
def maybe_prune_audit(db,now=None,interval=None,force=False):
    """限频执行 prune_audit；返回是否真正执行了清理。force=True 无条件执行并重置计时。"""
    mono=time.monotonic(); iv=audit_prune_interval(interval)
    with _AUDIT_PRUNE_LOCK:
        if not force and (mono-_LAST_AUDIT_PRUNE[0])<iv: return False
        _LAST_AUDIT_PRUNE[0]=mono
    prune_audit(db,now); return True
def audit_event(db_path,event,device_id="",detail="",now=None):
    now=int(time.time()) if now is None else int(now)
    if not event or len(event)>64 or len(device_id)>128 or len(detail)>256: raise ValueError("invalid_audit_event")
    with db_open(db_path) as db:
        db.execute("INSERT INTO audit_events(event,occurred_at,device_id,detail) VALUES(?,?,?,?)",(event,now,device_id,detail)); maybe_prune_audit(db,now); db.commit()
def recent_audit(db_path,limit=200):
    limit=min(max(int(limit),1),500)
    with db_open(db_path) as db: rows=db.execute("SELECT event,occurred_at,device_id,detail FROM audit_events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [{"event":event,"occurred_at":occurred,"device_id":device,"detail":detail} for event,occurred,device,detail in rows]
def ensure_device_state(db):
    """增量回填 device_state 物化表（高水位线契约，幂等可重入）。

    水位线 wm = 已物化进 device_state 的最大 report id（= MAX(latest_id)）。仅当 reports 出现
    比 wm 更新的行时才回填这批增量：正常写路径下 store_report 已在同一事务维护 device_state，
    故此处退化为两次单值 MAX 查找的廉价 no-op。直插 DB（测试）、旧库首次读、迁移缺口则触发
    一次性增量回填，使 /v1/devices 与 collector_summary 无需再对 reports 全表 GROUP BY。
    report_count 以设备级索引 COUNT 重算，语义与旧 `COUNT(*) ... GROUP BY device_id` 一致。"""
    wm=db.execute("SELECT COALESCE(MAX(latest_id),0) FROM device_state").fetchone()[0]
    rmax=db.execute("SELECT COALESCE(MAX(id),0) FROM reports").fetchone()[0]
    if rmax<=wm: return 0
    cur=db.execute("INSERT INTO device_state(device_id,latest_id,received_at,severity,agent_version,policy_version,report_count) SELECT r.device_id,r.id,r.received_at,r.severity,r.agent_version,r.policy_version,(SELECT COUNT(*) FROM reports x WHERE x.device_id=r.device_id) FROM reports r JOIN (SELECT device_id,MAX(id) AS mid FROM reports WHERE id>? GROUP BY device_id) d ON d.device_id=r.device_id AND d.mid=r.id ON CONFLICT(device_id) DO UPDATE SET latest_id=excluded.latest_id,received_at=excluded.received_at,severity=excluded.severity,agent_version=excluded.agent_version,policy_version=excluded.policy_version,report_count=excluded.report_count",(wm,))
    db.commit(); return max(int(cur.rowcount or 0),0)
def collector_summary(db_path,now=None,active_window=86400,required_agent=None,required_policy=None):
    """Return fleet posture from only the newest accepted report per device."""
    now=int(time.time()) if now is None else int(now); active_window=min(max(int(active_window),60),30*86400)
    with db_open(db_path) as db:
        ensure_device_state(db)
        # P0-3：从 device_state 定位每设备最新报告(PK join)，取代对 reports 全表 `MAX(id) GROUP BY
        # device_id`；INNER JOIN reports 天然排除最新报告已被保留清理的悬挂设备(与旧语义一致)。
        rows=db.execute("SELECT r.received_at,r.severity,r.agent_version,r.policy_version,a.generation FROM device_state ds JOIN reports r ON r.id=ds.latest_id LEFT JOIN device_auth_state a ON a.device_id=ds.device_id").fetchall()
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
        # 0) 仅令牌（无设备头）：token 哈希反查设备（令牌本身即密钥，持有即设备），
        #    供 /v1/policy 等自助端点一条命令调用（不便先算 device_id 的场景）。
        if supplied and not device_id:
            th=hashlib.sha256(supplied.encode()).hexdigest()
            try:
                with db_open(self.server.db_path) as db:
                    row=db.execute("SELECT device_id,signing_secret FROM device_tokens WHERE token_hash=?",(th,)).fetchone()
                if row: return (True,(row[0],[row[1]],0))
            except sqlite3.Error: pass
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
        if parsed.path=="/v1/policy":
            # 设备自助拉取当前签名策略(一条命令同步策略+重启服务用)。设备令牌鉴权,
            # 再由 Collector 以自身令牌向控制台 /api/policy/artifact 取件, 原样回传(含签名)。
            authenticated,binding=self.report_authentication()
            if not authenticated: return self.reply(401,{"error":"unauthorized"})
            tok=os.environ.get("AEGIS_COLLECTOR_TOKEN","")
            if not tok: return self.reply(503,{"error":"collector_token_missing"})
            try:
                req=urllib.request.Request("http://127.0.0.1:8787/api/policy/artifact",headers={"Authorization":"Bearer "+tok})
                with urllib.request.urlopen(req,timeout=20) as r:
                    body=r.read(); sha=r.headers.get("X-Aegis-Policy-Sha256",""); ver=r.headers.get("X-Aegis-Policy-Version","")
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store")
                if sha: self.send_header("X-Aegis-Policy-Sha256",sha)
                if ver: self.send_header("X-Aegis-Policy-Version",ver)
                self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
            except Exception: return self.reply(502,{"error":"policy_fetch_failed"})
        if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
        if parsed.path=="/v1/devices":
            query=parse_qs(parsed.query,keep_blank_values=True)
            if set(query)-{"limit","cursor"} or any(len(values)!=1 for values in query.values()): return self.reply(400,{"error":"invalid_query"})
            try: limit=int(query.get("limit",["500"])[0])
            except ValueError: return self.reply(400,{"error":"invalid_limit"})
            if not 1<=limit<=10000: return self.reply(400,{"error":"invalid_limit"})
            # P1-4：keyset 游标（= 上一页最后一个 device_id）。去 limit 截断——消费端携 cursor 循环
            # 翻页即可遍历**全量**舰队（30k 不再只见前 1 万台）。cursor 即 device_id([0-9a-f]{12})，
            # URL 安全、作绑定参数无注入面；空/缺省=从头。非法格式拒绝（不静默吞）。
            cursor=(query.get("cursor",[""])[0] or "").strip()
            if cursor and not re.fullmatch(r"[0-9a-f]{12}",cursor): return self.reply(400,{"error":"invalid_cursor"})
            try:
                generated_at=int(time.time())
                with db_open(self.server.db_path) as db:
                    ensure_device_state(db)
                    # P0-3：fleet 从 device_state 物化表取(每设备最新报告 id + report_count)，取代对
                    # reports 全表 `MAX(id)/COUNT(*) GROUP BY device_id`。保留 WITH fleet AS / COALESCE /
                    # device_auth_state 身份边界与响应列形状完全不变，仅把全表聚合换成 O(设备数) 物化读。
                    # P1-4：CTE 内 `WHERE device_id > ?` 走 device_state PK 区间扫实现 keyset 翻页；
                    # 悬挂行(最新报告被保留清理)由 INNER JOIN reports 天然跳过，游标按实际返回行推进，不漏不重。
                    rows=db.execute("WITH fleet AS (SELECT device_id,latest_id AS id,report_count FROM device_state WHERE device_id > ?) SELECT r.device_id,COALESCE(a.last_seen,r.received_at),fleet.report_count,a.generation,r.body,r.egress_ip FROM fleet JOIN reports r ON r.id=fleet.id LEFT JOIN device_auth_state a ON a.device_id=r.device_id ORDER BY r.device_id LIMIT ?",(cursor,limit+1)).fetchall()
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
                        net=body.get("network")
                        if isinstance(net,dict): dev["network"]=net
                        enf=body.get("enforcement")
                        if isinstance(enf,list): dev["enforcement"]=enf[:10]
                        # 能力诚实化: 运行态(system/user) + 真实封禁能力(pf/es), 控制台按设备标注。
                        if isinstance(body.get("run_mode"),str): dev["run_mode"]=body["run_mode"][:16]
                        cap=body.get("capabilities")
                        if isinstance(cap,dict): dev["capabilities"]={k:bool(cap.get(k)) for k in ("pf","es") if k in cap}
                        # 旧 Windows 客户端(0.36.1 前)不上报 run_mode: Windows agent 恒以 Windows 服务
                        # (LocalSystem) 运行, 据此推断并标注 inferred, 不假装终端自报。
                        if "run_mode" not in dev and isinstance(dev.get("os"),str) and dev["os"]=="windows":
                            dev["run_mode"]="system"; dev["capabilities"]={"pf":True,"es":False}; dev["run_mode_inferred"]=True
                        if isinstance(body.get("scan_root"),str): dev["scan_root"]=body["scan_root"][:64]
                        # 自更非例行结果（preflight_failed/rolled_back/apply_failed/updated）：
                        # 形状已由 valid_report._valid_self_update 校验，原样留存供 /v1/devices 暴露。
                        su=body.get("self_update")
                        if isinstance(su,dict): dev["self_update"]=su
                        inv=body.get("inventory")
                        if isinstance(inv,list):
                            dev["tools"]=sorted({x.get("name") for x in inv if isinstance(x,dict) and x.get("type")=="ai_agent" and isinstance(x.get("name"),str)})[:20]
                            # 封禁爆炸半径预览所需: 该设备已发现的 skill 名与 mcp 资产键。
                            dev["skills"]=sorted({x.get("name") for x in inv if isinstance(x,dict) and x.get("type")=="skill" and isinstance(x.get("name"),str)})[:200]
                            dev["mcp_assets"]=sorted({f.get("asset_key") for f in body.get("findings",[]) if isinstance(f,dict) and f.get("asset_type")=="mcp" and isinstance(f.get("asset_key"),str)})[:200]
                            dev["latest_severity"]={"critical":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="critical"),"high":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="high"),"medium":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="medium"),"low":sum(1 for f in body.get("findings",[]) if isinstance(f,dict) and f.get("severity")=="low")}
                except (ValueError,TypeError): pass
                eg=r[5]
                if isinstance(eg,str) and eg: dev.setdefault("network",{})["egress_ip"]=eg
                devices_out.append(dev)
            # P1-4：未 complete 时回传 keyset 游标（本页最后一个 device_id），供消费端翻页遍历全量。
            page={"generated_at":generated_at,"complete":complete,"devices":devices_out}
            if not complete and devices_out: page["next_cursor"]=devices_out[-1]["device_id"]
            return self.reply(200,page)
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
        if parsed.path=="/v1/findings/aggregate":
            # P1-1：跨设备发现聚合端点（keyset 游标翻页）。取代控制台对每台设备各发一个
            # /v1/findings 的 N+1 扇出（30k 下单页最多 1 万并发打垮 ThreadingHTTPServer + 控制台
            # worker OOM）。服务端走 device_state keyset 翻页 → 一次 IN 查询取本页各设备最新 body →
            # 解析 → 按 severity/since 过滤 → 扁平化返回。category 过滤与加白抑制仍留控制台
            # （避免与前端 categorize 规则双写发散）。设备原子纳入 + 单页发现硬上限双重设防巨响应。
            query=parse_qs(parsed.query,keep_blank_values=True)
            if set(query)-{"severity","since","cursor","limit"} or any(len(v)!=1 for v in query.values()): return self.reply(400,{"error":"invalid_query"})
            severity=(query.get("severity",["all"])[0] or "all").strip().lower()
            if severity not in {"all","critical","high","medium","low"}: return self.reply(400,{"error":"invalid_severity"})
            try: since=int(query.get("since",["0"])[0] or 0)
            except ValueError: return self.reply(400,{"error":"invalid_since"})
            if since<0: return self.reply(400,{"error":"invalid_since"})
            cursor=(query.get("cursor",[""])[0] or "").strip()
            if cursor and not re.fullmatch(r"[0-9a-f]{12}",cursor): return self.reply(400,{"error":"invalid_cursor"})
            try: limit=int(query.get("limit",["500"])[0])
            except ValueError: return self.reply(400,{"error":"invalid_limit"})
            if not 1<=limit<=1000: return self.reply(400,{"error":"invalid_limit"})
            try:
                generated_at=int(time.time())
                with db_open(self.server.db_path) as db:
                    ensure_device_state(db)
                    fetched=db.execute("SELECT device_id,latest_id FROM device_state WHERE device_id > ? ORDER BY device_id LIMIT ?",(cursor,limit+1)).fetchall()
                    has_more=len(fetched)>limit; page=fetched[:limit]
                    ids=[lid for _,lid in page]
                    bodies={row[0]:row[1] for row in db.execute("SELECT id,body FROM reports WHERE id IN ("+(",".join("?"*len(ids)) if ids else "NULL")+")",ids)} if ids else {}
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            out=[]; counts={"total":0,"critical":0,"high":0,"medium":0,"low":0}; devices_with=0; scanned=0; last=cursor; truncated=False
            for did,lid in page:
                raw=bodies.get(lid)
                if raw is None: last=did; continue          # 悬挂(最新报告被保留清理)→跳过但游标越过
                try: body=json.loads(raw) if raw else {}
                except (ValueError,TypeError): body={}
                if not isinstance(body,dict): body={}
                sat=body.get("scanned_at"); sat=sat if isinstance(sat,int) and not isinstance(sat,bool) else None
                scanned+=1
                if since and (sat is None or sat<since): last=did; continue   # since 过滤→跳过但游标越过
                fs=body.get("findings"); fs=fs if isinstance(fs,list) else []
                matched=[f for f in fs if isinstance(f,dict) and (severity=="all" or (f.get("severity") if isinstance(f.get("severity"),str) else "low")==severity)]
                # 设备原子纳入：若纳入本设备会超单页硬上限则停在**上一台**（不推进 last），
                # 下一页从本设备重新处理，绝不丢发现。out 为空时不截断（单设备受 agent schema 上限约束）。
                if out and len(out)+len(matched)>MAX_AGGREGATE_FINDINGS: truncated=True; break
                for f in matched:
                    sev=f.get("severity") if isinstance(f.get("severity"),str) else "low"
                    out.append({"device_id":did,"scanned_at":sat,"finding":f}); counts["total"]+=1
                    if sev in counts: counts[sev]+=1
                if matched: devices_with+=1
                last=did
            complete=(not has_more) and (not truncated)
            page_out={"generated_at":generated_at,"complete":complete,"devices_scanned":scanned,"devices_with_findings":devices_with,"counts":counts,"findings":out}
            if not complete and last and last!=cursor: page_out["next_cursor"]=last
            audit_event(self.server.db_path,"findings_aggregate_read",detail=str(scanned)+":"+str(len(out))+":"+("complete" if complete else "partial"))
            return self.reply(200,page_out)
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
        if not authenticated:
            # 401 诊断(真机 401 反复): 记录令牌匹配情况, 区分"令牌错/设备错/令牌属于别的设备"。
            did_h=self.headers.get("X-Aegis-Device-ID","") or ""
            sup=self.headers.get("Authorization","").removeprefix("Bearer ")
            th=hashlib.sha256(sup.encode()).hexdigest() if sup else ""
            info="no_token"
            try:
                with db_open(self.server.db_path) as db:
                    exact=db.execute("SELECT 1 FROM device_tokens WHERE device_id=? AND token_hash=?",(did_h,th)).fetchone()
                    n=db.execute("SELECT COUNT(*) FROM device_tokens WHERE device_id=?",(did_h,)).fetchone()[0]
                    anydev=db.execute("SELECT device_id FROM device_tokens WHERE token_hash=?",(th,)).fetchone()
                info="exact=%s tokens_for_device=%d token_belongs_to=%s" % (bool(exact), n, (anydev[0] if anydev else ""))
            except sqlite3.Error: info="db_error"
            audit_event(self.server.db_path,"report_auth_failed",device_id=did_h,detail=info[:200])
            return self.reply(401,{"error":"unauthorized"})
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
        # 互联网出口 IP：Collector 观测值（NAT 后公网视角）。nginx 透传真实客户端
        # （X-Real-IP 优先，其次 X-Forwarded-For 首跳），无代理直连时回落 peer 地址。
        # 存独立列，不写进签名正文（见 db_open 注释）。
        egress=(self.headers.get("X-Real-IP") or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or self.client_address[0] or "")[:64] or None
        try: result=store_report(self.server.db_path,body,report,credential_generation=binding[2] if binding else None,egress_ip=egress)
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
    # P0-3：启动时一次性增量回填 device_state（迁移旧库 / 补齐直插缺口）。全量回填仅在旧库首启
    # 发生一次；此后由 store_report 增量维护，读路径的 ensure_device_state 退化为廉价 no-op。
    try:
        with db_open(args.db) as _db: ensure_device_state(_db)
    except sqlite3.Error as _exc: print(f"device_state backfill skipped: {_exc}",file=sys.stderr)
    server=ThreadingHTTPServer((args.listen,args.port),Handler); server.db_path=args.db; server.rate_limiter=RateLimiter(); server.serve_forever()
if __name__=="__main__": main()
