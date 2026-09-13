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
        db.execute("CREATE TABLE IF NOT EXISTS remediation_receipts(id INTEGER PRIMARY KEY,recommendation_id TEXT NOT NULL,state TEXT NOT NULL,external_event_id TEXT NOT NULL,actor_ref TEXT NOT NULL,occurred_at INTEGER NOT NULL,idempotency_key TEXT NOT NULL UNIQUE)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_remediation_receipt_recommendation ON remediation_receipts(recommendation_id,id DESC)"); db.commit()
        yield db
    finally: db.close()
def valid_report(d,now=None):
    """Validate the published v1 contract without a third-party JSON Schema runtime."""
    if not isinstance(d,dict): return False
    required={"schema","agent_version","policy_version","device_id","scanned_at","summary","findings"}
    allowed=required|{"scan_root","inventory"}
    if not required.issubset(d) or not set(d).issubset(allowed): return False
    if d.get("schema")!="sentinel.report/v1": return False
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
        if not set(finding).issubset({"kind","severity","path","message","evidence"}): return False
        if finding.get("severity") not in counts: return False
        if any(not isinstance(finding.get(k),str) for k in ("kind","path","message")): return False
        if not 1<=len(finding["kind"])<=128 or len(finding["path"])>2048 or not 1<=len(finding["message"])<=2048: return False
        if "evidence" in finding and (not isinstance(finding["evidence"],str) or len(finding["evidence"])>512): return False
        counts[finding["severity"]]+=1
    return counts==summary
def signature_index(headers,body,secrets,now=None,max_skew=300):
    if not secrets: return -1 if allow_unsigned_reports() else None
    def header(name): return headers.get(name) or headers.get(name.lower())
    timestamp=header("X-Sentinel-Timestamp"); supplied=header("X-Sentinel-Signature") or ""
    try: request_time=int(timestamp)
    except (TypeError,ValueError): return None
    now=int(time.time()) if now is None else now
    if abs(now-request_time)>max_skew: return None
    device_id=header("X-Sentinel-Device-ID") or ""; prefix=timestamp.encode()+b"."+(device_id.encode()+b"." if device_id else b"")
    matches=[]
    for candidate in secrets:
        expected="sha256="+hmac.new(candidate.encode(),prefix+body,hashlib.sha256).hexdigest(); matches.append(hmac.compare_digest(expected,supplied))
    return next((index for index,matched in enumerate(matches) if matched),None)
def valid_signature(headers,body,now=None,secret=None,max_skew=300):
    secrets=secret_values("SENTINEL_REPORT_SIGNING_SECRET","SENTINEL_REPORT_SIGNING_SECRETS") if secret is None else (secret if isinstance(secret,list) else ([secret] if secret else []))
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
def private_secret_file(path):
    if not path: return []
    source=Path(path)
    if source.is_symlink(): raise ValueError("secret_file_symlink")
    info=source.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o600,0o640} or info.st_uid not in {0,os.geteuid()} or info.st_size>65536: raise ValueError("secret_file_permissions")
    value=json.loads(source.read_text(encoding="utf-8")); keys=value.get("keys") if isinstance(value,dict) else None
    if set(value)!={"schema","keys"} or value.get("schema")!="sentinel.policy-signing-keys/v1" or not isinstance(keys,list) or not 1<=len(keys)<=5 or any(not isinstance(key,str) or not 32<=len(key)<=4096 for key in keys) or len(keys)!=len(set(keys)): raise ValueError("secret_file_contract")
    return keys
def policy_key_id(key): return hashlib.sha256(key.encode()).hexdigest()[:16]
def policy_signing_keys(path=None):
    path=os.getenv("SENTINEL_POLICY_SIGNING_KEYS_FILE","") if path is None else path
    return private_secret_file(path)
def allow_unsigned_reports(value=None):
    raw=os.getenv("SENTINEL_ALLOW_UNSIGNED_REPORTS","") if value is None else value
    return str(raw).strip().lower() in {"1","true","yes"}
def device_credentials(path=None):
    path=os.getenv("SENTINEL_DEVICE_CREDENTIALS_FILE","") if path is None else path
    if not path: return {}
    source=Path(path)
    if source.is_symlink(): raise ValueError("device_credentials_symlink")
    info=source.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o600,0o640} or info.st_uid not in {0,os.geteuid()}: raise ValueError("device_credentials_permissions")
    value=json.loads(source.read_text(encoding="utf-8")); devices=value.get("devices") if isinstance(value,dict) else None
    if set(value)!={"schema","devices"} or value.get("schema")!="sentinel.device-credentials/v1" or not isinstance(devices,dict) or not 1<=len(devices)<=10000: raise ValueError("device_credentials_contract")
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
    errors=[]
    tokens=secret_values("SENTINEL_COLLECTOR_TOKEN","SENTINEL_COLLECTOR_TOKENS",env)
    signing=secret_values("SENTINEL_REPORT_SIGNING_SECRET","SENTINEL_REPORT_SIGNING_SECRETS",env)
    callback=secret_values("SENTINEL_APPROVAL_CALLBACK_TOKEN","SENTINEL_APPROVAL_CALLBACK_TOKENS",env)
    policy_keys=[]
    try: policy_keys=private_secret_file(env.get("SENTINEL_POLICY_SIGNING_KEYS_FILE",""))
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): errors.append("policy_signing_keys_missing_or_invalid")
    if not tokens: errors.append("collector_token_missing_or_invalid")
    if any(len(value)<32 for value in tokens): errors.append("collector_token_too_short")
    if len(tokens)!=len(set(tokens)): errors.append("collector_token_duplicate")
    unsigned=str(env.get("SENTINEL_ALLOW_UNSIGNED_REPORTS","")).strip().lower() in {"1","true","yes"}
    credentials_path=env.get("SENTINEL_DEVICE_CREDENTIALS_FILE","")
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
    if any(len(value)<32 for value in callback): errors.append("approval_callback_token_too_short")
    if len(callback)!=len(set(callback)): errors.append("approval_callback_token_duplicate")
    if set(callback)&(set(tokens)|set(signing)): errors.append("approval_callback_token_reused")
    if not policy_keys and "policy_signing_keys_missing_or_invalid" not in errors: errors.append("policy_signing_keys_missing_or_invalid")
    if set(policy_keys)&(set(tokens)|set(signing)|set(callback)): errors.append("policy_signing_key_reused")
    return errors
def retention_days(value=None):
    raw=os.getenv("SENTINEL_RETENTION_DAYS","30") if value is None else value
    try: return min(max(int(raw),1),3650)
    except (TypeError,ValueError): return 30
def requests_per_minute(value=None):
    raw=os.getenv("SENTINEL_REQUESTS_PER_MINUTE","120") if value is None else value
    try: return min(max(int(raw),1),10000)
    except (TypeError,ValueError): return 120
def audit_retention_days(value=None):
    raw=os.getenv("SENTINEL_AUDIT_RETENTION_DAYS","90") if value is None else value
    try: return min(max(int(raw),1),3650)
    except (TypeError,ValueError): return 90
def audit_max_events(value=None):
    raw=os.getenv("SENTINEL_AUDIT_MAX_EVENTS","100000") if value is None else value
    try: return min(max(int(raw),1000),1000000)
    except (TypeError,ValueError): return 100000
def required_version(name,default,env=None):
    env=os.environ if env is None else env; value=env.get(name,default)
    return value if isinstance(value,str) and 1<=len(value)<=64 else default
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
def service_health_status(inventory):
    """Classify only the minimized health attestation; malformed or duplicate evidence fails closed."""
    items=[item.get("status") for item in inventory if isinstance(item,dict) and item.get("type")=="service_health"] if isinstance(inventory,list) else []
    return items[0] if len(items)==1 and items[0] in {"healthy","degraded","invalid"} else "missing" if not items else "invalid"
def remediation_recommendation(row,required_agent="0.47.0",required_policy="5.1.0"):
    device_id,observed_at,severity,agent,policy,body=row
    try: inventory=json.loads(body).get("inventory",[])
    except (AttributeError,TypeError,ValueError,json.JSONDecodeError): inventory=[]
    health=service_health_status(inventory)
    if severity=="critical": reason,action,level="risk_critical","containment_pending_approval","critical"
    elif severity=="high": reason,action,level="risk_high","access_review_pending","high"
    elif health=="invalid": reason,action,level="service_health_invalid","verify_integrity","high"
    elif health=="degraded": reason,action,level="service_health_degraded","repair_service","high"
    elif health=="missing": reason,action,level="service_health_missing","upgrade_client","high"
    elif not agent or not policy or agent!=required_agent or policy!=required_policy: reason,action,level="version_drift","upgrade_client","high"
    else: return None
    seed=f"{device_id}\0{observed_at}\0{reason}\0{action}".encode(); correlation=hashlib.blake2s(seed,digest_size=20).hexdigest()
    return {"recommendation_id":correlation,"device_id":device_id,"reason":reason,"recommended_action":action,"approval_state":"external_approval_required","severity":level,"observed_at":observed_at,"correlation_id":correlation}
def collector_recommendations(db_path,limit=200,required_agent=None,required_policy=None):
    limit=min(max(int(limit),1),200); required_agent=required_agent or required_version("SENTINEL_REQUIRED_AGENT_VERSION","0.47.0"); required_policy=required_policy or required_version("SENTINEL_REQUIRED_POLICY_VERSION","5.1.0")
    with db_open(db_path) as db:
        rows=db.execute("SELECT r.device_id,r.received_at,r.severity,r.agent_version,r.policy_version,r.body FROM reports r JOIN (SELECT device_id,MAX(id) AS id FROM reports GROUP BY device_id) latest ON latest.id=r.id ORDER BY r.device_id").fetchall()
        states={row[0]:(row[1],row[2]) for row in db.execute("SELECT receipt.recommendation_id,receipt.state,receipt.occurred_at FROM remediation_receipts receipt JOIN (SELECT recommendation_id,MAX(id) AS id FROM remediation_receipts GROUP BY recommendation_id) latest ON latest.id=receipt.id")}
    items=[]
    for row in rows:
        item=remediation_recommendation(row,required_agent,required_policy)
        if item:
            state,updated=states.get(item["recommendation_id"],("pending",0)); item.update({"workflow_state":state,"receipt_updated_at":updated}); items.append(item)
    return {"generated_at":int(time.time()),"complete":len(items)<=limit,"recommendations":items[:limit]}
def valid_remediation_receipt(value,now=None):
    if not isinstance(value,dict) or set(value)!={"schema","recommendation_id","state","external_event_id","actor_id","occurred_at"}: return False
    if value.get("schema")!="sentinel.remediation-receipt/v1" or not isinstance(value.get("recommendation_id"),str) or not re.fullmatch(r"[0-9a-f]{40}",value["recommendation_id"]): return False
    if value.get("state") not in {"approved","rejected","executing","succeeded","failed"}: return False
    if not isinstance(value.get("external_event_id"),str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",value["external_event_id"]): return False
    if not isinstance(value.get("actor_id"),str) or not 1<=len(value["actor_id"])<=128: return False
    if not isinstance(value.get("occurred_at"),int) or isinstance(value["occurred_at"],bool): return False
    now=int(time.time()) if now is None else int(now); return abs(now-value["occurred_at"])<=300
def store_remediation_receipt(db_path,value,idempotency_key,now=None):
    if not re.fullmatch(r"[0-9a-f]{64}",idempotency_key or ""): raise ValueError("invalid_idempotency_key")
    now=int(time.time()) if now is None else int(now)
    with db_open(db_path) as db:
        duplicate=db.execute("SELECT recommendation_id,state FROM remediation_receipts WHERE idempotency_key=?",(idempotency_key,)).fetchone()
        if duplicate:
            if duplicate!=(value["recommendation_id"],value["state"]): raise ValueError("idempotency_conflict")
            return {"accepted":True,"duplicate":True,"recommendation_id":value["recommendation_id"],"state":value["state"]}
        recommendations=collector_recommendations(db_path,limit=200)["recommendations"]
        if value["recommendation_id"] not in {item["recommendation_id"] for item in recommendations}: raise ValueError("unknown_or_stale_recommendation")
        latest=db.execute("SELECT state FROM remediation_receipts WHERE recommendation_id=? ORDER BY id DESC LIMIT 1",(value["recommendation_id"],)).fetchone(); previous=latest[0] if latest else "pending"
        allowed={"pending":{"approved","rejected"},"approved":{"executing"},"executing":{"succeeded","failed"},"rejected":set(),"succeeded":set(),"failed":set()}
        if value["state"] not in allowed[previous]: raise ValueError("invalid_state_transition")
        actor_ref=hashlib.blake2s(value["actor_id"].encode(),digest_size=16).hexdigest()
        db.execute("INSERT INTO remediation_receipts(recommendation_id,state,external_event_id,actor_ref,occurred_at,idempotency_key) VALUES(?,?,?,?,?,?)",(value["recommendation_id"],value["state"],value["external_event_id"],actor_ref,value["occurred_at"],idempotency_key)); db.commit()
    audit_event(db_path,"remediation_receipt",device_id="",detail=value["recommendation_id"][:12]+":"+value["state"],now=now)
    return {"accepted":True,"duplicate":False,"recommendation_id":value["recommendation_id"],"state":value["state"]}
def collector_summary(db_path,now=None,active_window=86400,required_agent=None,required_policy=None):
    """Return fleet posture from only the newest accepted report per device."""
    now=int(time.time()) if now is None else int(now); active_window=min(max(int(active_window),60),30*86400)
    with db_open(db_path) as db:
        rows=db.execute("SELECT r.received_at,r.severity,r.agent_version,r.policy_version,a.generation,r.body FROM reports r JOIN (SELECT device_id,MAX(id) AS id FROM reports GROUP BY device_id) latest ON latest.id=r.id LEFT JOIN device_auth_state a ON a.device_id=r.device_id").fetchall()
    by_severity={"critical":0,"high":0,"normal":0}
    versions={"current":0,"agent_mismatch":0,"policy_mismatch":0,"both_mismatch":0,"unknown":0}; required_agent=required_agent or required_version("SENTINEL_REQUIRED_AGENT_VERSION","0.47.0"); required_policy=required_policy or required_version("SENTINEL_REQUIRED_POLICY_VERSION","5.1.0")
    credential_posture={"current":0,"previous":0,"legacy":0}
    supported_agents=("cursor","claude_code","codex","windsurf","gemini_cli","github_copilot_cli","workbuddy","qwen_enterprise","tongyi_lingma","codebuddy")
    agent_coverage={name:{"total":0,"active":0} for name in supported_agents}
    baseline_names=("claude_code","codex","gemini_cli","github_copilot_cli")
    baseline_coverage={name:{"total":0,"managed":0} for name in baseline_names}
    service_health_posture={"healthy":0,"degraded":0,"invalid":0,"missing":0}
    try: trusted_key_ids=[policy_key_id(key) for key in policy_signing_keys()]
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): trusted_key_ids=[]
    current_key_id=trusted_key_ids[0] if trusted_key_ids else "unavailable"; policy_trust_posture={"current":0,"overlap":0,"legacy":0,"unrecognized":0}
    for received,severity,agent,policy,generation,body in rows:
        by_severity[severity if severity in by_severity else "normal"]+=1
        if not agent or not policy: versions["unknown"]+=1
        elif agent!=required_agent and policy!=required_policy: versions["both_mismatch"]+=1
        elif agent!=required_agent: versions["agent_mismatch"]+=1
        elif policy!=required_policy: versions["policy_mismatch"]+=1
        else: versions["current"]+=1
        credential_posture["legacy" if generation is None else "current" if generation==0 else "previous"]+=1
        try: inventory=json.loads(body).get("inventory",[])
        except (AttributeError,TypeError,ValueError,json.JSONDecodeError): inventory=[]
        present={item.get("name") for item in inventory if isinstance(item,dict) and item.get("type")=="ai_agent" and isinstance(item.get("name"),str) and item.get("name") in agent_coverage}
        for name in present:
            agent_coverage[name]["total"]+=1
            if received>=now-active_window: agent_coverage[name]["active"]+=1
        baseline_items={item.get("name"):item.get("status") for item in inventory if isinstance(item,dict) and item.get("type")=="agent_baseline" and item.get("name") in baseline_coverage and item.get("status") in {"managed","missing","malformed","unsafe","unreadable"}}
        for name,status in baseline_items.items():
            baseline_coverage[name]["total"]+=1; baseline_coverage[name]["managed"]+=status=="managed"
        service_health_posture[service_health_status(inventory)]+=1
        trust_items=[item for item in inventory if isinstance(item,dict) and item.get("type")=="policy_trust"]
        ids=trust_items[0].get("key_ids",[]) if len(trust_items)==1 else []
        if not ids: policy_trust_posture["legacy"]+=1
        elif not isinstance(ids,list) or len(ids)>5 or any(not isinstance(item,str) or not re.fullmatch(r"[0-9a-f]{16}",item) for item in ids): policy_trust_posture["unrecognized"]+=1
        elif current_key_id in ids: policy_trust_posture["current"]+=1; policy_trust_posture["overlap"]+=len(ids)>1
        else: policy_trust_posture["unrecognized"]+=1
    active=sum(received>=now-active_window for received,_,_,_,_,_ in rows)
    return {"generated_at":now,"active_window_seconds":active_window,"required_agent_version":required_agent,"required_policy_version":required_policy,"total_devices":len(rows),"active_devices":active,"stale_devices":len(rows)-active,"latest_severity":by_severity,"version_posture":versions,"credential_posture":credential_posture,"agent_coverage":agent_coverage,"baseline_coverage":baseline_coverage,"service_health_posture":service_health_posture,"policy_trust_posture":policy_trust_posture,"active_policy_key_id":current_key_id}
class Handler(BaseHTTPRequestHandler):
    server_version="SentinelCollector/0.25"
    def reply(self,status,data,headers=None):
        body=json.dumps(data,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff")
        for name,value in (headers or {}).items(): self.send_header(name,str(value))
        self.end_headers(); self.wfile.write(body)
    def reply_policy(self):
        path=os.getenv("SENTINEL_POLICY_FILE","")
        try:
            candidate=Path(path)
            if not path or candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size>2_000_000: raise OSError("invalid policy file")
            body=candidate.read_bytes(); data=json.loads(body)
            if not isinstance(data,dict) or data.get("schema")!="sentinel.policy/v1" or not isinstance(data.get("version"),str): raise ValueError("invalid policy")
        except (OSError,ValueError,TypeError,json.JSONDecodeError,UnicodeError): return self.reply(503,{"error":"policy_unavailable"})
        try: keys=policy_signing_keys()
        except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): return self.reply(503,{"error":"policy_signing_unavailable"})
        digest=hashlib.sha256(body).hexdigest(); signature="sha256="+hmac.new(keys[0].encode(),body,hashlib.sha256).hexdigest(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","private, max-age=300"); self.send_header("ETag",'"'+digest+'"'); self.send_header("X-Sentinel-Policy-SHA256",digest); self.send_header("X-Sentinel-Policy-Key-ID",policy_key_id(keys[0])); self.send_header("X-Sentinel-Policy-Signature",signature); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(body)
    def rate_limited(self):
        limiter=getattr(self.server,"rate_limiter",None)
        if limiter is None: return False
        allowed,retry=limiter.check(self.client_address[0])
        if allowed: return False
        self.reply(429,{"error":"rate_limited"},{"Retry-After":retry}); return True
    def authorized(self):
        expected=secret_values("SENTINEL_COLLECTOR_TOKEN","SENTINEL_COLLECTOR_TOKENS"); supplied=self.headers.get("Authorization","").removeprefix("Bearer "); matched=False
        for candidate in expected: matched |= hmac.compare_digest(candidate,supplied)
        return bool(expected) and matched
    def callback_authorized(self):
        expected=secret_values("SENTINEL_APPROVAL_CALLBACK_TOKEN","SENTINEL_APPROVAL_CALLBACK_TOKENS"); supplied=self.headers.get("Authorization","").removeprefix("Bearer "); matched=False
        for candidate in expected: matched |= hmac.compare_digest(candidate,supplied)
        return bool(expected) and matched
    def report_authentication(self):
        path=os.getenv("SENTINEL_DEVICE_CREDENTIALS_FILE","")
        if not path: return (self.authorized(),None)
        try: credentials=device_credentials(path)
        except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): return (False,None)
        device_id=self.headers.get("X-Sentinel-Device-ID",""); credential=credentials.get(device_id)
        if not credential: return (False,None)
        supplied=self.headers.get("Authorization","").removeprefix("Bearer "); matched=False
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
        if not self.authorized(): return self.reply(401,{"error":"unauthorized"})
        parsed=urlsplit(self.path)
        if parsed.path=="/v1/policy" and not parsed.query:
            audit_event(self.server.db_path,"policy_read"); return self.reply_policy()
        if parsed.path=="/v1/devices":
            query=parse_qs(parsed.query,keep_blank_values=True)
            if set(query)-{"limit","view"} or any(len(values)!=1 for values in query.values()): return self.reply(400,{"error":"invalid_query"})
            try: limit=int(query.get("limit",["500"])[0])
            except ValueError: return self.reply(400,{"error":"invalid_limit"})
            if not 1<=limit<=10000: return self.reply(400,{"error":"invalid_limit"})
            view=query.get("view",["activation"])[0]
            if view not in {"activation","console"}: return self.reply(400,{"error":"invalid_view"})
            try:
                generated_at=int(time.time())
                with db_open(self.server.db_path) as db: rows=db.execute("WITH fleet AS (SELECT device_id,MAX(id) AS id,COUNT(*) AS report_count FROM reports GROUP BY device_id) SELECT r.device_id,COALESCE(a.last_seen,r.received_at),fleet.report_count,a.generation,r.severity,r.agent_version,r.policy_version,r.body FROM fleet JOIN reports r ON r.id=fleet.id LEFT JOIN device_auth_state a ON a.device_id=r.device_id ORDER BY r.device_id LIMIT ?",(limit+1,)).fetchall()
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            complete=len(rows)<=limit; rows=rows[:limit]; audit_event(self.server.db_path,"devices_read",detail=str(len(rows))+":"+("complete" if complete else "partial"))
            devices=[{"device_id":r[0],"last_seen":r[1],"report_count":r[2],"credential_generation":"legacy" if r[3] is None else "current" if r[3]==0 else "previous"} for r in rows]
            if view=="console":
                for index,item in enumerate(devices):
                    try: inventory=json.loads(rows[index][7]).get("inventory",[])
                    except (AttributeError,TypeError,ValueError,json.JSONDecodeError): inventory=[]
                    item.update({"severity":rows[index][4],"agent_version":rows[index][5] or "unknown","policy_version":rows[index][6] or "unknown","service_health_status":service_health_status(inventory)})
            return self.reply(200,{"generated_at":generated_at,"complete":complete,"devices":devices})
        if parsed.path=="/v1/summary" and not parsed.query:
            try:
                summary=collector_summary(self.server.db_path); audit_event(self.server.db_path,"summary_read",detail=str(summary["total_devices"])); return self.reply(200,summary)
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
        if parsed.path=="/v1/recommendations" and not parsed.query:
            try:
                result=collector_recommendations(self.server.db_path); audit_event(self.server.db_path,"recommendations_read",detail=str(len(result["recommendations"]))); return self.reply(200,result)
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
        if parsed.path=="/v1/audit" and not parsed.query:
            try:
                audit_event(self.server.db_path,"audit_read"); return self.reply(200,{"events":recent_audit(self.server.db_path)})
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
        self.reply(404,{"error":"not_found"})
    def do_POST(self):
        if self.rate_limited(): return
        if self.path=="/v1/remediation-receipts":
            if not self.callback_authorized(): return self.reply(401,{"error":"unauthorized"})
            try: length=int(self.headers.get("Content-Length","0"))
            except ValueError: return self.reply(400,{"error":"invalid_size"})
            if length<2 or length>16_384: return self.reply(413,{"error":"invalid_size"})
            try: value=json.loads(self.rfile.read(length))
            except (json.JSONDecodeError,UnicodeDecodeError,RecursionError,ValueError): return self.reply(400,{"error":"invalid_json"})
            if not valid_remediation_receipt(value): return self.reply(400,{"error":"invalid_receipt"})
            try: result=store_remediation_receipt(self.server.db_path,value,self.headers.get("Idempotency-Key",""))
            except ValueError as exc: return self.reply(409 if str(exc) in {"idempotency_conflict","invalid_state_transition","unknown_or_stale_recommendation"} else 400,{"error":str(exc)})
            except sqlite3.Error: return self.reply(503,{"error":"database_unavailable"})
            return self.reply(200 if result["duplicate"] else 202,result)
        if self.path!="/v1/reports": return self.reply(404,{"error":"not_found"})
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
    def log_message(self,fmt,*args): pass
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--listen",default="127.0.0.1"); ap.add_argument("--port",type=int,default=8788); ap.add_argument("--db",default="sentinel.db"); args=ap.parse_args()
    errors=runtime_secret_errors()
    if errors: raise SystemExit("invalid secret configuration: "+",".join(errors))
    server=ThreadingHTTPServer((args.listen,args.port),Handler); server.db_path=args.db; server.rate_limiter=RateLimiter(); server.serve_forever()
if __name__=="__main__": main()
