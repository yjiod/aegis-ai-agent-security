#!/usr/bin/env python3
"""Fail-safe vendor boundary for Sangfor EDR and Leagsoft. Disabled by default."""
import argparse, hashlib, hmac, json, os, re, tempfile, time, urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

SAFE_ACTIONS={"observe","alert","isolate_pending_approval","block_pending_approval"}
ADAPTERS=("sangfor","leagsoft","security_webhook")
MAX_VENDOR_PAYLOAD_BYTES=2_000_000
MAX_VENDOR_QUEUE_FILE_BYTES=2_100_000
MAX_VENDOR_CONFIG_BYTES=65_536
MAX_VENDOR_ACCEPTANCE_BYTES=262_144

def read_json_bounded(path,max_bytes):
    path=Path(path)
    if path.is_symlink() or not path.is_file(): raise ValueError("unsafe_json_input")
    if path.stat().st_size>max_bytes: raise ValueError("oversized_json_input")
    raw=path.read_bytes()
    if len(raw)>max_bytes: raise ValueError("oversized_json_input")
    return json.loads(raw.decode("utf-8"))
TARGET_FIELDS={"sangfor":{"enabled","mode","url","token_env","actions"},"leagsoft":{"enabled","mode","url","token_env","compliance"},"security_webhook":{"enabled","mode","url","secret_env"}}
CREDENTIAL_PREFIX={"sangfor":"SANGFOR_","leagsoft":"LEAGSOFT_","security_webhook":"SENTINEL_"}

def validate_config(config):
    if not isinstance(config,dict) or not set(config).issubset({"allowed_hosts",*ADAPTERS}): raise ValueError("invalid_adapter_config")
    hosts=config.get("allowed_hosts",[])
    if not isinstance(hosts,list) or len(hosts)>100 or any(not isinstance(host,str) or not 1<=len(host)<=253 for host in hosts): raise ValueError("invalid_allowed_hosts")
    for name in ADAPTERS:
        target=config.get(name,{})
        if not isinstance(target,dict) or not set(target).issubset(TARGET_FIELDS[name]): raise ValueError(f"invalid_adapter_target:{name}")
        if "enabled" in target and not isinstance(target["enabled"],bool): raise ValueError(f"invalid_adapter_enabled:{name}")
        env_name=target.get("secret_env" if name=="security_webhook" else "token_env","")
        if env_name and (not isinstance(env_name,str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}",env_name) or not env_name.startswith(CREDENTIAL_PREFIX[name])): raise ValueError(f"invalid_adapter_credential_env:{name}")
        if name=="sangfor":
            actions=target.get("actions",{})
            if not isinstance(actions,dict) or not set(actions).issubset({"critical","high","medium","low","normal"}) or any(not isinstance(action,str) or action not in SAFE_ACTIONS for action in actions.values()): raise ValueError("invalid_sangfor_actions")
        if name=="leagsoft" and target:
            compliance=target.get("compliance",{})
            if not isinstance(compliance,dict) or set(compliance)!={"max_policy_age_hours","critical_allowed"}: raise ValueError("invalid_leagsoft_compliance")
            age=compliance.get("max_policy_age_hours"); critical=compliance.get("critical_allowed")
            if isinstance(age,bool) or not isinstance(age,int) or not 1<=age<=168 or isinstance(critical,bool) or not isinstance(critical,int) or critical!=0: raise ValueError("invalid_leagsoft_compliance")
    return config

def valid_report(report):
    if not isinstance(report,dict): return False
    required={"schema","agent_version","policy_version","device_id","scanned_at","summary","findings"}; allowed=required|{"scan_root","inventory"}
    if not required.issubset(report) or not set(report).issubset(allowed) or report.get("schema")!="sentinel.report/v1": return False
    if not all(isinstance(report.get(key),str) and 1<=len(report[key])<=64 for key in ("agent_version","policy_version")): return False
    if not isinstance(report.get("device_id"),str) or not 8<=len(report["device_id"])<=128: return False
    if not isinstance(report.get("scanned_at"),int) or isinstance(report["scanned_at"],bool): return False
    if "scan_root" in report and (not isinstance(report["scan_root"],str) or len(report["scan_root"])>1024): return False
    if "inventory" in report and (not isinstance(report["inventory"],list) or len(report["inventory"])>5000 or any(not isinstance(item,dict) for item in report["inventory"])): return False
    levels=("critical","high","medium","low"); summary=report.get("summary")
    if not isinstance(summary,dict) or set(summary)!=set(levels) or any(not isinstance(summary[level],int) or isinstance(summary[level],bool) or summary[level]<0 for level in levels): return False
    findings=report.get("findings")
    if not isinstance(findings,list) or len(findings)>10000: return False
    counts={level:0 for level in levels}
    for item in findings:
        if not isinstance(item,dict) or not {"kind","severity","path","message"}.issubset(item) or not set(item).issubset({"kind","severity","path","message","evidence"}): return False
        if item.get("severity") not in counts or any(not isinstance(item.get(key),str) for key in ("kind","path","message")): return False
        if not 1<=len(item["kind"])<=128 or len(item["path"])>2048 or not 1<=len(item["message"])<=2048: return False
        if "evidence" in item and (not isinstance(item["evidence"],str) or len(item["evidence"])>512): return False
        counts[item["severity"]]+=1
    if counts!=summary: return False
    try: return len(json.dumps(report,ensure_ascii=False,separators=(",",":")).encode())<=MAX_VENDOR_PAYLOAD_BYTES
    except (TypeError,ValueError,RecursionError,UnicodeError): return False
def valid_payload(name,payload):
    if name=="security_webhook": return valid_report(payload)
    if not isinstance(payload,dict): return False
    try:
        if len(json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode())>MAX_VENDOR_PAYLOAD_BYTES: return False
    except (TypeError,ValueError,RecursionError,UnicodeError): return False
    fields={"sangfor":{"event_type","source","device_id","severity","recommended_action","finding_count","policy_version","occurred_at"},"leagsoft":{"source","device_id","compliant","risk_level","policy_version","last_scan","reason"}}
    if name not in fields or set(payload)!=fields[name]: return False
    if payload.get("source")!="sentinel" or not isinstance(payload.get("device_id"),str) or not 8<=len(payload["device_id"])<=128: return False
    if not isinstance(payload.get("policy_version"),str) or not 1<=len(payload["policy_version"])<=64: return False
    if payload.get("severity",payload.get("risk_level")) not in {"critical","high","medium","low","normal"}: return False
    if name=="sangfor": return payload.get("event_type")=="ai_agent_security_finding" and payload.get("recommended_action") in SAFE_ACTIONS and isinstance(payload.get("finding_count"),int) and not isinstance(payload["finding_count"],bool) and 0<=payload["finding_count"]<=10000 and isinstance(payload.get("occurred_at"),int) and not isinstance(payload["occurred_at"],bool)
    if not isinstance(payload.get("last_scan"),int) or isinstance(payload["last_scan"],bool): return False
    if payload["risk_level"] in {"critical","high"}: return payload.get("compliant") is False and payload.get("reason")=="critical_or_high_finding"
    if payload.get("reason")=="stale_policy": return payload.get("compliant") is False
    return payload.get("compliant") is True and payload.get("reason")=="policy_pass"

def severity(report):
    for level in ["critical","high","medium","low"]:
        if int(report.get("summary",{}).get(level,0))>0: return level
    return "normal"
def sangfor_event(report,config):
    level=severity(report); action=config.get("actions",{}).get(level,"observe")
    if action not in SAFE_ACTIONS: raise ValueError(f"unsafe_sangfor_action:{action}")
    return {"event_type":"ai_agent_security_finding","source":"sentinel","device_id":report["device_id"],"severity":level,"recommended_action":action,"finding_count":len(report.get("findings",[])),"policy_version":report.get("policy_version"),"occurred_at":report.get("scanned_at")}
def leagsoft_posture(report,config,now=None):
    level=severity(report); now=int(time.time()) if now is None else int(now); last_scan=report.get("scanned_at"); max_age=config["compliance"]["max_policy_age_hours"]*3600
    risky=level in {"critical","high"}; stale=last_scan>now+300 or now-last_scan>max_age
    compliant=not risky and not stale; reason="critical_or_high_finding" if risky else "stale_policy" if stale else "policy_pass"
    return {"source":"sentinel","device_id":report["device_id"],"compliant":compliant,"risk_level":level,"policy_version":report.get("policy_version"),"last_scan":last_scan,"reason":reason}
def validate_target(name,target,config,dry_run=False):
    if target.get("mode","webhook")!="webhook": raise ValueError(f"unsupported_adapter_mode:{name}")
    url=str(target.get("url","")); parsed=urlsplit(url)
    if parsed.scheme!="https" or not parsed.hostname: raise ValueError(f"invalid_https_url:{name}")
    allowed={str(x).lower().rstrip(".") for x in config.get("allowed_hosts",[])}; host=parsed.hostname.lower().rstrip(".")
    if host not in allowed: raise ValueError(f"unapproved_adapter_host:{name}")
    sensitive={"token","key","api_key","apikey","secret","password","access_token"}
    if parsed.username or parsed.password or any(k.lower() in sensitive for k,_ in parse_qsl(parsed.query,keep_blank_values=True)): raise ValueError(f"credentials_in_adapter_url:{name}")
    env_name=target.get("secret_env" if name=="security_webhook" else "token_env","")
    if not dry_run and (not env_name or not os.getenv(env_name,"")): raise ValueError(f"missing_adapter_credential:{name}")
def send(url,payload,token="",secret=""):
    body=json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode()
    if len(body)>MAX_VENDOR_PAYLOAD_BYTES: raise ValueError("adapter_payload_too_large")
    headers={"Content-Type":"application/json","User-Agent":"SentinelAdapter/0.15","Idempotency-Key":hashlib.sha256(body).hexdigest()}
    if token: headers["Authorization"]="Bearer "+token
    if secret:
        timestamp=str(int(time.time())); headers["X-Sentinel-Signature"]="sha256="+hmac.new(secret.encode(),timestamp.encode()+b"."+body,hashlib.sha256).hexdigest(); headers["X-Sentinel-Timestamp"]=timestamp
    with urllib.request.urlopen(urllib.request.Request(url,data=body,headers=headers,method="POST"),timeout=15) as response: return response.status
def deliver(name,target,payload,sender=send):
    env_name=target.get("secret_env" if name=="security_webhook" else "token_env",""); credential=os.getenv(env_name,"")
    status=sender(target["url"],payload,secret=credential) if name=="security_webhook" else sender(target["url"],payload,token=credential)
    if not isinstance(status,int) or isinstance(status,bool) or not 200<=status<300: raise OSError("adapter_delivery_not_accepted")
    return status
def spool_limit(value=None):
    raw=os.getenv("SENTINEL_ADAPTER_SPOOL_MAX_EVENTS","500") if value is None else value
    try: return min(max(int(raw),10),10000)
    except (TypeError,ValueError): return 500
def queue_delivery(spool,name,payload,limit=None):
    if spool.is_symlink(): raise OSError("adapter_spool_unsafe")
    spool.mkdir(mode=0o700,parents=True,exist_ok=True)
    if spool.is_symlink() or not spool.is_dir(): raise OSError("adapter_spool_unsafe")
    os.chmod(spool,0o700)
    files=sorted(spool.glob("*.json"),key=lambda item:(item.stat().st_mtime_ns,item.name)); keep=spool_limit(limit)
    if len(files)>=keep: raise OSError("adapter_spool_full")
    body=json.dumps({"adapter":name,"queued_at":int(time.time()),"payload":payload},ensure_ascii=False,separators=(",",":")); digest=hashlib.sha256(body.encode()).hexdigest()[:16]
    path=spool/f"{int(time.time())}-{time.time_ns()}-{digest}.json"; fd,temp_name=tempfile.mkstemp(prefix=".sentinel-adapter-",suffix=".tmp",dir=spool); temp=Path(temp_name)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as handle: fd=-1; handle.write(body); handle.flush(); os.fsync(handle.fileno())
        os.replace(temp,path)
        directory_fd=os.open(spool,os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        return path
    finally:
        if fd>=0: os.close(fd)
        if temp.exists(): temp.unlink()
def quarantine(path,spool,keep=20):
    invalid=path.with_name(path.name+f".{time.time_ns()}.invalid"); path.rename(invalid); os.chmod(invalid,0o600)
    files=sorted(spool.glob("*.invalid"),key=lambda item:(item.stat().st_mtime_ns,item.name))
    for expired in files[:-keep]: expired.unlink()
    return invalid
def flush_spool(config,spool,sender=send,limit=50):
    try: validate_config(config)
    except ValueError as exc: return [{"adapter":"boundary","result":"rejected","error":str(exc)}]
    if not spool.exists(): return []
    results=[]
    for path in sorted(spool.glob("*.json"))[:limit]:
        try:
            if path.stat().st_size>MAX_VENDOR_QUEUE_FILE_BYTES: raise ValueError("oversized_queued_event")
            item=json.loads(path.read_text()); name=item["adapter"]
            if name not in ADAPTERS or set(item)!={"adapter","queued_at","payload"} or not valid_payload(name,item["payload"]): raise ValueError("invalid_queued_event")
        except (OSError,json.JSONDecodeError,UnicodeDecodeError,RecursionError,TypeError,KeyError,ValueError) as exc:
            invalid=quarantine(path,spool); results.append({"adapter":path.name,"result":"quarantined","queue_id":invalid.name,"error":type(exc).__name__}); continue
        try:
            target=config.get(name,{}); validate_target(name,target,config); status=deliver(name,target,item["payload"],sender); path.unlink(); results.append({"adapter":name,"result":"sent_from_spool","status":status})
        except Exception as exc: results.append({"adapter":name,"result":"retained","queue_id":path.name,"error":type(exc).__name__})
    return results
def process(report,config,dry_run=False,spool_dir=None,sender=send,now=None):
    if not valid_report(report): return [{"adapter":"boundary","result":"rejected","error":"invalid_report_contract"}]
    try: validate_config(config)
    except ValueError as exc: return [{"adapter":"boundary","result":"rejected","error":str(exc)}]
    outputs=[]; spool=Path(spool_dir) if spool_dir else Path(os.getenv("SENTINEL_ADAPTER_SPOOL",Path.home()/".sentinel-adapter/spool"))
    builders={"sangfor":sangfor_event,"leagsoft":lambda value,target:leagsoft_posture(value,target,now),"security_webhook":lambda value,_config:value}
    for name in ADAPTERS:
        target=config.get(name,{})
        if not target.get("enabled"): continue
        payload=None
        try:
            validate_target(name,target,config,dry_run); payload=builders[name](report,target)
            if not valid_payload(name,payload): raise ValueError(f"invalid_adapter_payload:{name}")
            if dry_run: outputs.append({"adapter":name,"result":"dry_run","payload":payload}); continue
            status=deliver(name,target,payload,sender); outputs.append({"adapter":name,"result":"sent","status":status,"payload":payload})
        except ValueError as exc:
            outputs.append({"adapter":name,"result":"rejected","error":str(exc)})
        except Exception as exc:
            if payload is None: outputs.append({"adapter":name,"result":"rejected","error":"payload_build_failed"}); continue
            try:
                path=queue_delivery(spool,name,payload); outputs.append({"adapter":name,"result":"queued","queue_id":path.name,"error":type(exc).__name__})
            except OSError as queue_error:
                error=str(queue_error) if str(queue_error) in {"adapter_spool_full","adapter_spool_unsafe"} else "adapter_spool_write_failed"
                outputs.append({"adapter":name,"result":"retained","error":error})
    return outputs
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("report",nargs="?"); ap.add_argument("--config",default=str(Path(__file__).with_name("sentinel-adapters.json"))); ap.add_argument("--dry-run",action="store_true"); ap.add_argument("--spool-dir",default=os.getenv("SENTINEL_ADAPTER_SPOOL","")); ap.add_argument("--flush-only",action="store_true"); args=ap.parse_args()
    try: config=read_json_bounded(args.config,MAX_VENDOR_CONFIG_BYTES); validate_config(config)
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc: raise SystemExit("invalid adapter configuration: "+type(exc).__name__)
    spool=Path(args.spool_dir) if args.spool_dir else Path.home()/".sentinel-adapter/spool"
    if args.flush_only: print(json.dumps(flush_spool(config,spool),ensure_ascii=False,indent=2)); return
    if not args.report: ap.error("report is required unless --flush-only is used")
    try: report=read_json_bounded(args.report,MAX_VENDOR_PAYLOAD_BYTES)
    except (OSError,ValueError,TypeError,RecursionError,UnicodeError,json.JSONDecodeError) as exc: raise SystemExit("invalid adapter report: "+type(exc).__name__)
    print(json.dumps(process(report,config,args.dry_run,spool),ensure_ascii=False,indent=2))
if __name__=="__main__": main()
