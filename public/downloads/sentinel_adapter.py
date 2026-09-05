#!/usr/bin/env python3
"""Fail-safe vendor boundary for Sangfor EDR and Leagsoft. Disabled by default."""
import argparse, hashlib, hmac, json, os, time, urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

SAFE_ACTIONS={"observe","alert","isolate_pending_approval","block_pending_approval"}
ADAPTERS=("sangfor","leagsoft","security_webhook")

def severity(report):
    for level in ["critical","high","medium","low"]:
        if int(report.get("summary",{}).get(level,0))>0: return level
    return "normal"
def sangfor_event(report,config):
    level=severity(report); action=config.get("actions",{}).get(level,"observe")
    if action not in SAFE_ACTIONS: raise ValueError(f"unsafe_sangfor_action:{action}")
    return {"event_type":"ai_agent_security_finding","source":"sentinel","device_id":report["device_id"],"severity":level,"recommended_action":action,"finding_count":len(report.get("findings",[])),"policy_version":report.get("policy_version"),"occurred_at":report.get("scanned_at")}
def leagsoft_posture(report,config):
    level=severity(report); return {"source":"sentinel","device_id":report["device_id"],"compliant":level not in ["critical","high"],"risk_level":level,"policy_version":report.get("policy_version"),"last_scan":report.get("scanned_at"),"reason":"critical_or_high_finding" if level in ["critical","high"] else "policy_pass"}
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
    body=json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode(); headers={"Content-Type":"application/json","User-Agent":"SentinelAdapter/0.4"}
    if token: headers["Authorization"]="Bearer "+token
    if secret:
        timestamp=str(int(time.time())); headers["X-Sentinel-Signature"]="sha256="+hmac.new(secret.encode(),timestamp.encode()+b"."+body,hashlib.sha256).hexdigest(); headers["X-Sentinel-Timestamp"]=timestamp
    with urllib.request.urlopen(urllib.request.Request(url,data=body,headers=headers,method="POST"),timeout=15) as response: return response.status
def deliver(name,target,payload,sender=send):
    env_name=target.get("secret_env" if name=="security_webhook" else "token_env",""); credential=os.getenv(env_name,"")
    return sender(target["url"],payload,secret=credential) if name=="security_webhook" else sender(target["url"],payload,token=credential)
def spool_limit(value=None):
    raw=os.getenv("SENTINEL_ADAPTER_SPOOL_MAX_EVENTS","500") if value is None else value
    try: return min(max(int(raw),10),10000)
    except (TypeError,ValueError): return 500
def queue_delivery(spool,name,payload,limit=None):
    spool.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(spool,0o700)
    body=json.dumps({"adapter":name,"queued_at":int(time.time()),"payload":payload},ensure_ascii=False,separators=(",",":")); digest=hashlib.sha256(body.encode()).hexdigest()[:16]
    path=spool/f"{int(time.time())}-{time.time_ns()}-{digest}.json"; path.write_text(body); os.chmod(path,0o600)
    files=sorted(spool.glob("*.json"),key=lambda item:(item.stat().st_mtime_ns,item.name)); keep=spool_limit(limit)
    for expired in files[:-keep]: expired.unlink()
    return path
def quarantine(path,spool,keep=20):
    invalid=path.with_name(path.name+f".{time.time_ns()}.invalid"); path.rename(invalid); os.chmod(invalid,0o600)
    files=sorted(spool.glob("*.invalid"),key=lambda item:(item.stat().st_mtime_ns,item.name))
    for expired in files[:-keep]: expired.unlink()
    return invalid
def flush_spool(config,spool,sender=send,limit=50):
    if not spool.exists(): return []
    results=[]
    for path in sorted(spool.glob("*.json"))[:limit]:
        try:
            item=json.loads(path.read_text()); name=item["adapter"]
            if name not in ADAPTERS or "payload" not in item: raise ValueError("invalid_queued_event")
        except (OSError,json.JSONDecodeError,UnicodeDecodeError,RecursionError,TypeError,KeyError,ValueError) as exc:
            invalid=quarantine(path,spool); results.append({"adapter":path.name,"result":"quarantined","queue_id":invalid.name,"error":type(exc).__name__}); continue
        try:
            target=config.get(name,{}); validate_target(name,target,config); status=deliver(name,target,item["payload"],sender); path.unlink(); results.append({"adapter":name,"result":"sent_from_spool","status":status})
        except Exception as exc: results.append({"adapter":name,"result":"retained","queue_id":path.name,"error":type(exc).__name__})
    return results
def process(report,config,dry_run=False,spool_dir=None,sender=send):
    outputs=[]; spool=Path(spool_dir) if spool_dir else Path(os.getenv("SENTINEL_ADAPTER_SPOOL",Path.home()/".sentinel-adapter/spool"))
    builders={"sangfor":sangfor_event,"leagsoft":leagsoft_posture,"security_webhook":lambda value,_config:value}
    for name in ADAPTERS:
        target=config.get(name,{})
        if not target.get("enabled"): continue
        payload=None
        try:
            validate_target(name,target,config,dry_run); payload=builders[name](report,target)
            if dry_run: outputs.append({"adapter":name,"result":"dry_run","payload":payload}); continue
            status=deliver(name,target,payload,sender); outputs.append({"adapter":name,"result":"sent","status":status,"payload":payload})
        except ValueError as exc:
            outputs.append({"adapter":name,"result":"rejected","error":str(exc)})
        except Exception as exc:
            path=queue_delivery(spool,name,payload); outputs.append({"adapter":name,"result":"queued","queue_id":path.name,"error":type(exc).__name__})
    return outputs
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("report",nargs="?"); ap.add_argument("--config",default=str(Path(__file__).with_name("sentinel-adapters.json"))); ap.add_argument("--dry-run",action="store_true"); ap.add_argument("--spool-dir",default=os.getenv("SENTINEL_ADAPTER_SPOOL","")); ap.add_argument("--flush-only",action="store_true"); args=ap.parse_args()
    config=json.loads(Path(args.config).read_text()); spool=Path(args.spool_dir) if args.spool_dir else Path.home()/".sentinel-adapter/spool"
    if args.flush_only: print(json.dumps(flush_spool(config,spool),ensure_ascii=False,indent=2)); return
    if not args.report: ap.error("report is required unless --flush-only is used")
    report=json.loads(Path(args.report).read_text()); print(json.dumps(process(report,config,args.dry_run,spool),ensure_ascii=False,indent=2))
if __name__=="__main__": main()
