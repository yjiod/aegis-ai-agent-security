#!/usr/bin/env python3
"""Vendor-neutral adapter boundary for Sangfor EDR and Leagsoft. Disabled by default."""
import argparse, hashlib, hmac, json, os, sys, time, urllib.request
from pathlib import Path

def severity(report):
    for level in ["critical","high","medium","low"]:
        if int(report.get("summary",{}).get(level,0))>0: return level
    return "normal"
def sangfor_event(report,config):
    level=severity(report); return {"event_type":"ai_agent_security_finding","source":"sentinel","device_id":report["device_id"],"severity":level,"recommended_action":config.get("actions",{}).get(level,"observe"),"finding_count":len(report.get("findings",[])),"policy_version":report.get("policy_version"),"occurred_at":report.get("scanned_at")}
def leagsoft_posture(report,config):
    level=severity(report); return {"source":"sentinel","device_id":report["device_id"],"compliant":level not in ["critical","high"],"risk_level":level,"policy_version":report.get("policy_version"),"last_scan":report.get("scanned_at"),"reason":"critical_or_high_finding" if level in ["critical","high"] else "policy_pass"}
def send(url,payload,token="",secret=""):
    body=json.dumps(payload,ensure_ascii=False,separators=(",",":")).encode(); headers={"Content-Type":"application/json","User-Agent":"SentinelAdapter/0.2"}
    if token: headers["Authorization"]="Bearer "+token
    if secret:
        timestamp=str(int(time.time())); headers["X-Sentinel-Signature"]="sha256="+hmac.new(secret.encode(),timestamp.encode()+b"."+body,hashlib.sha256).hexdigest(); headers["X-Sentinel-Timestamp"]=timestamp
    with urllib.request.urlopen(urllib.request.Request(url,data=body,headers=headers,method="POST"),timeout=15) as response: return response.status
def process(report,config,dry_run=False):
    outputs=[]
    for name,builder in [("sangfor",sangfor_event),("leagsoft",leagsoft_posture)]:
        target=config.get(name,{})
        if not target.get("enabled"): continue
        payload=builder(report,target); result="dry_run" if dry_run else send(target["url"],payload,os.getenv(target.get("token_env",""),"")); outputs.append({"adapter":name,"result":result,"payload":payload})
    hook=config.get("security_webhook",{})
    if hook.get("enabled"):
        result="dry_run" if dry_run else send(hook["url"],report,secret=os.getenv(hook.get("secret_env",""),"")); outputs.append({"adapter":"security_webhook","result":result})
    return outputs
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("report"); ap.add_argument("--config",default=str(Path(__file__).with_name("sentinel-adapters.json"))); ap.add_argument("--dry-run",action="store_true"); args=ap.parse_args()
    report=json.loads(Path(args.report).read_text()); config=json.loads(Path(args.config).read_text()); print(json.dumps(process(report,config,args.dry_run),ensure_ascii=False,indent=2))
if __name__=="__main__": main()
