#!/usr/bin/env python3
"""Fail-closed operational acceptance probe for a Sentinel Collector."""
import argparse, hashlib, hmac, json, os, re, ssl, sys, time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_RESPONSE=1_000_000

def endpoint(base,path): return base.rstrip("/")+path
def request_json(url,headers=None,body=None,expected=(200,)):
    request=Request(url,data=body,headers=headers or {},method="POST" if body is not None else "GET")
    try:
        with urlopen(request,timeout=10,context=ssl.create_default_context()) as response:
            raw=response.read(MAX_RESPONSE+1); status=response.status
    except HTTPError as exc:
        try: raw=exc.read(MAX_RESPONSE+1); status=exc.code
        finally: exc.close()
    if len(raw)>MAX_RESPONSE: raise ValueError("response_too_large")
    if status not in expected: raise ValueError(f"unexpected_http_status:{status}")
    try: value=json.loads(raw)
    except (UnicodeDecodeError,json.JSONDecodeError): raise ValueError("invalid_json_response")
    return status,value

def validate_base(value):
    parsed=urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"","/"}: raise ValueError("invalid_collector_url")
    if parsed.scheme!="https" and not (parsed.scheme=="http" and parsed.hostname in {"127.0.0.1","localhost","::1"}): raise ValueError("collector_url_requires_https")
    if not parsed.hostname: raise ValueError("invalid_collector_url")
    return value.rstrip("/")

def auth_headers(token): return {"Authorization":"Bearer "+token}
def check_read_only(base,token):
    _,health=request_json(endpoint(base,"/health"));
    if health!={"status":"ok","database":"ok"}: raise ValueError("health_contract_invalid")
    status,_=request_json(endpoint(base,"/v1/summary"),expected=(401,))
    if status!=401: raise ValueError("unauthorized_summary_not_rejected")
    headers=auth_headers(token)
    _,summary=request_json(endpoint(base,"/v1/summary"),headers)
    required={"generated_at","active_window_seconds","required_agent_version","required_policy_version","total_devices","active_devices","stale_devices","latest_severity","version_posture","credential_posture","agent_coverage","baseline_coverage"}
    if not isinstance(summary,dict) or set(summary)!=required or type(summary["generated_at"]) is not int or type(summary["total_devices"]) is not int: raise ValueError("summary_contract_invalid")
    _,devices=request_json(endpoint(base,"/v1/devices?limit=10000"),headers)
    if not isinstance(devices,dict) or set(devices)!={"generated_at","complete","devices"} or type(devices["generated_at"]) is not int or type(devices["complete"]) is not bool or not isinstance(devices["devices"],list) or len(devices["devices"])>10000: raise ValueError("devices_contract_invalid")
    return {"health":True,"unauthorized_rejected":True,"summary":True,"devices":True,"fleet_complete":devices["complete"]}

def check_write(base,token,secret,device_id):
    if not 32<=len(secret)<=4096 or hmac.compare_digest(token,secret): raise ValueError("invalid_probe_credentials")
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,128}",device_id): raise ValueError("invalid_device_id")
    now=int(time.time()); report={"schema":"sentinel.report/v1","agent_version":"0.42.0","policy_version":"5.0.0","device_id":device_id,"scanned_at":now,"summary":{"critical":0,"high":0,"medium":0,"low":0},"findings":[]}
    body=json.dumps(report,separators=(",",":"),ensure_ascii=False).encode(); digest=hashlib.sha256(body).hexdigest(); signature=hmac.new(secret.encode(),str(now).encode()+b"."+device_id.encode()+b"."+body,hashlib.sha256).hexdigest()
    headers={**auth_headers(token),"Content-Type":"application/json","X-Sentinel-Timestamp":str(now),"X-Sentinel-Signature":"sha256="+signature,"X-Sentinel-Device-ID":device_id}
    results=[]
    for expected_duplicate in (False,True):
        status,ack=request_json(endpoint(base,"/v1/reports"),headers,body,expected=(200,202))
        if not isinstance(ack,dict) or set(ack)!={"accepted","duplicate","report_id","severity"} or ack!={"accepted":True,"duplicate":expected_duplicate,"report_id":digest[:20],"severity":"normal"}: raise ValueError("collector_ack_invalid")
        if status!=(200 if expected_duplicate else 202): raise ValueError("collector_ack_status_invalid")
        results.append(status)
    return {"signed_upload":True,"ack_body_bound":True,"duplicate_deduplicated":True,"statuses":results}

def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument("--url",required=True); parser.add_argument("--token-env",default="SENTINEL_PROBE_TOKEN"); parser.add_argument("--write-test",action="store_true"); parser.add_argument("--signing-secret-env",default="SENTINEL_PROBE_SIGNING_SECRET"); parser.add_argument("--device-id",default="sentinel-probe")
    args=parser.parse_args(argv); base=validate_base(args.url); token=os.environ.get(args.token_env,"")
    if not 32<=len(token)<=4096: raise ValueError("probe_token_missing_or_weak")
    result={"schema":"sentinel.collector-probe/v1","mode":"write" if args.write_test else "read_only","checks":check_read_only(base,token)}
    if args.write_test: result["checks"].update(check_write(base,token,os.environ.get(args.signing_secret_env,""),args.device_id))
    print(json.dumps(result,separators=(",",":"),sort_keys=True)); return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except (ValueError,URLError,OSError) as exc:
        print(json.dumps({"schema":"sentinel.collector-probe/v1","ok":False,"error":str(exc)},separators=(",",":")),file=sys.stderr); raise SystemExit(1)
