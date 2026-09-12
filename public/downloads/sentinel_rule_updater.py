#!/usr/bin/env python3
"""Track allowlisted upstream rule engines without executing or auto-promoting them."""
from __future__ import annotations
import argparse, hashlib, json, os, re, stat, tempfile, time, urllib.request
from pathlib import Path
from urllib.parse import urlsplit

MAX_RESPONSE=512_000
ALLOWED_LICENSES={"Apache-2.0","MIT","Semgrep-Rules-License-1.0","Apache-2.0-client-terms-apply-api"}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError("redirect_rejected")

def validate_catalog(value):
    if not isinstance(value,dict) or value.get("schema")!="sentinel.rule-sources/v1": raise ValueError("invalid_catalog")
    hosts=value.get("allowed_api_hosts",[]); sources=value.get("sources",[])
    if not isinstance(hosts,list) or not hosts or any(not re.fullmatch(r"[a-z0-9.-]+",x) for x in hosts): raise ValueError("invalid_allowed_hosts")
    if not isinstance(sources,list) or not sources or len(sources)>32: raise ValueError("invalid_sources")
    ids=set()
    for item in sources:
        if not isinstance(item,dict) or set(item)!={"id","api_url","mode","license","use","promotion"}: raise ValueError("invalid_source")
        parsed=urlsplit(item["api_url"])
        if parsed.scheme!="https" or parsed.hostname not in hosts or parsed.username or parsed.password or parsed.fragment: raise ValueError("invalid_source_url")
        if item["mode"] not in {"release","commit"} or item["license"] not in ALLOWED_LICENSES or item["id"] in ids: raise ValueError("invalid_source_metadata")
        ids.add(item["id"])
    return value

def fetch(source,hosts,timeout=15):
    request=urllib.request.Request(source["api_url"],headers={"Accept":"application/vnd.github+json","User-Agent":"SentinelRuleUpdater/1.0","X-GitHub-Api-Version":"2022-11-28"})
    with urllib.request.build_opener(NoRedirect).open(request,timeout=timeout) as response:
        final=urlsplit(response.geturl())
        if final.scheme!="https" or final.hostname not in hosts: raise ValueError("response_origin_rejected")
        raw=response.read(MAX_RESPONSE+1)
        if len(raw)>MAX_RESPONSE: raise ValueError("response_too_large")
    value=json.loads(raw)
    if source["mode"]=="release":
        revision=value.get("tag_name"); published=value.get("published_at")
        if not isinstance(revision,str) or not revision or len(revision)>100 or not isinstance(published,str): raise ValueError("invalid_release_response")
    else:
        revision=value.get("sha"); published=value.get("commit",{}).get("committer",{}).get("date")
        if not isinstance(revision,str) or not re.fullmatch(r"[0-9a-f]{40}",revision) or not isinstance(published,str): raise ValueError("invalid_commit_response")
    return {"id":source["id"],"revision":revision,"published_at":published,"license":source["license"],"use":source["use"],"promotion":source["promotion"],"metadata_sha256":hashlib.sha256(raw).hexdigest(),"status":"quarantined"}

def atomic_write(path,data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        info=path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode): raise ValueError("unsafe_output")
    fd,name=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent)
    try:
        with os.fdopen(fd,"wb") as handle: fd=-1; handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.chmod(name,0o644); os.replace(name,path)
    finally:
        if fd>=0: os.close(fd)
        try: os.unlink(name)
        except FileNotFoundError: pass

def update(catalog_path,output_path,timeout=15):
    catalog=validate_catalog(json.loads(Path(catalog_path).read_text()))
    results=[]
    for source in catalog["sources"]:
        try: results.append(fetch(source,set(catalog["allowed_api_hosts"]),timeout))
        except Exception as exc: results.append({"id":source["id"],"status":"unavailable","error":type(exc).__name__})
    snapshot={"schema":"sentinel.rule-source-status/v1","generated_at":int(time.time()),"auto_executed":False,"auto_promoted":False,"sources":results}
    atomic_write(output_path,(json.dumps(snapshot,ensure_ascii=False,indent=2)+"\n").encode()); return snapshot

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--catalog",default=str(Path(__file__).with_name("sentinel-rule-sources.json"))); parser.add_argument("--output",default="/var/lib/sentinel/rule-source-status.json"); parser.add_argument("--timeout",type=int,default=15); args=parser.parse_args()
    try:
        result=update(args.catalog,args.output,min(max(args.timeout,2),30)); print(json.dumps({"ok":True,"available":sum(x["status"]=="quarantined" for x in result["sources"]),"total":len(result["sources"])},separators=(",",":"))); return 0
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":str(exc)},separators=(",",":"))); return 1
if __name__=="__main__": raise SystemExit(main())
