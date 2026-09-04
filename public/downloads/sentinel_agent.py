#!/usr/bin/env python3
"""Sentinel endpoint scanner prototype. Standard-library only; read-only by default."""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys, time, urllib.request
from pathlib import Path
DEFAULT_POLICY=Path(__file__).with_name("sentinel-policy.json")
AGENT_CONFIGS=[".cursor/mcp.json",".claude.json",".codex/config.toml",".codeium/windsurf/mcp_config.json"]
SKILL_ROOTS=[".codex/skills",".claude/skills",".cursor/skills"]
BASELINE=Path(__file__).with_name("sentinel-security-baseline.md")
MANAGED_MARKER="<!-- sentinel-managed-baseline -->"
def safe_path(path):
    value=str(path)
    for home in managed_homes():
        try: value=value.replace(str(home),"~")
        except OSError: pass
    return value
def finding(kind,severity,path,message,evidence=""): return {"kind":kind,"severity":severity,"path":safe_path(path),"message":message,"evidence":evidence[:180]}
def managed_homes():
    homes=[Path.home()]
    if hasattr(os,"geteuid") and os.geteuid()==0:
        for base in [Path("/Users"),Path("/home")]:
            if base.exists(): homes.extend(p for p in base.iterdir() if p.is_dir() and not p.name.startswith("."))
    return list(dict.fromkeys(homes))
def scan_text(path,text,policy):
    out=[]; low=text.lower(); checks=[("prompt_override","high",r"ignore (all |any )?(previous|prior) instructions"),("credential_access","high",r"(?:~/|\$home/)(?:\.ssh|\.aws)|security\s+find-(?:generic|internet)-password"),("unbounded_shell","high",r"shell\s*=\s*true|subprocess\..*shell\s*=\s*true"),("dynamic_eval","medium",r"\beval\s*\(|\bexec\s*\(")]
    for kind,sev,pat in checks:
        hit=re.search(pat,low)
        if hit: out.append(finding(kind,sev,path,f"匹配规则 {pat}",hit.group(0)))
    for pat in policy.get("secret_patterns",[]):
        hit=re.search(pat,text)
        if hit: out.append(finding("hardcoded_secret","critical",path,"疑似硬编码凭据",hit.group(0)[:8]+"…"))
    return out
def scan_mcp_config(path,text,policy):
    out=[]
    if path.suffix.lower()!=".json": return out
    try: data=json.loads(text)
    except json.JSONDecodeError: return [finding("invalid_mcp_config","medium",path,"MCP JSON 配置无法解析")]
    servers=data.get("mcpServers",data.get("servers",{})) if isinstance(data,dict) else {}
    if not isinstance(servers,dict): return out
    allowed=set(policy.get("allowed_mcp_servers",[])); allowed_commands=set(policy.get("allowed_mcp_commands",[])); allowed_domains=set(policy.get("allowed_mcp_domains",[]))
    for name,cfg in servers.items():
        if not isinstance(cfg,dict): continue
        if allowed and name not in allowed: out.append(finding("unknown_mcp","medium",path,f"未在允许列表中的 MCP Server: {name}"))
        command=str(cfg.get("command","")); base=Path(command).name
        if command and allowed_commands and base not in allowed_commands: out.append(finding("unapproved_mcp_command","high",path,f"MCP 使用未批准命令: {base}"))
        args=[str(x) for x in cfg.get("args",[]) if isinstance(x,(str,int,float))]
        if any(x in ["/","C:\\","$HOME","~"] or x.startswith(("/Users/","/home/")) for x in args): out.append(finding("broad_filesystem_scope","high",path,f"MCP {name} 请求宽泛文件范围"))
        for key,value in (cfg.get("env",{}) or {}).items():
            if re.search(r"TOKEN|SECRET|PASSWORD|API_KEY",str(key),re.I) and value and not re.match(r"^\$\{?[A-Z0-9_]+\}?$",str(value)): out.append(finding("literal_mcp_secret","critical",path,f"MCP {name} 包含明文敏感环境变量: {key}","[REDACTED]"))
        url=str(cfg.get("url",cfg.get("serverUrl","")))
        if url.startswith("http://"): out.append(finding("insecure_mcp_transport","high",path,f"MCP {name} 使用未加密 HTTP"))
        if url and allowed_domains and not any(url.startswith("https://"+d+"/") or url=="https://"+d for d in allowed_domains): out.append(finding("unapproved_mcp_domain","medium",path,f"MCP {name} 连接未批准域名"))
    return out
def scan(root,policy):
    findings=[]; inventory=[]
    for home in managed_homes():
        for rel in AGENT_CONFIGS:
            p=home/rel
            if p.exists():
                inventory.append({"type":"agent_config","path":safe_path(p)})
                try:
                    text=p.read_text(errors="ignore"); findings.extend(scan_text(p,text,policy)); findings.extend(scan_mcp_config(p,text,policy))
                except OSError: findings.append(finding("unreadable","low",p,"配置存在但无法读取"))
        for rel in SKILL_ROOTS:
            d=home/rel
            if d.exists():
                for p in d.rglob("SKILL.md"):
                    if ".system" in p.parts: continue
                    inventory.append({"type":"skill","path":safe_path(p)})
                    try: findings.extend(scan_text(p,p.read_text(errors="ignore"),policy))
                    except OSError: pass
    suffixes={".py",".js",".ts",".tsx",".jsx",".go",".java",".rb",".php",".sh",".json",".toml",".yaml",".yml"}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in suffixes and ".git" not in p.parts and "node_modules" not in p.parts:
            try:
                if p.stat().st_size<=1_000_000:
                    text=p.read_text(errors="ignore"); findings.extend(scan_text(p,text,policy))
                    if p.name in ["mcp.json","mcp_config.json"]: findings.extend(scan_mcp_config(p,text,policy))
            except OSError: pass
    return inventory,findings
def install_baseline(root):
    """Install additive, clearly-marked rules without replacing repository guidance."""
    content=BASELINE.read_text()
    targets=[(root/".cursor/rules/sentinel-security.mdc","---\ndescription: 企业安全编码基线\nalwaysApply: true\n---\n"+content),(root/".windsurf/rules/sentinel-security.md",content)]
    changed=[]
    for path,data in targets:
        path.parent.mkdir(parents=True,exist_ok=True)
        managed=MANAGED_MARKER+"\n"+data
        if not path.exists() or path.read_text(errors="ignore")!=managed:
            path.write_text(managed); changed.append(str(path))
    for name in ["AGENTS.md","CLAUDE.md"]:
        path=root/name; block=f"\n{MANAGED_MARKER}\n## 企业安全基线\n执行任何代码变更前，必须遵循 [.sentinel/SECURITY_BASELINE.md](.sentinel/SECURITY_BASELINE.md)。\n"
        current=path.read_text(errors="ignore") if path.exists() else ""
        if MANAGED_MARKER not in current: path.write_text(current.rstrip()+block); changed.append(str(path))
    shared=root/".sentinel/SECURITY_BASELINE.md"; shared.parent.mkdir(parents=True,exist_ok=True); shared.write_text(MANAGED_MARKER+"\n"+content)
    return changed
def post_report(url,token,report):
    if not url: return "disabled"
    body=json.dumps(report,ensure_ascii=False).encode(); headers={"Content-Type":"application/json","User-Agent":"SentinelAgent/0.3.0"}
    if token: headers["Authorization"]="Bearer "+token
    request=urllib.request.Request(url,data=body,headers=headers,method="POST")
    with urllib.request.urlopen(request,timeout=15) as response: return str(response.status)
def queue_report(spool,report):
    spool.mkdir(parents=True,exist_ok=True); path=spool/f"{report['scanned_at']}-{report['device_id']}.json"; path.write_text(json.dumps(report,ensure_ascii=False)); return path
def flush_spool(spool,url,token):
    if not spool.exists() or not url: return 0
    sent=0
    for path in sorted(spool.glob("*.json"))[:50]:
        post_report(url,token,json.loads(path.read_text())); path.unlink(); sent+=1
    return sent
def build_report(root,policy):
    inventory,findings=scan(root,policy)
    return {"schema":"sentinel.report/v1","agent_version":"0.4.0","policy_version":policy["version"],"device_id":hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12],"scanned_at":int(time.time()),"scan_root":safe_path(root),"inventory":inventory,"summary":{s:sum(f["severity"]==s for f in findings) for s in ["critical","high","medium","low"]},"findings":findings}
def main():
    ap=argparse.ArgumentParser(description="Sentinel AI Agent 安全扫描器"); ap.add_argument("scan_path",nargs="?",default="."); ap.add_argument("--policy",default=str(DEFAULT_POLICY)); ap.add_argument("--output"); ap.add_argument("--install-baseline",action="store_true"); ap.add_argument("--watch",action="store_true"); ap.add_argument("--interval",type=int,default=300); ap.add_argument("--report-url",default=os.getenv("SENTINEL_REPORT_URL","")); ap.add_argument("--spool-dir",default=os.getenv("SENTINEL_SPOOL_DIR","")); args=ap.parse_args()
    policy=json.loads(Path(args.policy).read_text()); root=Path(args.scan_path).resolve()
    if args.install_baseline: install_baseline(root)
    while True:
        report=build_report(root,policy); data=json.dumps(report,ensure_ascii=False,indent=2)
        if args.output: Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(data)
        if args.report_url:
            token=os.getenv("SENTINEL_REPORT_TOKEN",""); spool=Path(args.spool_dir) if args.spool_dir else (Path(args.output).parent/"spool" if args.output else Path.home()/".sentinel-agent/spool")
            try: flush_spool(spool,args.report_url,token); post_report(args.report_url,token,report)
            except Exception as exc: queue_report(spool,report); print(f"report upload failed; queued locally: {exc}",file=sys.stderr)
        print(data)
        if not args.watch: return 2 if report["summary"]["critical"] or report["summary"]["high"] else 0
        time.sleep(max(args.interval,60))
if __name__=="__main__": sys.exit(main())
