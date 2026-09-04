#!/usr/bin/env python3
"""Sentinel endpoint scanner prototype. Standard-library only; read-only by default."""
from __future__ import annotations
import argparse, hashlib, hmac, json, os, re, sys, time, urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
DEFAULT_POLICY=Path(__file__).with_name("sentinel-policy.json")
AGENT_CONFIGS=[".cursor/mcp.json",".claude.json",".codex/config.toml",".codeium/windsurf/mcp_config.json"]
SKILL_ROOTS=[".codex/skills",".claude/skills",".cursor/skills"]
DEPENDENCY_MANIFESTS={"package.json","requirements.txt","requirements-dev.txt"}
AGENT_HOME_MARKERS={
    "cursor":[".cursor/mcp.json","Library/Application Support/Cursor/User/settings.json",".config/Cursor/User/settings.json"],
    "codex":[".codex/config.toml",".local/bin/codex"],
    "claude_code":[".claude.json",".claude/settings.json",".local/bin/claude"],
    "windsurf":[".codeium/windsurf/mcp_config.json","Library/Application Support/Windsurf/User/settings.json",".config/Windsurf/User/settings.json"],
}
AGENT_SYSTEM_MARKERS={
    "cursor":["/Applications/Cursor.app","/usr/local/bin/cursor","/opt/homebrew/bin/cursor"],
    "codex":["/usr/local/bin/codex","/opt/homebrew/bin/codex"],
    "claude_code":["/usr/local/bin/claude","/opt/homebrew/bin/claude"],
    "windsurf":["/Applications/Windsurf.app","/usr/local/bin/windsurf","/opt/homebrew/bin/windsurf"],
}
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
def discover_agent_tools(homes=None,system_markers=None):
    """Discover supported AI coding agents from files only; never execute them."""
    homes=managed_homes() if homes is None else homes; markers=AGENT_SYSTEM_MARKERS if system_markers is None else system_markers
    found=[]; seen=set()
    def add(name,path,scope):
        key=(name,str(path))
        if key not in seen: found.append({"type":"ai_agent","name":name,"path":safe_path(path),"scope":scope,"detected_by":"filesystem_marker"}); seen.add(key)
    for home in homes:
        for name,relative_paths in AGENT_HOME_MARKERS.items():
            for rel in relative_paths:
                path=Path(home)/rel
                if path.exists(): add(name,path,"user"); break
    for name,paths in markers.items():
        for raw in paths:
            path=Path(raw)
            if path.exists(): add(name,path,"system"); break
    return found
def scan_text(path,text,policy):
    out=[]; low=text.lower(); checks=[("prompt_override","high",r"ignore (all |any )?(previous|prior) instructions"),("credential_access","high",r"(?:~/|\$home/)(?:\.ssh|\.aws)|security\s+find-(?:generic|internet)-password"),("unbounded_shell","high",r"shell\s*=\s*true|subprocess\..*shell\s*=\s*true"),("dynamic_eval","medium",r"\beval\s*\(|\bexec\s*\(")]
    for kind,sev,pat in checks:
        hit=re.search(pat,low)
        if hit: out.append(finding(kind,sev,path,f"匹配规则 {pat}",hit.group(0)))
    hidden=re.search(r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]",text)
    if hidden: out.append(finding("hidden_instruction","high",path,"包含可隐藏或改变显示方向的 Unicode 控制字符",f"U+{ord(hidden.group(0)):04X}"))
    weak=re.search(r"(?is)(?:token|secret|session|nonce).{0,120}(?:math\.random|random\.random)\s*\(|(?:math\.random|random\.random)\s*\(.{0,120}(?:token|secret|session|nonce)",text)
    if weak: out.append(finding("weak_random_token","high",path,"安全敏感值使用非密码学随机数","weak random generator"))
    for command in policy.get("blocked_commands",[]):
        pattern=re.escape(command.lower()).replace(r"\*",r"[^\r\n]*")
        hit=re.search(r"(?m)^\s*"+pattern+r"(?:\s|$)",low)
        if hit: out.append(finding("blocked_command","high",path,f"命中禁止命令: {command}",hit.group(0).strip()[:80]))
    for pat in policy.get("secret_patterns",[]):
        hit=re.search(pat,text)
        if hit: out.append(finding("hardcoded_secret","critical",path,"疑似硬编码凭据",hit.group(0)[:8]+"…"))
    return out
def scan_mcp_server(path,name,cfg,policy):
    out=[]; allowed=set(policy.get("allowed_mcp_servers",[])); allowed_commands=set(policy.get("allowed_mcp_commands",[])); allowed_domains={x.lower().rstrip(".") for x in policy.get("allowed_mcp_domains",[])}; allowed_transports=set(policy.get("allowed_mcp_transports",[]))
    if "allowed_mcp_servers" in policy and name not in allowed: out.append(finding("unknown_mcp","medium",path,f"未在允许列表中的 MCP Server: {name}"))
    command=str(cfg.get("command","")).strip(); base=re.split(r"[\\/]",command)[-1]
    url=str(cfg.get("url",cfg.get("serverUrl",""))).strip(); explicit=str(cfg.get("transport","")).lower()
    transport=explicit or ("https" if url.startswith("https://") else "http" if url.startswith("http://") else "stdio" if command else "unknown")
    if command and url: out.append(finding("ambiguous_mcp_transport","high",path,f"MCP {name} 同时配置本地命令和远程 URL"))
    if "allowed_mcp_transports" in policy and transport not in allowed_transports: out.append(finding("unapproved_mcp_transport","high",path,f"MCP {name} 使用未批准传输: {transport}"))
    if command and "allowed_mcp_commands" in policy and base not in allowed_commands: out.append(finding("unapproved_mcp_command","high",path,f"MCP 使用未批准命令: {base}"))
    args=[str(x) for x in cfg.get("args",[]) if isinstance(x,(str,int,float))]
    if any(x in ["/","C:\\","$HOME","~"] or x.startswith(("/Users/","/home/")) for x in args): out.append(finding("broad_filesystem_scope","high",path,f"MCP {name} 请求宽泛文件范围"))
    for key,value in (cfg.get("env",{}) or {}).items():
        if re.search(r"TOKEN|SECRET|PASSWORD|API_KEY",str(key),re.I) and value and not re.match(r"^\$\{?[A-Z0-9_]+\}?$",str(value)): out.append(finding("literal_mcp_secret","critical",path,f"MCP {name} 包含明文敏感环境变量: {key}","[REDACTED]"))
    if url:
        try: parsed=urlsplit(url); host=(parsed.hostname or "").lower().rstrip(".")
        except ValueError: return out+[finding("invalid_mcp_url","high",path,f"MCP {name} URL 无法解析")]
        if parsed.scheme!="https": out.append(finding("insecure_mcp_transport","high",path,f"MCP {name} 未使用 HTTPS"))
        if "allowed_mcp_domains" in policy and host not in allowed_domains: out.append(finding("unapproved_mcp_domain","medium",path,f"MCP {name} 连接未批准域名: {host or '[missing]'}"))
        sensitive={"token","key","api_key","apikey","secret","password","access_token"}
        if parsed.username or parsed.password or any(k.lower() in sensitive for k,_ in parse_qsl(parsed.query,keep_blank_values=True)): out.append(finding("mcp_url_credentials","critical",path,f"MCP {name} URL 包含凭据或敏感查询参数","[REDACTED]"))
    if not command and not url: out.append(finding("incomplete_mcp_server","medium",path,f"MCP {name} 未配置命令或 URL"))
    return out
def scan_mcp_config(path,text,policy):
    out=[]
    if path.suffix.lower()==".toml":
        sections=list(re.finditer(r"(?ms)^\[mcp_servers\.([A-Za-z0-9_.-]+)\]\s*(.*?)(?=^\[|\Z)",text))
        for section in sections:
            name=section.group(1); body=section.group(2)
            if name.endswith(".env"): continue
            command_match=re.search(r'(?m)^\s*command\s*=\s*["\']([^"\']+)',body); command=command_match.group(1) if command_match else ""
            url_match=re.search(r'(?m)^\s*url\s*=\s*["\']([^"\']+)',body); url=url_match.group(1) if url_match else ""
            transport_match=re.search(r'(?m)^\s*transport\s*=\s*["\']([^"\']+)',body); transport=transport_match.group(1) if transport_match else ""
            args_match=re.search(r"(?ms)^\s*args\s*=\s*\[(.*?)\]",body); args=re.findall(r'["\']([^"\']+)["\']',args_match.group(1)) if args_match else []
            out.extend(scan_mcp_server(path,name,{"command":command,"url":url,"transport":transport,"args":args},policy))
        for secret in re.finditer(r'(?im)^\s*([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Z0-9_]*)\s*=\s*["\']([^"\']+)',text):
            if not re.match(r"^\$\{?[A-Z0-9_]+\}?$",secret.group(2)): out.append(finding("literal_mcp_secret","critical",path,f"MCP TOML 包含明文敏感环境变量: {secret.group(1)}","[REDACTED]"))
        return out
    if path.suffix.lower()!=".json": return out
    try: data=json.loads(text)
    except json.JSONDecodeError: return [finding("invalid_mcp_config","medium",path,"MCP JSON 配置无法解析")]
    servers=data.get("mcpServers",data.get("servers",{})) if isinstance(data,dict) else {}
    if not isinstance(servers,dict): return out
    for name,cfg in servers.items():
        if not isinstance(cfg,dict): continue
        out.extend(scan_mcp_server(path,name,cfg,policy))
    return out
def scan_dependency_manifest(path,text):
    out=[]
    if path.name=="package.json":
        try: data=json.loads(text)
        except json.JSONDecodeError: return [finding("invalid_dependency_manifest","medium",path,"package.json 无法解析")]
        dependencies={}
        for key in ("dependencies","devDependencies","optionalDependencies","peerDependencies"):
            values=data.get(key,{}) if isinstance(data,dict) else {}
            if isinstance(values,dict): dependencies.update(values)
        for name,raw in dependencies.items():
            version=str(raw).strip(); low=version.lower()
            if re.match(r"^(?:https?://|git(?:\+|://)|github:)",low): out.append(finding("dependency_untrusted_source","high",path,f"依赖 {name} 直接使用远程源码",version[:80]))
            elif low in {"*","latest","next"} or re.match(r"^[~^<>=]",version): out.append(finding("dependency_unpinned","medium",path,f"依赖 {name} 未固定到精确版本",version[:80]))
        locks=("package-lock.json","npm-shrinkwrap.json","pnpm-lock.yaml","yarn.lock","bun.lock","bun.lockb")
        if dependencies and not any((path.parent/x).exists() for x in locks): out.append(finding("missing_lockfile","medium",path,"JavaScript 依赖缺少受支持的锁文件"))
    elif path.name.startswith("requirements") and path.suffix==".txt":
        for line in text.splitlines():
            value=line.strip()
            if not value or value.startswith("#"): continue
            if re.match(r"^(?:-e\s+)?(?:https?://|git\+)",value,re.I): out.append(finding("dependency_untrusted_source","high",path,"Python 依赖直接使用远程源码",value[:80]))
            elif value.startswith(("-r ","--requirement ")): out.append(finding("dependency_external_manifest","medium",path,"Python 依赖引用其他清单，需纳入审核",value[:80]))
            elif "==" not in value: out.append(finding("dependency_unpinned","medium",path,"Python 依赖未固定到精确版本",value[:80]))
    return out
def scan_skill(skill_file,policy,max_files=500):
    """Scan the complete Skill package without following links outside its root."""
    root=skill_file.parent; out=[]; scanned=0; name=root.name
    allowed=set(policy.get("allowed_skills",[]))
    if "allowed_skills" in policy and name not in allowed:
        action=policy.get("enforcement",{}).get("unknown_skill","audit"); severity="high" if action=="block" else "medium"
        out.append(finding("unknown_skill",severity,skill_file,f"未批准的 Skill: {name}"))
    readable={".md",".txt",".py",".js",".ts",".tsx",".jsx",".sh",".ps1",".json",".toml",".yaml",".yml"}
    root_resolved=root.resolve()
    for current,dirs,files in os.walk(root,followlinks=False):
        current_path=Path(current); dirs[:]=[x for x in dirs if x not in [".git","node_modules","vendor","dist","build"]]
        for entry in list(dirs)+files:
            path=current_path/entry
            if path.is_symlink():
                try: path.resolve().relative_to(root_resolved)
                except (OSError,ValueError): out.append(finding("skill_symlink_escape","high",path,"Skill 符号链接指向包目录之外"))
        for filename in files:
            if scanned>=max_files: break
            path=current_path/filename
            if path.is_symlink() or path.suffix.lower() not in readable: continue
            try:
                if path.stat().st_size<=1_000_000:
                    text=path.read_text(errors="ignore"); out.extend(scan_text(path,text,policy))
                    if path.name in DEPENDENCY_MANIFESTS: out.extend(scan_dependency_manifest(path,text))
                    scanned+=1
            except OSError: out.append(finding("unreadable","low",path,"Skill 文件存在但无法读取"))
        if scanned>=max_files: out.append(finding("skill_scan_truncated","medium",root,f"Skill 文件数超过扫描上限 {max_files}")); break
    return out,scanned
def scan(root,policy):
    findings=[]; homes=managed_homes(); inventory=discover_agent_tools(homes)
    skill_seen=set()
    for home in homes:
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
                    skill_root=p.parent.resolve()
                    if skill_root in skill_seen: continue
                    skill_seen.add(skill_root); approved=p.parent.name in set(policy.get("allowed_skills",[]))
                    skill_findings,scanned=scan_skill(p,policy)
                    inventory.append({"type":"skill","name":p.parent.name,"path":safe_path(p),"approved":approved,"scanned_files":scanned})
                    findings.extend(skill_findings)
    suffixes={".py",".js",".ts",".tsx",".jsx",".go",".java",".rb",".php",".sh",".json",".toml",".yaml",".yml"}
    for p in root.rglob("*"):
        if p.is_file() and (p.suffix.lower() in suffixes or p.name in DEPENDENCY_MANIFESTS) and ".git" not in p.parts and "node_modules" not in p.parts:
            try:
                if p.stat().st_size<=1_000_000:
                    text=p.read_text(errors="ignore"); findings.extend(scan_text(p,text,policy))
                    if p.name in ["mcp.json","mcp_config.json","config.toml"]: findings.extend(scan_mcp_config(p,text,policy))
                    if p.name in DEPENDENCY_MANIFESTS: inventory.append({"type":"dependency_manifest","path":safe_path(p)}); findings.extend(scan_dependency_manifest(p,text))
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
def discover_repositories(root,max_depth=4):
    root=root.resolve(); repos=[]
    if (root/".git").exists(): repos.append(root)
    for current,dirs,_files in os.walk(root):
        path=Path(current); depth=len(path.relative_to(root).parts)
        dirs[:]=[d for d in dirs if d not in [".git","node_modules","vendor","dist","build",".venv"] and not d.startswith(".")]
        if depth>=max_depth: dirs[:]=[]
        if (path/".git").exists() and path not in repos: repos.append(path); dirs[:]=[]
    return repos
def auto_enroll(root):
    changed=[]
    for repo in discover_repositories(root): changed.extend(install_baseline(repo))
    return changed
def report_headers(body,token="",secret="",now=None):
    headers={"Content-Type":"application/json","User-Agent":"SentinelAgent/0.11.0"}
    if token: headers["Authorization"]="Bearer "+token
    if secret:
        timestamp=str(int(time.time()) if now is None else now); signed=timestamp.encode()+b"."+body
        headers["X-Sentinel-Timestamp"]=timestamp; headers["X-Sentinel-Signature"]="sha256="+hmac.new(secret.encode(),signed,hashlib.sha256).hexdigest()
    return headers
def post_report(url,token,report):
    if not url: return "disabled"
    body=json.dumps(report,ensure_ascii=False).encode(); headers=report_headers(body,token,os.getenv("SENTINEL_REPORT_SIGNING_SECRET",""))
    request=urllib.request.Request(url,data=body,headers=headers,method="POST")
    with urllib.request.urlopen(request,timeout=15) as response: return str(response.status)
def queue_report(spool,report):
    spool.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(spool,0o700); path=spool/f"{report['scanned_at']}-{report['device_id']}.json"; path.write_text(json.dumps(report,ensure_ascii=False)); os.chmod(path,0o600); return path
def flush_spool(spool,url,token):
    if not spool.exists() or not url: return 0
    sent=0
    for path in sorted(spool.glob("*.json"))[:50]:
        post_report(url,token,json.loads(path.read_text())); path.unlink(); sent+=1
    return sent
def build_report(root,policy):
    inventory,findings=scan(root,policy)
    return {"schema":"sentinel.report/v1","agent_version":"0.11.0","policy_version":policy["version"],"device_id":hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12],"scanned_at":int(time.time()),"scan_root":safe_path(root),"inventory":inventory,"summary":{s:sum(f["severity"]==s for f in findings) for s in ["critical","high","medium","low"]},"findings":findings}
def main():
    ap=argparse.ArgumentParser(description="Sentinel AI Agent 安全扫描器"); ap.add_argument("scan_path",nargs="?",default="."); ap.add_argument("--policy",default=str(DEFAULT_POLICY)); ap.add_argument("--output"); ap.add_argument("--install-baseline",action="store_true"); ap.add_argument("--auto-enroll",action="store_true"); ap.add_argument("--watch",action="store_true"); ap.add_argument("--interval",type=int,default=300); ap.add_argument("--report-url",default=os.getenv("SENTINEL_REPORT_URL","")); ap.add_argument("--spool-dir",default=os.getenv("SENTINEL_SPOOL_DIR","")); args=ap.parse_args()
    policy=json.loads(Path(args.policy).read_text()); root=Path(args.scan_path).resolve()
    if args.install_baseline: install_baseline(root)
    while True:
        if args.auto_enroll: auto_enroll(root)
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
