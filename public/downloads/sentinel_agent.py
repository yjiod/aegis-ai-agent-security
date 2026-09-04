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
def finding(kind,severity,path,message,evidence=""): return {"kind":kind,"severity":severity,"path":str(path),"message":message,"evidence":evidence[:180]}
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
def scan(root,policy):
    findings=[]; inventory=[]
    for home in managed_homes():
        for rel in AGENT_CONFIGS:
            p=home/rel
            if p.exists():
                inventory.append({"type":"agent_config","path":str(p)})
                try: findings.extend(scan_text(p,p.read_text(errors="ignore"),policy))
                except OSError: findings.append(finding("unreadable","low",p,"配置存在但无法读取"))
        for rel in SKILL_ROOTS:
            d=home/rel
            if d.exists():
                for p in d.rglob("SKILL.md"):
                    if ".system" in p.parts: continue
                    inventory.append({"type":"skill","path":str(p)})
                    try: findings.extend(scan_text(p,p.read_text(errors="ignore"),policy))
                    except OSError: pass
    suffixes={".py",".js",".ts",".tsx",".jsx",".go",".java",".rb",".php",".sh",".json",".toml",".yaml",".yml"}
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in suffixes and ".git" not in p.parts and "node_modules" not in p.parts:
            try:
                if p.stat().st_size<=1_000_000: findings.extend(scan_text(p,p.read_text(errors="ignore"),policy))
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
def build_report(root,policy):
    inventory,findings=scan(root,policy)
    return {"schema":"sentinel.report/v1","agent_version":"0.3.0","policy_version":policy["version"],"device_id":hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12],"scanned_at":int(time.time()),"scan_root":str(root),"inventory":inventory,"summary":{s:sum(f["severity"]==s for f in findings) for s in ["critical","high","medium","low"]},"findings":findings}
def main():
    ap=argparse.ArgumentParser(description="Sentinel AI Agent 安全扫描器"); ap.add_argument("scan_path",nargs="?",default="."); ap.add_argument("--policy",default=str(DEFAULT_POLICY)); ap.add_argument("--output"); ap.add_argument("--install-baseline",action="store_true"); ap.add_argument("--watch",action="store_true"); ap.add_argument("--interval",type=int,default=300); ap.add_argument("--report-url",default=os.getenv("SENTINEL_REPORT_URL","")); args=ap.parse_args()
    policy=json.loads(Path(args.policy).read_text()); root=Path(args.scan_path).resolve()
    if args.install_baseline: install_baseline(root)
    while True:
        report=build_report(root,policy); data=json.dumps(report,ensure_ascii=False,indent=2)
        if args.output: Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(data)
        if args.report_url:
            try: post_report(args.report_url,os.getenv("SENTINEL_REPORT_TOKEN",""),report)
            except Exception as exc: print(f"report upload failed: {exc}",file=sys.stderr)
        print(data)
        if not args.watch: return 2 if report["summary"]["critical"] or report["summary"]["high"] else 0
        time.sleep(max(args.interval,60))
if __name__=="__main__": sys.exit(main())
