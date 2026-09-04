#!/usr/bin/env python3
"""Sentinel endpoint scanner prototype. Standard-library only; read-only by default."""
from __future__ import annotations
import argparse, hashlib, json, os, re, sys, time
from pathlib import Path
DEFAULT_POLICY=Path(__file__).with_name("sentinel-policy.json")
AGENT_CONFIGS=[".cursor/mcp.json",".claude.json",".codex/config.toml",".codeium/windsurf/mcp_config.json"]
SKILL_ROOTS=[".codex/skills",".claude/skills",".cursor/skills"]
def finding(kind,severity,path,message,evidence=""): return {"kind":kind,"severity":severity,"path":str(path),"message":message,"evidence":evidence[:180]}
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
    findings=[]; inventory=[]; home=Path.home()
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
def main():
    ap=argparse.ArgumentParser(description="Sentinel AI Agent 安全扫描器（只读原型）"); ap.add_argument("scan_path",nargs="?",default="."); ap.add_argument("--policy",default=str(DEFAULT_POLICY)); ap.add_argument("--output"); args=ap.parse_args()
    policy=json.loads(Path(args.policy).read_text()); root=Path(args.scan_path).resolve(); inventory,findings=scan(root,policy)
    report={"schema":"sentinel.report/v1","agent_version":"0.1.0","policy_version":policy["version"],"device_id":hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12],"scanned_at":int(time.time()),"scan_root":str(root),"inventory":inventory,"summary":{s:sum(f["severity"]==s for f in findings) for s in ["critical","high","medium","low"]},"findings":findings}
    data=json.dumps(report,ensure_ascii=False,indent=2)
    if args.output: Path(args.output).write_text(data)
    print(data); return 2 if report["summary"]["critical"] or report["summary"]["high"] else 0
if __name__=="__main__": sys.exit(main())
