#!/usr/bin/env python3
"""Aegis endpoint scanner prototype. Standard-library only; read-only by default."""
from __future__ import annotations
import argparse, hashlib, hmac, json, os, re, stat, sys, tempfile, time, urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
DEFAULT_POLICY=Path(__file__).with_name("aegis-policy.json")
AGENT_CONFIGS=[".cursor/mcp.json",".claude.json",".codex/config.toml",".codeium/windsurf/mcp_config.json",".gemini/settings.json",".copilot/mcp-config.json",".workbuddy/mcp.json",".qwenworkcn/mcp.json",".lingma/mcp.json",".codebuddy/mcp.json"]
SKILL_ROOTS=[".codex/skills",".claude/skills",".cursor/skills",".gemini/skills",".copilot/skills",".workbuddy/skills",".qwenworkcn/skills",".lingma/skills",".codebuddy/skills"]
DEPENDENCY_MANIFESTS={"package.json","requirements.txt","requirements-dev.txt"}
REPORT_INVENTORY_LIMIT=5000
REPORT_FINDING_LIMIT=10000
def max_file_bytes(policy):
    raw=policy.get("limits",{}).get("max_file_bytes",1_000_000)
    try: return min(max(int(raw),65_536),10_000_000)
    except (TypeError,ValueError): return 1_000_000
def validate_policy(data):
    if not isinstance(data,dict) or data.get("schema")!="aegis.policy/v1" or not isinstance(data.get("version"),str) or not data["version"]: raise ValueError("invalid_policy_contract")
    if not isinstance(data.get("limits",{}),dict) or not isinstance(data.get("enforcement",{}),dict): raise ValueError("invalid_policy_objects")
    string_lists=("allowed_skills","allowed_mcp_transports","allowed_mcp_servers","allowed_mcp_commands","allowed_mcp_command_paths","allowed_mcp_domains","blocked_commands","secret_patterns","skill_rules","mcp_rules","code_rules")
    for key in string_lists:
        values=data.get(key,[])
        if not isinstance(values,list) or any(not isinstance(value,str) for value in values): raise ValueError("invalid_policy_list:"+key)
    for pattern in data.get("secret_patterns",[]):
        try: re.compile(pattern)
        except re.error as exc: raise ValueError("invalid_policy_regex") from exc
    invocations=data.get("allowed_mcp_invocations",[])
    if not isinstance(invocations,list) or any(not isinstance(item,list) or len(item)<2 or any(not isinstance(value,str) or not value for value in item) for item in invocations): raise ValueError("invalid_mcp_invocations")
    return data
def load_policy(path):
    data=json.loads(Path(path).read_text())
    return validate_policy(data)
def reload_policy(path,current=None):
    try: return load_policy(path),False
    except (OSError,ValueError,RecursionError,UnicodeError): return current,True
AGENT_HOME_MARKERS={
    "cursor":[".cursor/mcp.json","Library/Application Support/Cursor/User/settings.json",".config/Cursor/User/settings.json"],
    "codex":[".codex/config.toml",".local/bin/codex"],
    "claude_code":[".claude.json",".claude/settings.json",".local/bin/claude"],
    "windsurf":[".codeium/windsurf/mcp_config.json","Library/Application Support/Windsurf/User/settings.json",".config/Windsurf/User/settings.json"],
    "gemini_cli":[".gemini/settings.json",".config/gemini/settings.json"],
    "github_copilot_cli":[".copilot/config.json",".copilot/settings.json",".copilot/mcp-config.json",".local/bin/copilot"],
    "qwen_enterprise":[".qwenworkcn","Library/Application Support/QwenWork"],
    "tongyi_lingma":[".lingma",".aliyun/lingma","Library/Application Support/Lingma"],
    "codebuddy":[".codebuddy","Library/Application Support/CodeBuddyExtension"],
}
AGENT_SYSTEM_MARKERS={
    "cursor":["/Applications/Cursor.app","/usr/local/bin/cursor","/opt/homebrew/bin/cursor"],
    "codex":["/usr/local/bin/codex","/opt/homebrew/bin/codex"],
    "claude_code":["/usr/local/bin/claude","/opt/homebrew/bin/claude"],
    "windsurf":["/Applications/Windsurf.app","/usr/local/bin/windsurf","/opt/homebrew/bin/windsurf"],
    "gemini_cli":["/usr/local/bin/gemini","/opt/homebrew/bin/gemini"],
    "github_copilot_cli":["/usr/local/bin/copilot","/opt/homebrew/bin/copilot"],
    "qwen_enterprise":["/Applications/Qwen.app","/Applications/QwenWork.app"],
    "tongyi_lingma":["/Applications/Lingma.app"],
    "codebuddy":["/Applications/CodeBuddy.app"],
}
BASELINE=Path(__file__).with_name("aegis-security-baseline.md")
MANAGED_MARKER="<!-- aegis-managed-baseline -->"
USER_BASELINE_START="<!-- aegis-managed-user-baseline:start -->"
USER_BASELINE_END="<!-- aegis-managed-user-baseline:end -->"
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
    quality_checks=[
        ("insecure_tls_verification","critical",r"(?is)\brequests\.(?:get|post|put|patch|delete|request)\s*\([^)]{0,500}\bverify\s*=\s*false|rejectunauthorized\s*:\s*false|node_tls_reject_unauthorized\s*=\s*['\"]?0"),
        ("unsafe_deserialization","high",r"(?i)\bpickle\.loads?\s*\(|\bbinaryformatter\s*\(|\bobjectinputstream\s*\("),
        ("debug_mode_enabled","medium",r"(?is)\b(?:app|application)\.run\s*\([^)]{0,300}\bdebug\s*=\s*true"),
        ("empty_exception_handler","medium",r"(?m)^\s*except(?:\s+[^:]+)?:\s*(?:#.*\n\s*)?pass\s*$|\bcatch\s*\{\s*\}"),
    ]
    enabled=set(policy.get("code_rules",[]))
    for kind,sev,pat in quality_checks:
        if kind not in enabled: continue
        hit=re.search(pat,text)
        if hit: out.append(finding(kind,sev,path,f"安全代码质量规则命中: {kind}",hit.group(0).strip()[:80]))
    hidden=re.search(r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]",text)
    if hidden: out.append(finding("hidden_instruction","high",path,"包含可隐藏或改变显示方向的 Unicode 控制字符",f"U+{ord(hidden.group(0)):04X}"))
    weak=re.search(r"(?is)(?:token|secret|session|nonce).{0,120}(?:math\.random|random\.random)\s*\(|(?:math\.random|random\.random)\s*\(.{0,120}(?:token|secret|session|nonce)",text)
    if weak: out.append(finding("weak_random_token","high",path,"安全敏感值使用非密码学随机数","weak random generator"))
    for command in policy.get("blocked_commands",[]):
        pattern=re.escape(command.lower()).replace(r"\*",r"[^\r\n]*")
        hit=re.search(r"(?m)^\s*"+pattern+r"(?:\s|$)",low)
        if hit: out.append(finding("blocked_command","high",path,f"命中禁止命令: {command}",hit.group(0).strip()[:80]))
    for pat in policy.get("secret_patterns",[]):
        try: hit=re.search(pat,text)
        except re.error:
            out.append(finding("invalid_policy_regex","high",path,"策略包含无效的敏感信息正则",hashlib.sha256(str(pat).encode()).hexdigest()[:12])); continue
        if hit: out.append(finding("hardcoded_secret","critical",path,"疑似硬编码凭据",hit.group(0)[:8]+"…"))
    return out
def scan_mcp_server(path,name,cfg,policy):
    out=[]; allowed=set(policy.get("allowed_mcp_servers",[])); allowed_commands=set(policy.get("allowed_mcp_commands",[])); allowed_paths={os.path.normcase(os.path.normpath(str(x))) for x in policy.get("allowed_mcp_command_paths",[])}; allowed_domains={x.lower().rstrip(".") for x in policy.get("allowed_mcp_domains",[])}; allowed_transports=set(policy.get("allowed_mcp_transports",[]))
    if "allowed_mcp_servers" in policy and name not in allowed: out.append(finding("unknown_mcp","medium",path,f"未在允许列表中的 MCP Server: {name}"))
    command=str(cfg.get("command","")).strip(); base=re.split(r"[\\/]",command)[-1]
    url=str(cfg.get("url",cfg.get("serverUrl",""))).strip(); explicit=str(cfg.get("transport","")).lower()
    transport=explicit or ("https" if url.startswith("https://") else "http" if url.startswith("http://") else "stdio" if command else "unknown")
    if command and url: out.append(finding("ambiguous_mcp_transport","high",path,f"MCP {name} 同时配置本地命令和远程 URL"))
    if "allowed_mcp_transports" in policy and transport not in allowed_transports: out.append(finding("unapproved_mcp_transport","high",path,f"MCP {name} 使用未批准传输: {transport}"))
    if command and "allowed_mcp_commands" in policy and base not in allowed_commands: out.append(finding("unapproved_mcp_command","high",path,f"MCP 使用未批准命令: {base}"))
    raw_args=cfg.get("args",[])
    if not isinstance(raw_args,list):
        out.append(finding("invalid_mcp_arguments","high",path,f"MCP {name} 的 args 必须是数组")); raw_args=[]
    args=[str(x) for x in raw_args if isinstance(x,(str,int,float))]
    if command and ("/" in command or "\\" in command) and os.path.normcase(os.path.normpath(command)) not in allowed_paths: out.append(finding("unapproved_mcp_command_path","high",path,f"MCP {name} 使用未批准的可执行路径"))
    allowed_invocations={tuple(str(value) for value in item) for item in policy.get("allowed_mcp_invocations",[]) if isinstance(item,list)}
    if command and args and tuple([base]+args) not in allowed_invocations: out.append(finding("unapproved_mcp_invocation","high",path,f"MCP {name} 的命令参数组合未获批准"))
    if any(x in ["/","C:\\","$HOME","~"] or x.startswith(("/Users/","/home/")) for x in args): out.append(finding("broad_filesystem_scope","high",path,f"MCP {name} 请求宽泛文件范围"))
    env=cfg.get("env",{}) or {}
    if not isinstance(env,dict): out.append(finding("invalid_mcp_environment","high",path,f"MCP {name} 的 env 必须是对象")); env={}
    for key,value in env.items():
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
    except (json.JSONDecodeError,RecursionError,ValueError): return [finding("invalid_mcp_config","medium",path,"MCP JSON 配置无法安全解析")]
    if not isinstance(data,dict): return [finding("invalid_mcp_config","medium",path,"MCP JSON 顶层必须是对象")]
    servers=data.get("mcpServers",data.get("servers",{}))
    if not isinstance(servers,dict): return [finding("invalid_mcp_config","medium",path,"MCP Server 集合必须是对象")]
    for name,cfg in servers.items():
        if not isinstance(cfg,dict):
            out.append(finding("invalid_mcp_server","high",path,f"MCP Server {name} 配置必须是对象")); continue
        out.extend(scan_mcp_server(path,name,cfg,policy))
    return out
def scan_dependency_manifest(path,text):
    out=[]
    if path.name=="package.json":
        try: data=json.loads(text)
        except (json.JSONDecodeError,RecursionError,ValueError): return [finding("invalid_dependency_manifest","medium",path,"package.json 无法安全解析")]
        if not isinstance(data,dict): return [finding("invalid_dependency_manifest","medium",path,"package.json 顶层必须是对象")]
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
_SKILL_NET=re.compile(r"\b(curl|wget|fetch\(|requests\.|urllib|https?://|websocket|socket\.)",re.I)
_SKILL_EXEC=re.compile(r"\b(subprocess|os\.system|exec\(|eval\(|bash\s+-c|os\.popen|Popen|shell=True)",re.I)
_SKILL_CRED=re.compile(r"\b(api[_-]?key|secret|password|token|credential|\.env|keychain)",re.I)
_SKILL_FW=re.compile(r"\b(open\([^)]*['\"]w|write\(|rm\s+-|shutil\.rmtree|unlink|remove\()",re.I)
def skill_risk_score(skill_file):
    """Score a Skill package by risk signals: exec+2, cred+2, network+1, filewrite+1."""
    root=skill_file.parent; text=""; 
    readable={".md",".txt",".py",".js",".ts",".tsx",".jsx",".sh",".ps1",".json",".toml",".yaml",".yml"}
    n=0
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=[x for x in dirs if x not in [".git","node_modules","vendor","dist","build"]]
        for f in files:
            if Path(f).suffix.lower() in readable and n<200:
                try: text+=Path(current,f).read_text(errors="ignore")[:200000]; n+=1
                except OSError: pass
    sig={"exec":len(_SKILL_EXEC.findall(text)),"cred":len(_SKILL_CRED.findall(text)),"network":len(_SKILL_NET.findall(text)),"filewrite":len(_SKILL_FW.findall(text))}
    score=(2 if sig["exec"] else 0)+(2 if sig["cred"] else 0)+(1 if sig["network"] else 0)+(1 if sig["filewrite"] else 0)
    return score,sig
SKILL_CATEGORY_RULES={
  "dingtalk-cli":{"label":"钉钉 CLI 集成类","action":"monitor","severity":"medium","tags":["cli","network","credential-pass"],"desc":"通过 dws CLI 调用钉钉 OpenAPI；exec/network/cred 为正常 CLI 调用模式。预制规则: 保持 monitor + 记录每次调用审计; 只读子能力可个案加白, 写操作(审批/写表)保持告警。"},
  "doc-processing":{"label":"文档处理类","action":"monitor","severity":"medium","tags":["filewrite","network-deps"],"desc":"文档读写/转换技能, 含文件写与依赖下载。预制规则: monitor + 锁定版本 + 监控文件写范围; 业务必需可加白+监控。"},
  "cloud-service":{"label":"云服务/平台类","action":"monitor","severity":"medium","tags":["network","cloud-api"],"desc":"调用云平台 API (Pages/Supabase/媒体生成)。预制规则: monitor + 监控外联域名白名单。"},
  "dev-assist":{"label":"开发辅助/方法论类","action":"monitor","severity":"low","tags":["read-mostly"],"desc":"方法论/示例/调试辅助, 以只读为主。预制规则: monitor 低危, 研判后可批量加白。"},
  "unknown":{"label":"未分类","action":"monitor","severity":"medium","tags":[],"desc":"未匹配任何预制类别, 按通用 monitor 处理, 待人工归类。"},
}
def skill_category(name):
    n=(name or "").lower()
    if n.startswith("dingtalk") or n.startswith("dws"): return "dingtalk-cli"
    if any(k in n for k in ["pdf","pptx","xlsx","docx","document","html-markdown"]): return "doc-processing"
    if any(k in n for k in ["qw-pages","supabase","media-generation","mini-program"]): return "cloud-service"
    if any(k in n for k in ["debug","test","standards","java","python","frontend","markdown-lint","bootstrapping","feature-council","deeplearning","create-adaptable","working-with"]): return "dev-assist"
    return "unknown"
def scan_skill(skill_file,policy,max_files=500):
    """Scan the complete Skill package without following links outside its root."""
    root=skill_file.parent; out=[]; scanned=0; name=root.name
    allowed=set(policy.get("allowed_skills",[]))
    if "allowed_skills" in policy and name not in allowed:
        action=policy.get("enforcement",{}).get("unknown_skill","audit")
        score,sig=skill_risk_score(skill_file)
        cat=skill_category(name); rule=SKILL_CATEGORY_RULES.get(cat,SKILL_CATEGORY_RULES["unknown"])
        # severity = max(risk-signal severity, category preset severity)
        sig_sev="high" if score>=4 else ("medium" if score>=2 else "low")
        order={"low":0,"medium":1,"high":2}
        severity=sig_sev if order[sig_sev]>=order[rule["severity"]] else rule["severity"]
        dom=max(sig,key=sig.get)
        out.append(finding("unknown_skill",severity,skill_file,f"未批准的 Skill: {name} [类别:{rule['label']}] (风险信号 {dom}={sig[dom]}, score={score}) 预制规则: {rule['desc']}"))
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
            scanned+=1
            try:
                size=path.stat().st_size
                if size<=max_file_bytes(policy):
                    text=path.read_text(errors="ignore"); out.extend(scan_text(path,text,policy))
                    if path.name in DEPENDENCY_MANIFESTS: out.extend(scan_dependency_manifest(path,text))
                else: out.append(finding("oversized_file_skipped","medium",path,f"Skill 文件超过扫描字节上限 {max_file_bytes(policy)}",str(size)))
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
                    size=p.stat().st_size
                    if size>max_file_bytes(policy): findings.append(finding("oversized_file_skipped","medium",p,f"Agent 配置超过扫描字节上限 {max_file_bytes(policy)}",str(size)))
                    else:
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
    raw_limit=policy.get("limits",{}).get("project_files",10000)
    try: file_limit=min(max(int(raw_limit),100),100000)
    except (TypeError,ValueError): file_limit=10000
    scanned=0; truncated=False
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=[name for name in dirs if name not in [".git","node_modules","vendor","dist","build",".venv"] and not (Path(current)/name).is_symlink()]
        for name in files:
            p=Path(current)/name
            if p.is_symlink() or not (p.suffix.lower() in suffixes or p.name in DEPENDENCY_MANIFESTS): continue
            if scanned>=file_limit: truncated=True; break
            scanned+=1
            try:
                size=p.stat().st_size
                if size<=max_file_bytes(policy):
                    text=p.read_text(errors="ignore"); findings.extend(scan_text(p,text,policy))
                    if p.name in ["mcp.json","mcp_config.json","config.toml"]: findings.extend(scan_mcp_config(p,text,policy))
                    if p.name in DEPENDENCY_MANIFESTS: inventory.append({"type":"dependency_manifest","path":safe_path(p)}); findings.extend(scan_dependency_manifest(p,text))
                else: findings.append(finding("oversized_file_skipped","medium",p,f"代码或配置文件超过扫描字节上限 {max_file_bytes(policy)}",str(size)))
            except OSError: pass
        if truncated: break
    if truncated: findings.append(finding("project_scan_truncated","medium",root,f"项目候选文件超过扫描上限 {file_limit}"))
    return inventory,findings
def safe_managed_target(root,path):
    """Reject symlinks and parent paths that resolve outside the managed root."""
    try:
        root=Path(root).resolve(); path=Path(path)
        path.parent.resolve().relative_to(root)
        return not path.is_symlink()
    except (OSError,ValueError): return False
def install_baseline(root):
    """Install additive, clearly-marked rules without replacing repository guidance."""
    root=Path(root).resolve()
    content=BASELINE.read_text()
    targets=[(root/".cursor/rules/aegis-security.mdc","---\ndescription: 企业安全编码基线\nalwaysApply: true\n---\n"+content),(root/".windsurf/rules/aegis-security.md",content)]
    changed=[]
    for path,data in targets:
        if not safe_managed_target(root,path): continue
        path.parent.mkdir(parents=True,exist_ok=True)
        managed=MANAGED_MARKER+"\n"+data
        if not path.exists() or path.read_text(errors="ignore")!=managed:
            path.write_text(managed); changed.append(str(path))
    for name in ["AGENTS.md","CLAUDE.md"]:
        path=root/name; block=f"\n{MANAGED_MARKER}\n## 企业安全基线\n执行任何代码变更前，必须遵循 [.aegis/SECURITY_BASELINE.md](.aegis/SECURITY_BASELINE.md)。\n"
        if not safe_managed_target(root,path): continue
        current=path.read_text(errors="ignore") if path.exists() else ""
        if MANAGED_MARKER not in current: path.write_text(current.rstrip()+block); changed.append(str(path))
    shared=root/".aegis/SECURITY_BASELINE.md"
    if safe_managed_target(root,shared): shared.parent.mkdir(parents=True,exist_ok=True); shared.write_text(MANAGED_MARKER+"\n"+content)
    return changed
def install_user_baselines(homes=None):
    """Load the baseline into already-present user Agent instruction files."""
    homes=managed_homes() if homes is None else homes; content=BASELINE.read_text().rstrip()
    block=f"{USER_BASELINE_START}\n{content}\n{USER_BASELINE_END}"
    changed=[]
    for home in homes:
        home=Path(home); targets=[]
        if (home/".codex").is_dir(): targets.append(home/".codex/AGENTS.md")
        if (home/".claude").is_dir() or (home/".claude.json").is_file(): targets.append(home/".claude/CLAUDE.md")
        if (home/".workbuddy").is_dir(): targets.append(home/".workbuddy/AGENTS.md")
        if (home/".qwenworkcn").is_dir(): targets.append(home/".qwenworkcn/AGENTS.md")
        if (home/".gemini").is_dir(): targets.append(home/".gemini/GEMINI.md")
        if (home/".copilot").is_dir(): targets.append(home/".copilot/copilot-instructions.md")
        if (home/".lingma").is_dir(): targets.append(home/".lingma/rules.md")
        if (home/".codebuddy").is_dir(): targets.append(home/".codebuddy/rules.md")
        for path in targets:
            if not safe_managed_target(home,path): continue
            path.parent.mkdir(parents=True,exist_ok=True); current=path.read_text(errors="ignore") if path.exists() else ""
            pattern=re.compile(re.escape(USER_BASELINE_START)+r".*?"+re.escape(USER_BASELINE_END),re.S)
            updated=pattern.sub(block,current) if pattern.search(current) else current.rstrip()+("\n\n" if current.strip() else "")+block+"\n"
            if updated!=current:
                path.write_text(updated)
                if hasattr(os,"geteuid") and os.geteuid()==0:
                    try: owner=home.stat(); os.chown(path,owner.st_uid,owner.st_gid)
                    except OSError: pass
                changed.append(str(path))
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
    changed=install_user_baselines()
    for repo in discover_repositories(root): changed.extend(install_baseline(repo))
    return changed
def verify_user_baselines(homes=None):
    """Return privacy-minimized evidence that detected user Agents loaded the managed block."""
    homes=managed_homes() if homes is None else homes
    try: expected=BASELINE.read_text().rstrip()
    except OSError: return [],[]
    inventory=[];findings=[]
    targets={"codex":(".codex",".codex/AGENTS.md"),"claude_code":((".claude",".claude.json"),".claude/CLAUDE.md"),"workbuddy":(".workbuddy",".workbuddy/AGENTS.md"),"gemini_cli":(".gemini",".gemini/GEMINI.md"),"github_copilot_cli":(".copilot",".copilot/copilot-instructions.md"),"qwen_enterprise":(".qwenworkcn",".qwenworkcn/AGENTS.md"),"tongyi_lingma":(".lingma",".lingma/rules.md"),"codebuddy":(".codebuddy",".codebuddy/rules.md")}
    for home in homes:
        home=Path(home)
        if home.is_symlink() or not home.is_dir(): continue
        for agent,(markers,relative) in targets.items():
            markers=(markers,) if isinstance(markers,str) else markers
            if not any((home/m).exists() for m in markers): continue
            path=home/relative; status="missing"
            if not safe_managed_target(home,path): status="unsafe"
            elif path.is_file():
                try:
                    text=path.read_text(errors="ignore"); starts=text.count(USER_BASELINE_START); ends=text.count(USER_BASELINE_END)
                    match=re.search(re.escape(USER_BASELINE_START)+r"\n(.*?)\n"+re.escape(USER_BASELINE_END),text,re.S)
                    status="managed" if starts==1 and ends==1 and match and match.group(1).rstrip()==expected else "malformed"
                except OSError: status="unreadable"
            inventory.append({"type":"agent_baseline","name":agent,"status":status,"scope":"user"})
            if status!="managed": findings.append(finding("agent_baseline_not_loaded","high",path,f"{agent} 已发现但企业安全基线未处于受管状态",status))
    return inventory,findings
def load_reporting_config(path):
    path=Path(path)
    if path.is_symlink(): raise ValueError("reporting_config_symlink")
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077: raise ValueError("reporting_config_permissions")
    if hasattr(os,"geteuid") and info.st_uid not in {0,os.geteuid()}: raise ValueError("reporting_config_owner")
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict) or set(value)!={"schema","report_url","report_token","signing_secret"} or value.get("schema")!="aegis.reporting/v1": raise ValueError("reporting_config_contract")
    parsed=urlsplit(value.get("report_url",""))
    if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or len(value["report_url"])>2048: raise ValueError("reporting_config_url")
    token=value.get("report_token"); secret=value.get("signing_secret")
    if not isinstance(token,str) or not isinstance(secret,str) or not 32<=len(token)<=4096 or not 32<=len(secret)<=4096 or hmac.compare_digest(token,secret): raise ValueError("reporting_config_secrets")
    return value
def report_headers(body,token="",secret="",now=None,device_id=""):
    headers={"Content-Type":"application/json","User-Agent":"AegisAgent/0.30.0"}
    if token: headers["Authorization"]="Bearer "+token
    if device_id:
        if not isinstance(device_id,str) or not re.fullmatch(r"[A-Za-z0-9._-]{8,128}",device_id): raise ValueError("invalid_report_device_id")
        headers["X-Aegis-Device-ID"]=device_id
    if secret:
        timestamp=str(int(time.time()) if now is None else now); signed=timestamp.encode()+b"."+(device_id.encode()+b"." if device_id else b"")+body
        headers["X-Aegis-Timestamp"]=timestamp; headers["X-Aegis-Signature"]="sha256="+hmac.new(secret.encode(),signed,hashlib.sha256).hexdigest()
    return headers
def post_report(url,token,report,signing_secret=None):
    if not url: return "disabled"
    body=json.dumps(report,ensure_ascii=False).encode(); headers=report_headers(body,token,os.getenv("AEGIS_REPORT_SIGNING_SECRET","") if signing_secret is None else signing_secret,device_id=report.get("device_id","") if isinstance(report,dict) else "")
    request=urllib.request.Request(url,data=body,headers=headers,method="POST")
    with urllib.request.urlopen(request,timeout=15) as response:
        if response.status not in {200,202}: raise OSError("collector_delivery_not_accepted")
        raw=response.read(4097)
    if len(raw)>4096: raise OSError("collector_ack_too_large")
    try: ack=json.loads(raw)
    except (json.JSONDecodeError,UnicodeDecodeError,RecursionError,ValueError) as exc: raise OSError("collector_ack_invalid_json") from exc
    expected_report_id=hashlib.sha256(body).hexdigest()[:20]
    if not isinstance(ack,dict) or set(ack)!={"accepted","duplicate","report_id","severity"} or ack.get("accepted") is not True or type(ack.get("duplicate")) is not bool or ack.get("report_id")!=expected_report_id or ack.get("severity") not in {"critical","high","normal"}: raise OSError("collector_ack_invalid_contract")
    return ack
def spool_limit(value=None):
    raw=os.getenv("AEGIS_SPOOL_MAX_REPORTS","500") if value is None else value
    try: return min(max(int(raw),10),10000)
    except (TypeError,ValueError): return 500
def write_private_atomic(path,data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp_name=tempfile.mkstemp(prefix="."+path.name+".",suffix=".tmp",dir=path.parent); temp=Path(temp_name)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.chmod(temp,0o600); os.replace(temp,path)
    except Exception:
        try: os.close(fd)
        except OSError: pass
        temp.unlink(missing_ok=True); raise
    return path
def queue_report(spool,report,limit=None):
    spool.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(spool,0o700)
    data=json.dumps(report,ensure_ascii=False,separators=(",",":")); digest=hashlib.sha256(data.encode()).hexdigest()[:12]
    path=spool/f"{report['scanned_at']}-{report['device_id']}-{time.time_ns()}-{digest}.json"; write_private_atomic(path,data)
    files=sorted(spool.glob("*.json"),key=lambda item:(item.stat().st_mtime_ns,item.name)); keep=spool_limit(limit)
    for expired in files[:-keep]: expired.unlink()
    return path
def flush_spool(spool,url,token,signing_secret=None):
    if not spool.exists() or not url: return 0
    sent=0
    for path in sorted(spool.glob("*.json"))[:50]:
        try: report=json.loads(path.read_text())
        except (OSError,json.JSONDecodeError,UnicodeDecodeError,RecursionError,ValueError):
            invalid=path.with_name(path.name+f".{time.time_ns()}.invalid"); path.rename(invalid); os.chmod(invalid,0o600); continue
        post_report(url,token,report,signing_secret); path.unlink(); sent+=1
    return sent
def write_upload_status(path,url,now=None):
    host=urlsplit(url).hostname
    if not host: raise ValueError("invalid_upload_status_host")
    value={"schema":"aegis.upload-status/v1","status":"accepted","last_success":int(time.time()) if now is None else int(now),"collector_host":host.lower().rstrip(".")}
    return write_private_atomic(path,json.dumps(value,separators=(",",":")))
def build_report(root,policy):
    inventory,findings=scan(root,policy)
    baseline_inv,baseline_findings=verify_user_baselines()
    inventory.extend(baseline_inv); findings.extend(baseline_findings)
    if len(inventory)>REPORT_INVENTORY_LIMIT:
        inventory=inventory[:REPORT_INVENTORY_LIMIT-1]+[{"type":"inventory_truncated","omitted":len(inventory)-REPORT_INVENTORY_LIMIT+1}]
    if len(findings)>REPORT_FINDING_LIMIT:
        omitted=len(findings)-REPORT_FINDING_LIMIT+1; findings=findings[:REPORT_FINDING_LIMIT-1]+[finding("findings_truncated","medium",root,f"报告发现项超限，省略 {omitted} 项")]
    return {"schema":"aegis.report/v1","agent_version":AGENT_VERSION,"policy_version":policy["version"],"device_id":hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12],"hostname":os.uname().nodename,"os_user":(os.environ.get("USER") or os.environ.get("LOGNAME") or os.environ.get("USERNAME") or "unknown"),"scanned_at":int(time.time()),"scan_root":safe_path(root),"inventory":inventory,"summary":{s:sum(f["severity"]==s for f in findings) for s in ["critical","high","medium","low"]},"findings":findings}
def add_report_finding(report,item):
    if len(report["findings"])<REPORT_FINDING_LIMIT: report["findings"].append(item)
    else: report["findings"][-1]=item
    report["summary"]={severity:sum(f["severity"]==severity for f in report["findings"]) for severity in ["critical","high","medium","low"]}
AGENT_VERSION = "0.31.0"


def maybe_self_update(policy, report_url):
    """无桌管环境的自更新兜底通道；主通道永远是桌管/MDM 推送。

    仅当策略 agent_self_update.enabled=true 且能推导 manifest URL 时执行。
    best-effort：任何失败静默返回，绝不影响本轮扫描/上报。
    """
    cfg = policy.get("agent_self_update") if isinstance(policy, dict) else None
    if not isinstance(cfg, dict) or cfg.get("enabled") is not True:
        return
    manifest_url = cfg.get("manifest_url") or ""
    if not manifest_url and report_url and "/api/" in report_url:
        manifest_url = report_url.split("/api/")[0] + "/downloads/update-manifest.json"
    if not manifest_url:
        return
    try:
        script_dir = str(Path(__file__).resolve().parent)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import aegis_self_update as su
    except Exception:
        return
    device_id = hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12]
    try:
        res = su.check_and_apply(
            manifest_url,
            AGENT_VERSION,
            device_id,
            "aegis_agent.py",
            str(Path(__file__).resolve()),
            rollout_percent=int(cfg.get("rollout_percent", 100)),
        )
        if res.get("updated"):
            print(f"aegis agent self-updated {res.get('from')} -> {res.get('to')}; next run uses new version", file=sys.stderr)
    except Exception:
        return


def main():
    ap=argparse.ArgumentParser(description="Aegis AI Agent 安全扫描器"); ap.add_argument("scan_path",nargs="?",default="."); ap.add_argument("--policy",default=str(DEFAULT_POLICY)); ap.add_argument("--output"); ap.add_argument("--install-baseline",action="store_true"); ap.add_argument("--auto-enroll",action="store_true"); ap.add_argument("--watch",action="store_true"); ap.add_argument("--interval",type=int,default=300); ap.add_argument("--report-url",default=os.getenv("AEGIS_REPORT_URL","")); ap.add_argument("--report-config",default=os.getenv("AEGIS_REPORT_CONFIG","")); ap.add_argument("--spool-dir",default=os.getenv("AEGIS_SPOOL_DIR","")); args=ap.parse_args()
    if not args.report_config:
        candidate=Path(__file__).with_name("reporting.json")
        if candidate.is_file(): args.report_config=str(candidate)
    policy,policy_error=reload_policy(args.policy); root=Path(args.scan_path).resolve()
    if policy_error or policy is None: raise SystemExit("valid Aegis policy is required")
    maybe_self_update(policy, args.report_url)
    reporting=None; reporting_error=False
    if args.report_config:
        try: reporting=load_reporting_config(args.report_config); args.report_url=reporting["report_url"]
        except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): reporting_error=True; args.report_url=""
    if args.install_baseline: install_baseline(root)
    while True:
        policy,reload_failed=reload_policy(args.policy,policy)
        if args.auto_enroll: auto_enroll(root)
        report=build_report(root,policy); data=json.dumps(report,ensure_ascii=False,indent=2)
        if reload_failed:
            add_report_finding(report,finding("policy_reload_failed","high",args.policy,"策略热加载失败，继续使用上一份有效策略")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if reporting_error:
            add_report_finding(report,finding("reporting_config_invalid","high",args.report_config,"受保护上报配置权限、所有者或契约无效；本轮拒绝上报")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if args.output: write_private_atomic(args.output,data)
        if args.report_url:
            token=reporting["report_token"] if reporting else os.getenv("AEGIS_REPORT_TOKEN",""); signing=reporting["signing_secret"] if reporting else None; spool=Path(args.spool_dir) if args.spool_dir else (Path(args.output).parent/"spool" if args.output else Path.home()/".aegis-agent/spool")
            status_path=(Path(args.output).parent if args.output else spool.parent)/"upload-status.json"
            try: flush_spool(spool,args.report_url,token,signing); post_report(args.report_url,token,report,signing); write_upload_status(status_path,args.report_url)
            except Exception as exc: queue_report(spool,report); print(f"report upload failed; queued locally: {exc}",file=sys.stderr)
        print(data)
        if not args.watch: return 2 if report["summary"]["critical"] or report["summary"]["high"] else 0
        time.sleep(max(args.interval,60))
if __name__=="__main__": sys.exit(main())
