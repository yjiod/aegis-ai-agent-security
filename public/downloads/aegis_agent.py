#!/usr/bin/env python3
"""Aegis endpoint scanner prototype. Standard-library only; read-only by default."""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, os, platform, re, stat, subprocess, sys, tempfile, time, urllib.request
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
def canonical_json(obj):
    # 必须与控制台 lib/policy.ts 的 canonicalJson 逐字节一致：递归排序 key + 紧凑分隔符 + 不转义非 ASCII。
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False)
def policy_verify_keyring():
    # 多钥验签环：AEGIS_POLICY_VERIFY_KEYS(JSON {key_id:secret}) 优先；回退单钥 AEGIS_POLICY_VERIFY_KEY。
    raw=os.getenv("AEGIS_POLICY_VERIFY_KEYS","")
    ring={}
    if raw:
        try:
            parsed=json.loads(raw)
            if isinstance(parsed,dict): ring={str(k):v for k,v in parsed.items() if isinstance(v,str) and v}
        except (ValueError,TypeError): ring={}
    if not ring:
        single=os.getenv("AEGIS_POLICY_VERIFY_KEY","")
        if single: ring={"default":single}
    return ring
def verify_policy_signature(data,key_or_ring=None):
    sig=data.get("signature")
    if not isinstance(sig,str) or not sig: return False
    if isinstance(key_or_ring,str): ring={"default":key_or_ring} if key_or_ring else {}
    elif isinstance(key_or_ring,dict): ring={k:v for k,v in key_or_ring.items() if isinstance(v,str) and v}
    else: ring=policy_verify_keyring()
    if not ring: return False
    # 批3 dual-sign：剔除 HMAC 签名/密钥id 以及 Ed25519 附加字段后再规范化，
    # 使双签工件的 HMAC 验签与仅-HMAC 工件一致（Ed25519 独立验签为后续能力）。
    body={k:v for k,v in data.items() if k not in ("signature","signing_key_id","ed25519_signature","ed25519_public","ed25519_key_id")}
    canon=canonical_json(body).encode("utf-8")
    kid=data.get("signing_key_id")
    order=[]
    if isinstance(kid,str) and kid in ring: order.append(kid)
    order+=[k for k in ring if k not in order]
    for k in order:
        if hmac.compare_digest(hmac.new(ring[k].encode(),canon,hashlib.sha256).hexdigest(),sig): return True
    return False

# ── Ed25519 (RFC8032) 纯 Python 验签（批3：终端独立验签）────────────────
# 仅验签（不签名），默认只在发布件携带 ed25519_* 字段时启用；用 unittest 的
# OpenSSL 生成向量验证本实现的正确性。公钥来自发布件 ed25519_public（base64）。
_ED_P = (1 << 255) - 19
_ED_L = 7237005577332262213973186563042994240857116359379907606001950938285454250989
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
def _ed_recover_x(y, sign):
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if x % 2 != sign:
        x = _ED_P - x
    return x
def _ed_decode_point(b):
    if len(b) != 32: return None
    y = int.from_bytes(b, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _ED_P: return None
    x = _ed_recover_x(y, sign)
    if (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_P != 0: return None
    return (x, y, 1, (x * y) % _ED_P)
_ED_BY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
_ED_B = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_P)
def _ed_add(P, Q):
    x1, y1, z1, t1 = P; x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (2 * t1 * t2 * _ED_D) % _ED_P
    dd = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P; f = (dd - c) % _ED_P; g = (dd + c) % _ED_P; h = (b + a) % _ED_P
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)
def _ed_mult(P, e):
    R = (0, 1, 1, 0)
    while e > 0:
        if e & 1: R = _ed_add(R, P)
        P = _ed_add(P, P)
        e >>= 1
    return R
def _ed_equal(P, Q):
    x1, y1, z1, _t1 = P; x2, y2, z2, _t2 = Q
    return (x1 * z2 - x2 * z1) % _ED_P == 0 and (y1 * z2 - y2 * z1) % _ED_P == 0
def ed25519_verify(pub, msg, sig):
    """RFC8032 Ed25519 验签（纯 Python，仅验签）。pub/msg/sig 为 bytes。"""
    if len(sig) != 64 or len(pub) != 32: return False
    R = _ed_decode_point(sig[:32]); A = _ed_decode_point(pub)
    if R is None or A is None: return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _ED_L: return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _ED_L
    return _ed_equal(_ed_mult(_ED_B, S), _ed_add(R, _ed_mult(A, k)))
def verify_policy_ed25519(data):
    """发布件携带 ed25519_* 时独立验签：Ed 签名覆盖"不含 ed 字段"的 canonical。
    返回 True/False；无 ed 字段返回 None（调用方回落 HMAC 验签）。"""
    pub = data.get("ed25519_public"); sig = data.get("ed25519_signature")
    if not (isinstance(pub, str) and pub and isinstance(sig, str) and sig): return None
    try:
        pub_b = base64.b64decode(pub); sig_b = base64.b64decode(sig)
    except Exception:
        return False
    body = {k: v for k, v in data.items() if k not in ("ed25519_signature", "ed25519_public", "ed25519_key_id")}
    return ed25519_verify(pub_b, canonical_json(body).encode("utf-8"), sig_b)
def load_policy(path,verify_key=None,require_signature=False):
    data=json.loads(Path(path).read_text())
    data=validate_policy(data)
    if "signature" in data:
        ring={"default":verify_key} if verify_key else policy_verify_keyring()
        if not ring: raise ValueError("policy_signed_but_no_verify_key")
        if not verify_policy_signature(data,ring): raise ValueError("policy_signature_invalid")
    elif require_signature:
        # fail-closed：要求已签名时，缺签名字段即拒绝——防止能写本地策略文件的攻击者
        # 丢掉签名、放宽 blocked_commands/allowed_* 来静默降级强制力。require 标志只来自
        # 带外可信源（入网配置/env），绝不来自（可能未签名的）策略体本身。
        raise ValueError("policy_signature_required")
    # 批3：发布件携带 ed25519_* 时独立验签（在 HMAC 校验之后附加）；无 ed 字段返回 None 回落。
    ed = verify_policy_ed25519(data)
    if ed is False: raise ValueError("policy_ed25519_invalid")
    return data
def reload_policy(path,current=None,verify_key=None,require_signature=False):
    try: return load_policy(path,verify_key,require_signature),False
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
def finding(kind,severity,path,message,evidence="",asset_type="",asset_key=""):
    f={"kind":kind,"severity":severity,"path":safe_path(path),"message":message,"evidence":evidence[:180]}
    # 显式同源键：asset_type/asset_key 让控制台把 finding 与处置标签(asset_labels)按
    # (类型,名字)精确关联——此前 finding 只有文件 path，与 label 的 asset_key(名字)口径不一致，
    # 导致"加白后抑制告警/自动消除同源工单"无法可靠匹配。
    if asset_type: f["asset_type"]=asset_type
    if asset_key: f["asset_key"]=str(asset_key)[:128]
    return f
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
    mode = policy.get("scan_mode", "standard")
    if mode == "quick":
        enabled = set()
    elif mode == "custom":
        enabled = set(policy.get("custom_baseline_rules", []))
        if not enabled: enabled = set(policy.get("code_rules", []))  # fail-safe：custom 规则为空时回落，绝不静默关闭扫描
    else:
        enabled = set(policy.get("code_rules", []))
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
    for f in out: f["asset_type"]="mcp"; f["asset_key"]=str(name)[:128]
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
    """Score a Skill package by risk signals: exec+2, cred+2, network+1, filewrite+1.

    同时回收每类能力命中的"证据位置"(相对文件:行号:该行片段)，供控制台"详细信息"
    展开——让安全运营核对到底是技能包里哪个 .md/.py 的哪一处字段触发了计数，判断是
    真命中还是文档里的无害提及，避免误伤。sig 仍是全量命中处数(与旧口径一致)，证据
    samples 是有界样本(每类≤8、总≤32)，绝不无限膨胀报告。逐文件计数等价于旧的拼接计数
    (正则均为词边界匹配，不跨文件)，但能给出准确文件/行号。
    """
    root=skill_file.parent
    readable={".md",".txt",".py",".js",".ts",".tsx",".jsx",".sh",".ps1",".json",".toml",".yaml",".yml"}
    pats=(("exec",_SKILL_EXEC),("cred",_SKILL_CRED),("network",_SKILL_NET),("filewrite",_SKILL_FW))
    sig={"exec":0,"cred":0,"network":0,"filewrite":0}
    samples=[]; per_cap={"exec":0,"cred":0,"network":0,"filewrite":0}
    PER_CAP=8; TOTAL=32; n=0
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=[x for x in dirs if x not in [".git","node_modules","vendor","dist","build"]]
        for f in files:
            if Path(f).suffix.lower() not in readable or n>=200: continue
            fp=Path(current,f)
            try: text=fp.read_text(errors="ignore")[:200000]
            except OSError: continue
            n+=1
            try: rel=str(fp.relative_to(root))
            except ValueError: rel=f
            rel=rel[:512]; lines=text.split("\n")
            for cap,pat in pats:
                for m in pat.finditer(text):
                    sig[cap]+=1
                    if per_cap[cap]<PER_CAP and len(samples)<TOTAL:
                        per_cap[cap]+=1
                        ln=text.count("\n",0,m.start())+1
                        snippet=(lines[ln-1].strip() if 1<=ln<=len(lines) else m.group(0))[:160]
                        samples.append({"cap":cap,"file":rel,"line":ln,"text":snippet})
    score=(2 if sig["exec"] else 0)+(2 if sig["cred"] else 0)+(1 if sig["network"] else 0)+(1 if sig["filewrite"] else 0)
    return score,sig,samples
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
        score,sig,samples=skill_risk_score(skill_file)
        cat=skill_category(name); rule=SKILL_CATEGORY_RULES.get(cat,SKILL_CATEGORY_RULES["unknown"])
        # severity = max(risk-signal severity, category preset severity)
        sig_sev="high" if score>=4 else ("medium" if score>=2 else "low")
        order={"low":0,"medium":1,"high":2}
        severity=sig_sev if order[sig_sev]>=order[rule["severity"]] else rule["severity"]
        dom=max(sig,key=sig.get)
        f=finding("unknown_skill",severity,skill_file,f"未批准的 Skill: {name} [类别:{rule['label']}] (风险信号 {dom}={sig[dom]}, score={score}) 预制规则: {rule['desc']}")
        # 结构化证据：四类能力的全量命中处数 + 综合分 + 有界命中位置样本，
        # 供控制台"详细信息"展开核对到底是哪个 .md/.py 的哪一行触发了计数（避免误伤）。
        f["signal_matches"]={"counts":sig,"score":score,"samples":samples}
        out.append(f)
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
    for f in out: f["asset_type"]="skill"; f["asset_key"]=str(name)[:128]
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
        # 剪枝：跳过 .git/node_modules 等、符号链接、以及**子目录挂载点**（网络/合成/
        # FUSE 文件系统可能无限期阻塞 opendir/open，曾导致 watch 模式挂死）。根目录本身不剪。
        dirs[:]=[name for name in dirs if name not in [".git","node_modules","vendor","dist","build",".venv"] and not (Path(current)/name).is_symlink() and not os.path.ismount(os.path.join(current,name))]
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
    """Install additive, clearly-marked rules without replacing repository guidance.
    内容=内置/上游基线 + 企业级 MD（附加合并，互不覆盖）。"""
    root=Path(root).resolve()
    content=effective_baseline()+"\n"
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
    """Load the baseline into already-present user Agent instruction files.
    内容=内置/上游基线 + 企业级 MD（effective_baseline，附加合并）——必须与
    verify_user_baselines 的期望一致，否则企业 MD 落盘后用户级基线会被判 malformed。"""
    homes=managed_homes() if homes is None else homes; content=effective_baseline()
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
            # 用「函数式 repl」而非字符串 repl：block 含企业级 MD 正文，其中常有正则/代码示例
            # 的反斜杠序列（\d \w \. \b）。字符串 repl 会被 re.sub 当替换模板解析 →
            # `\d`/`\w` 抛 PatternError: bad escape（注入整体失败，企业 MD 永远进不了工具指令文件），
            # `\b` 静默变成退格符（内容损坏）。lambda repl 原样返回 block，彻底规避转义解析。
            updated=pattern.sub(lambda _m: block,current) if pattern.search(current) else current.rstrip()+("\n\n" if current.strip() else "")+block+"\n"
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
    try: expected=effective_baseline()
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
def load_enrollment_config(path):
    # 每设备入网凭据(aegis.device-enrollment/v1)：与全网 reporting 配置同等加固，
    # 但绑定单一 device_id，使每台终端只持有自己的 token/secret（不再全网共享密钥）。
    path=Path(path)
    if path.is_symlink(): raise ValueError("enrollment_config_symlink")
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077: raise ValueError("enrollment_config_permissions")
    if hasattr(os,"geteuid") and info.st_uid not in {0,os.geteuid()}: raise ValueError("enrollment_config_owner")
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict) or (set(value)-{"require_signed_policy","department"})!={"schema","device_id","report_token","signing_secret"} or value.get("schema")!="aegis.device-enrollment/v1": raise ValueError("enrollment_config_contract")
    if "require_signed_policy" in value and not isinstance(value["require_signed_policy"],bool): raise ValueError("enrollment_config_contract")
    if "department" in value and not isinstance(value["department"],str): raise ValueError("enrollment_config_contract")
    if not isinstance(value.get("device_id"),str) or not re.fullmatch(r"[0-9a-f]{12}",value["device_id"]): raise ValueError("enrollment_config_device_id")
    token=value.get("report_token"); secret=value.get("signing_secret")
    if not isinstance(token,str) or not isinstance(secret,str) or not 32<=len(token)<=4096 or not 32<=len(secret)<=4096 or hmac.compare_digest(token,secret): raise ValueError("enrollment_config_secrets")
    return value
def report_headers(body,token="",secret="",now=None,device_id=""):
    headers={"Content-Type":"application/json","User-Agent":f"AegisAgent/{AGENT_VERSION}"}
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
def hardware_serial():
    """稳定硬件标识（不随 hostname/升级/系统语言变化）：
    mac = IOPlatformSerialNumber（ioreg IOPlatformExpertDevice，输出与系统语言无关）；
    win = 机器序列号（Win32_ComputerSystemProduct.IdentifyingNumber → Win32_BIOS.SerialNumber）；
    linux = /etc/machine-id。失败返回空串（调用方回落）。
    历史缺陷：mac 曾用 ioreg -c IOPlatformExpert(类名错) + system_profiler 英文正则，
    中文系统输出"序列号 (系统):"匹配不到 → 序列号空 → 回落 hostname → 同一台机器换名/升级
    后产生"新终端"(重复设备)。现统一按序列号识别（用户要求）。"""
    import platform
    _BAD = {"", "to be filled by o.e.m.", "none", "default string", "unknown", "o.e.m.", "not specified"}
    try:
        sysname = platform.system()
        if sysname == "Darwin":
            # IOPlatformExpertDevice 类的 IOPlatformSerialNumber 不受 locale 影响，作为首选。
            out = subprocess.run(["ioreg", "-c", "IOPlatformExpertDevice"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r'IOPlatformSerialNumber"\s*=\s*"([^"]+)"', out)
            if m and m.group(1).strip().lower() not in _BAD:
                return m.group(1).strip()
            # 兜底：system_profiler，兼容中/英文标签（"Serial Number (system):" / "序列号 (系统):"）。
            sp = subprocess.run(["system_profiler", "SPHardwareDataType"], capture_output=True, text=True, timeout=30).stdout
            m = re.search(r'(?:Serial Number|序列号)\s*(?:\(system\)|（系统）)?\s*[:：]\s*([A-Za-z0-9]+)', sp)
            if m and m.group(1).strip().lower() not in _BAD:
                return m.group(1).strip()
        elif sysname == "Linux":
            for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                if os.path.exists(p):
                    v = open(p).read().strip()
                    if v:
                        return v
        elif sysname == "Windows":
            ps = ("try{$s=(Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber}catch{$s=$null};"
                  "if(-not $s){try{$s=(Get-CimInstance Win32_BIOS).SerialNumber}catch{$s=$null}};"
                  "if($s){$s.Trim()}else{''}")
            v = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=20).stdout.strip()
            if v.lower() not in _BAD:
                return v
    except Exception:
        return ""
    return ""
def interactive_os_user():
    """上报"实际使用者"：优先环境变量；以 root/守护进程运行时 env 无真实用户，
    多级回落交互控制台登录用户，避免 owner/os_user 显示 unknown/待分配（用户要求解决）：
    mac: stat /dev/console 属主 → who 的 console 行 → scutil State:/Users/ConsoleUser；
    linux: stat /dev/console 属主 → who 的 console/:0 行。"""
    u = (os.environ.get("USER") or os.environ.get("LOGNAME") or os.environ.get("USERNAME") or "").strip()
    if u and u.lower() not in ("root", "system", "localsystem", "$"):
        return u
    import platform
    sysname = platform.system()
    def _ok(v):
        v = (v or "").strip()
        return v if v and v.lower() not in ("", "root", "system", "localsystem", "$") else ""
    try:
        if sysname == "Darwin":
            got = _ok(subprocess.run(["stat", "-f", "%Su", "/dev/console"], capture_output=True, text=True, timeout=5).stdout)
            if got:
                return got
            # who 的 console 行（如 "shine   console  ..."）
            for line in subprocess.run(["who"], capture_output=True, text=True, timeout=5).stdout.splitlines():
                if "console" in line:
                    got = _ok(line.split()[0]) if line.split() else ""
                    if got:
                        return got
            # scutil State:/Users/ConsoleUser 的 Name 字段
            sc = subprocess.run(["scutil"], input="show State:/Users/ConsoleUser\n", capture_output=True, text=True, timeout=5).stdout
            m = re.search(r'Name\s*:\s*(\S+)', sc)
            got = _ok(m.group(1) if m else "")
            if got:
                return got
        elif sysname == "Linux":
            got = _ok(subprocess.run(["stat", "-c", "%U", "/dev/console"], capture_output=True, text=True, timeout=5).stdout)
            if got:
                return got
            for line in subprocess.run(["who"], capture_output=True, text=True, timeout=5).stdout.splitlines():
                if "console" in line or ":0" in line:
                    got = _ok(line.split()[0]) if line.split() else ""
                    if got:
                        return got
    except Exception:
        pass
    return u or "unknown"
_SERIAL_CACHE = {"v": None}
def device_serial():
    """真实硬件序列号（进程内缓存）：mac=IOPlatformSerialNumber、win=机器序列号、
    linux=machine-id。供上报与展示以便定位设备（用户要求显示真实序列号）；无则空串。"""
    if _SERIAL_CACHE["v"] is None:
        _SERIAL_CACHE["v"] = hardware_serial()
    return _SERIAL_CACHE["v"]
def server_override_path():
    """预留的服务器地址覆盖文件（用户编辑即全自动切换控制台，无需重装）。"""
    return Path(__file__).with_name("server-override.json")
def read_server_override():
    """读 server-override.json 的 server_url；仅接受 https，非法/缺失返回空串。
    容忍用户写全路径（…/api/enroll、…/aegis/v1/reports 等）：归一化为 origin，
    避免"写裸域不生效/写全路径才生效"的困惑（用户反馈）。"""
    try:
        d = json.loads(server_override_path().read_text())
    except (OSError, ValueError, UnicodeError):
        return ""
    if not isinstance(d, dict):
        return ""
    u = str(d.get("server_url") or d.get("server") or "").strip().rstrip("/")
    for suffix in ("/api/enroll", "/aegis/v1/reports", "/v1/reports", "/api/policy/artifact", "/downloads/update-manifest.json"):
        if u.endswith(suffix):
            u = u[: -len(suffix)]
            break
    return u if u.startswith("https://") and len(u) <= 256 else ""
def report_url_origin(url):
    try:
        u = urlsplit(url or "")
        return f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else ""
    except ValueError:
        return ""
def enroll_to_server(server, device_id):
    """向指定控制台零接触入网（改 server-override.json 后全自动切换）。
    返回 (reporting_config, policy_or_None)；契约不满足抛 ValueError。"""
    body = json.dumps({"hostname": os.uname().nodename, "device_id": device_id, "agent_version": AGENT_VERSION}).encode()
    req = urllib.request.Request(server + "/api/enroll", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        d = json.loads(r.read().decode())
    tok = str(d.get("report_token") or ""); sec = str(d.get("signing_secret") or "")
    ru = str(d.get("report_url") or (server + "/aegis/v1/reports"))
    if len(tok) < 32 or len(tok) > 4096: raise ValueError("enroll_token_invalid")
    if len(sec) < 32 or len(sec) > 4096: raise ValueError("enroll_secret_invalid")
    if not ru.startswith("https://"): raise ValueError("enroll_report_url_not_https")
    return {"schema": "aegis.reporting/v1", "report_url": ru, "report_token": tok, "signing_secret": sec}, (d.get("policy") if isinstance(d.get("policy"), dict) else None)
_OVERRIDE_NOTED = {"fail": False}
def apply_server_override(args, host_device_id):
    """每周期检查 server-override.json：服务器变更则重新入网并改写上报配置/策略。
    失败保持现配置（SOFT FAIL），仅记一次 finding，绝不中断扫描/上报。
    返回 rep(dict)=已切换 / False=切换失败 / None=无需切换。"""
    ov = read_server_override()
    if not ov or ov == report_url_origin(args.report_url):
        return None
    rpath = Path(args.report_config) if args.report_config else Path(__file__).with_name("reporting.json")
    try:
        rep, pol = enroll_to_server(ov, host_device_id)
        write_private_atomic(str(rpath), json.dumps(rep, separators=(",", ":")))
        if isinstance(pol, dict):
            write_private_atomic(args.policy, json.dumps(pol, ensure_ascii=False))
        args.report_url = rep["report_url"]
        return rep
    except Exception:
        return False
def hardware_device_id():
    """设备唯一 ID = sha256("aegis-hw:"+硬件序列)[:12]；无硬件标识时回落 hostname（旧行为）。
    用户反馈:hostname 变更/升级不应产生"新终端"，故优先硬件序列（稳定）。"""
    s=device_serial()
    if s: return hashlib.sha256(("aegis-hw:"+s).encode()).hexdigest()[:12]
    return hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12]
ENTERPRISE_BASELINE_VERSION=""
ENTERPRISE_BASELINE_AUTH_FAILED=False
def enterprise_baseline_path():
    return Path(__file__).with_name("enterprise-baseline.md")
def effective_baseline():
    """上游/内置基线 + 企业级 MD（附加合并，互不覆盖）。企业 MD 不在范围/未发布时仅内置基线。"""
    base=BASELINE.read_text().rstrip()
    try:
        extra=enterprise_baseline_path().read_text(errors="ignore").rstrip()
        if extra: base=base+"\n\n"+extra
    except OSError: pass
    return base
def sync_enterprise_baseline(base_url,token,device_id,department):
    """从 Collector 拉取企业级 MD（按灰度范围）；在范围则落盘 enterprise-baseline.md 并记版本，
    不在范围/未发布(404)则删除旧文件（避免过期企业基线残留）。返回版本号字符串。

    可观测性：401/403 是"鉴权链路坏了"(每设备令牌未被 Collector 接受)——与 404(合法地不在
    范围)语义完全不同，此前被压成同一分支静默删文件，令管理员无从发现企业 MD 推不到终端。
    现区分：401/403 置 ENTERPRISE_BASELINE_AUTH_FAILED 并保留上一份文件(基础设施问题不改范围)，
    由主循环产出 HIGH finding；404 正常清除。"""
    global ENTERPRISE_BASELINE_VERSION, ENTERPRISE_BASELINE_AUTH_FAILED
    ep=enterprise_baseline_path()
    ENTERPRISE_BASELINE_AUTH_FAILED=False
    if not base_url or not token:
        ENTERPRISE_BASELINE_VERSION=""; return ""
    url=base_url.rstrip("/")+"/v1/enterprise-baseline?device_id="+urllib.parse.quote(device_id)+"&department="+urllib.parse.quote(department or "")
    try:
        # Collector 的每设备令牌鉴权依赖 X-Aegis-Device-ID 头绑定 device_id。
        req=urllib.request.Request(url,headers={"Authorization":"Bearer "+token,"X-Aegis-Device-ID":device_id})
        with urllib.request.urlopen(req,timeout=20) as r:
            d=json.loads(r.read().decode("utf-8"))
        content=d.get("content"); version=str(d.get("version") or "")
        if isinstance(content,str) and content and 0<len(content)<=2_000_000:
            write_private_atomic(ep,content); ENTERPRISE_BASELINE_VERSION=version; return version
    except urllib.error.HTTPError as e:
        if e.code in (401,403):
            # 鉴权链路故障：保留上一份企业基线(若有)，标记以便上报，绝不静默当作"不在范围"。
            ENTERPRISE_BASELINE_AUTH_FAILED=True
        elif e.code==404:
            try: ep.unlink(missing_ok=True)
            except OSError: pass
            ENTERPRISE_BASELINE_VERSION=""; return ""
    except Exception:
        pass
    return ENTERPRISE_BASELINE_VERSION
def build_report(root,policy):
    inventory,findings=scan(root,policy)
    baseline_inv,baseline_findings=verify_user_baselines()
    inventory.extend(baseline_inv); findings.extend(baseline_findings)
    if len(inventory)>REPORT_INVENTORY_LIMIT:
        inventory=inventory[:REPORT_INVENTORY_LIMIT-1]+[{"type":"inventory_truncated","omitted":len(inventory)-REPORT_INVENTORY_LIMIT+1}]
    if len(findings)>REPORT_FINDING_LIMIT:
        omitted=len(findings)-REPORT_FINDING_LIMIT+1; findings=findings[:REPORT_FINDING_LIMIT-1]+[finding("findings_truncated","medium",root,f"报告发现项超限，省略 {omitted} 项")]
    return {"schema":"aegis.report/v1","agent_version":AGENT_VERSION,"policy_version":policy["version"],"device_id":hardware_device_id(),"hostname":os.uname().nodename,"os_user":interactive_os_user(),"owner":(os.environ.get("AEGIS_DEVICE_OWNER") or "")[:64],"os":platform.system().lower()[:16],"serial":device_serial()[:64],"enterprise_baseline_version":ENTERPRISE_BASELINE_VERSION,"scanned_at":int(time.time()),"scan_root":safe_path(root),"inventory":inventory,"summary":{s:sum(f["severity"]==s for f in findings) for s in ["critical","high","medium","low"]},"findings":findings}
def add_report_finding(report,item):
    if len(report["findings"])<REPORT_FINDING_LIMIT: report["findings"].append(item)
    else: report["findings"][-1]=item
    report["summary"]={severity:sum(f["severity"]==severity for f in report["findings"]) for severity in ["critical","high","medium","low"]}
AGENT_VERSION = "0.34.7"

# 上报被拒(401/403=凭据失效或被吊销)时的一次自愈：重新入网刷新每设备凭据。
# 限每进程 10 分钟一次，避免凭据故障时打爆入网端点；仅 --auto-enroll 模式可用
# （否则无从推导入网地址）。best-effort：任何失败返回 None，回落本地 spool 排队。
_REENROLL_COOLDOWN_S = 600
_last_reenroll_ts = 0.0
def maybe_reenroll_on_auth_failure(exc, args, root, enroll_path, host_device_id):
    global _last_reenroll_ts
    if getattr(exc, "code", None) not in (401, 403) or not getattr(args, "auto_enroll", False):
        return None
    now = time.time()
    if now - _last_reenroll_ts < _REENROLL_COOLDOWN_S:
        return None
    _last_reenroll_ts = now
    try:
        auto_enroll(root)
        if enroll_path:
            cfg = load_enrollment_config(enroll_path)
            if cfg.get("device_id") == host_device_id:
                print("aegis agent re-enrolled after credential rejection; retrying report", file=sys.stderr)
                return cfg
    except Exception:
        return None
    return None


def maybe_self_update(policy, report_url):
    """无桌管环境的自更新兜底通道；主通道永远是桌管/MDM 推送。

    仅当策略 agent_self_update.enabled=true 且能推导 manifest URL 时执行。
    best-effort：任何失败静默返回，绝不影响本轮扫描/上报。
    """
    cfg = policy.get("agent_self_update") if isinstance(policy, dict) else None
    if not isinstance(cfg, dict) or cfg.get("enabled") is not True:
        return
    manifest_url = cfg.get("manifest_url") or ""
    if not manifest_url and report_url:
        # 更新清单由控制台静态提供于 <源>/downloads/update-manifest.json。上报地址可能是
        # <源>/aegis/v1/reports(nginx 反代 collector)、<源>/v1/reports 或 <源>/api/v1/reports，
        # 前缀不固定；旧逻辑只认 "/api/" 切分，在 /aegis/ 拓扑下 manifest_url 恒为空 →
        # 自更新静默不执行。改为取上报地址的 scheme://netloc 源，与路径前缀解耦。
        try:
            _u = urllib.parse.urlsplit(report_url)
            if _u.scheme in ("https", "http") and _u.netloc:
                manifest_url = f"{_u.scheme}://{_u.netloc}/downloads/update-manifest.json"
        except (ValueError, TypeError):
            manifest_url = ""
        if not manifest_url and "/api/" in report_url:
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
    device_id = hardware_device_id()
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
    ap=argparse.ArgumentParser(description="Aegis AI Agent 安全扫描器"); ap.add_argument("scan_path",nargs="?",default="."); ap.add_argument("--policy",default=str(DEFAULT_POLICY)); ap.add_argument("--output"); ap.add_argument("--install-baseline",action="store_true"); ap.add_argument("--auto-enroll",action="store_true"); ap.add_argument("--watch",action="store_true"); ap.add_argument("--interval",type=int,default=300); ap.add_argument("--report-url",default=os.getenv("AEGIS_REPORT_URL","")); ap.add_argument("--report-config",default=os.getenv("AEGIS_REPORT_CONFIG","")); ap.add_argument("--spool-dir",default=os.getenv("AEGIS_SPOOL_DIR","")); ap.add_argument("--enrollment-config",default=os.getenv("AEGIS_ENROLLMENT_CONFIG","")); ap.add_argument("--enrollment-dir",default=os.getenv("AEGIS_ENROLLMENT_DIR","")); args=ap.parse_args()
    # 扫描看门狗（watch 模式）：每个周期在**子进程**内跑一次性扫描+上报，父进程以
    # 时间预算(AEGIS_SCAN_BUDGET_SECONDS,默认1800s)监督；子进程挂死(如阻塞在 hung/
    # 网络挂载的 open())会被 kill，父进程记录 scan_timeout 并进入下一周期，绝不让
    # 守护循环整体挂死。配合 scan() 跳过子目录挂载点，双保险。
    if args.watch:
        try: budget=min(max(int(os.getenv("AEGIS_SCAN_BUDGET_SECONDS","1800")),60),86400)
        except (TypeError,ValueError): budget=1800
        child_argv=[sys.executable,str(Path(__file__).resolve())]+[a for a in sys.argv[1:] if a!="--watch"]
        while True:
            try:
                subprocess.run(child_argv,timeout=budget,check=False)
            except subprocess.TimeoutExpired:
                print(f"aegis scan cycle exceeded budget {budget}s; child killed (scan_timeout); will retry next interval",file=sys.stderr)
            time.sleep(max(args.interval,60))
    host_device_id=hardware_device_id()
    # 每设备入网凭据优先：显式 --enrollment-config > --enrollment-dir/<本机device_id>.json > 全网 reporting.json(向后兼容)。
    enroll_path=args.enrollment_config
    if not enroll_path and args.enrollment_dir:
        cand=Path(args.enrollment_dir)/(host_device_id+".json")
        if cand.is_file(): enroll_path=str(cand)
    enrollment=None; enrollment_error=False; enrollment_mismatch=False
    if enroll_path:
        try:
            enrollment=load_enrollment_config(enroll_path)
            if enrollment["device_id"]!=host_device_id: enrollment_mismatch=True; enrollment=None
        except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): enrollment_error=True; enrollment=None
    # 强制验签开关只来自带外可信源（入网配置 require_signed_policy 优先，其次 env），
    # 绝不来自（可能未签名的）策略体本身，避免攻击者自行降级。默认 False 保持向后兼容。
    if enrollment is not None and isinstance(enrollment.get("require_signed_policy"),bool):
        require_signature=enrollment["require_signed_policy"]
    else:
        require_signature=os.getenv("AEGIS_REQUIRE_SIGNED_POLICY","").strip().lower() in {"1","true","yes"}
    policy,policy_error=reload_policy(args.policy,require_signature=require_signature); root=Path(args.scan_path).resolve()
    if policy_error or policy is None: raise SystemExit("valid Aegis policy is required")
    # 仅在未启用每设备入网时回退全网 reporting；入网凭据无效/不符时拒报，绝不静默回退全网共享密钥。
    reporting=None; reporting_error=False
    if enrollment is None and not enrollment_error and not enrollment_mismatch:
        if not args.report_config:
            candidate=Path(__file__).with_name("reporting.json")
            if candidate.is_file(): args.report_config=str(candidate)
        if args.report_config:
            try: reporting=load_reporting_config(args.report_config); args.report_url=reporting["report_url"]
            except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): reporting_error=True; args.report_url=""
    # 自更新必须在 report_url 定稿之后调用：LaunchDaemon/Agent 以 --report-config 传入上报配置，
    # args.report_url 要到上面 load_reporting_config 才被赋值；此前在赋值前调用 → manifest_url
    # 恒空 → 自更新静默不执行（用户手动装新客户端后"未来自更新"不生效的根因）。
    maybe_self_update(policy, args.report_url)
    if args.install_baseline: install_baseline(root)
    while True:
        # 服务器地址覆盖（预留文件 server-override.json）：用户编辑该文件即全自动重新
        # 入网、切换控制台并拉取新策略，无需重装客户端。失败 SOFT FAIL 保持原配置。
        _ov = apply_server_override(args, host_device_id)
        _EMIT_OV = False
        if _ov is False and not _OVERRIDE_NOTED.get("emitted"):
            _OVERRIDE_NOTED["emitted"] = True; _EMIT_OV = True
        elif isinstance(_ov, dict):
            _OVERRIDE_NOTED["emitted"] = False
            reporting = {"report_token": _ov["report_token"], "signing_secret": _ov["signing_secret"]}
            # 重新入网成功即视为上报配置已修复：必须同时清 reporting_error，否则本周期
            # can_report 仍为 False、要等下一个周期才上报（用户实测"写全路径才生效"的真因）。
            reporting_error = False
            enrollment = None; enrollment_error = False; enrollment_mismatch = False
        policy,reload_failed=reload_policy(args.policy,policy,require_signature=require_signature)
        # 先拉取企业级 MD（按灰度范围）再注入基线：保证本轮注入即用最新企业 MD，
        # 否则新发布的企业 MD 要延迟一个扫描周期才生效（注入早于拉取的历史缺陷）。
        eb_token=(enrollment or {}).get("report_token") or (reporting or {}).get("report_token") or os.getenv("AEGIS_REPORT_TOKEN","")
        eb_base=(args.report_url or "").replace("/v1/reports","")
        eb_dept=(enrollment or {}).get("department") or os.environ.get("AEGIS_DEVICE_DEPARTMENT","")
        sync_enterprise_baseline(eb_base, eb_token, host_device_id, eb_dept)
        if args.auto_enroll: auto_enroll(root)
        report=build_report(root,policy); data=json.dumps(report,ensure_ascii=False,indent=2)
        if reload_failed:
            add_report_finding(report,finding("policy_reload_failed","high",args.policy,("策略热加载失败（已启用强制验签：缺签名/验签失败/解析错误），继续使用上一份有效签名策略" if require_signature else "策略热加载失败，继续使用上一份有效策略"))); data=json.dumps(report,ensure_ascii=False,indent=2)
        if ENTERPRISE_BASELINE_AUTH_FAILED:
            add_report_finding(report,finding("enterprise_baseline_auth_failed","high",eb_base+"/v1/enterprise-baseline","企业级 MD 拉取被拒(401/403)：每设备上报令牌未被 Collector 接受，终端未纳入企业基线管理（排查 Collector 令牌/设备令牌注册）")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if reporting_error:
            add_report_finding(report,finding("reporting_config_invalid","high",args.report_config,"受保护上报配置权限、所有者或契约无效；本轮拒绝上报")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if enrollment_error:
            add_report_finding(report,finding("enrollment_config_invalid","high",enroll_path,"每设备入网凭据权限、所有者或契约无效；本轮拒绝上报，绝不回退全网共享凭据")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if enrollment_mismatch:
            add_report_finding(report,finding("enrollment_device_mismatch","high",enroll_path,f"入网凭据 device_id 与本机派生 ID({host_device_id}) 不符；本轮拒绝上报")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if _EMIT_OV:
            add_report_finding(report,finding("server_override_failed","medium",str(server_override_path()),"server-override.json 指向的控制台入网失败，保持原上报配置；请检查该控制台可达性与 /api/enroll")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if args.output: write_private_atomic(args.output,data)
        can_report=bool(args.report_url) and not reporting_error and not enrollment_error and not enrollment_mismatch
        if can_report:
            if enrollment: token=enrollment["report_token"]; signing=enrollment["signing_secret"]
            elif reporting: token=reporting["report_token"]; signing=reporting["signing_secret"]
            else: token=os.getenv("AEGIS_REPORT_TOKEN",""); signing=None
            spool=Path(args.spool_dir) if args.spool_dir else (Path(args.output).parent/"spool" if args.output else Path.home()/".aegis-agent/spool")
            status_path=(Path(args.output).parent if args.output else spool.parent)/"upload-status.json"
            try: flush_spool(spool,args.report_url,token,signing); post_report(args.report_url,token,report,signing); write_upload_status(status_path,args.report_url)
            except Exception as exc:
                # 凭据被拒(401/403)时一次自愈：重新入网刷新凭据并重试一轮；否则本地排队。
                refreshed=maybe_reenroll_on_auth_failure(exc,args,root,enroll_path,host_device_id)
                if refreshed is not None:
                    enrollment=refreshed
                    try: post_report(args.report_url,refreshed["report_token"],report,refreshed["signing_secret"]); write_upload_status(status_path,args.report_url)
                    except Exception: queue_report(spool,report); print("report upload failed after re-enroll; queued locally",file=sys.stderr)
                else:
                    queue_report(spool,report); print(f"report upload failed; queued locally: {exc}",file=sys.stderr)
        print(data)
        if not args.watch: return 2 if report["summary"]["critical"] or report["summary"]["high"] else 0
        time.sleep(max(args.interval,60))
if __name__=="__main__": sys.exit(main())
