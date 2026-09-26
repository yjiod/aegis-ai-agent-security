#!/usr/bin/env python3
"""Aegis endpoint scanner prototype. Standard-library only; read-only by default."""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, os, platform, random, re, shutil, signal, socket, stat, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
# 冻结(PyInstaller/Nuitka --onefile)后 __file__ 指向临时解压目录(_MEIPASS)，agent 的 sibling
# 配置/基线(aegis-policy.json / aegis-security-baseline.md / reporting.json / server-override.json /
# enterprise-baseline.md)并不在那里，而是与**可执行文件**同目录。故统一用 BASE_DIR 定位这些 sibling：
# 冻结时=可执行文件所在目录(sys.executable 的父目录)，非冻结时=脚本所在目录。python3 直跑行为不变。
def _aegis_base_dir() -> "Path":
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent
BASE_DIR = _aegis_base_dir()
# 冻结二进制(PyInstaller)不携带系统 CA 信任库 → https 因找不到 CA 而 URLError（python3 形态用系统
# CA 无此问题；本机实测：冻结二进制不设 CA 时 enroll 报 URLError，设 SSL_CERT_FILE=/etc/ssl/cert.pem
# 后即通）。冻结时给 ssl 指定 CA：优先 certifi（若 --collect-all certifi 打进包），否则回落各平台系统
# CA 路径。必须在任何 https 之前设 SSL_CERT_FILE —— ssl 默认上下文在创建时从该环境变量加载 CA。
if getattr(sys, "frozen", False) and not os.environ.get("SSL_CERT_FILE"):
    _aegis_ca = None
    try:
        import certifi  # 可选；未打包则回落系统 CA
        _aegis_ca = certifi.where()
    except Exception:
        for _c in ("/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem",
                   "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"):
            if os.path.exists(_c):
                _aegis_ca = _c
                break
    if _aegis_ca:
        os.environ["SSL_CERT_FILE"] = _aegis_ca
DEFAULT_POLICY=BASE_DIR / "aegis-policy.json"
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
    # modules(真实可开关) 与 deny(显式封禁名单) 为可选块：缺省=全开/空名单，向后兼容旧策略。
    modules=data.get("modules",{})
    if not isinstance(modules,dict) or any(not isinstance(k,str) or not isinstance(v,bool) for k,v in modules.items()): raise ValueError("invalid_policy_modules")
    deny=data.get("deny",{})
    if not isinstance(deny,dict): raise ValueError("invalid_policy_deny")
    for dkey in ("skills","mcp"):
        dval=deny.get(dkey,[])
        if not isinstance(dval,list) or any(not isinstance(x,str) or not x for x in dval): raise ValueError("invalid_policy_deny:"+dkey)
    return data
def policy_module(policy,name,default=True):
    """模块开关：策略 modules.<name>，缺省 default。执行类开关(skill_enforce/mcp_enforce)缺省 False 由调用方传入。"""
    mods=policy.get("modules") if isinstance(policy,dict) else None
    if isinstance(mods,dict) and name in mods and isinstance(mods[name],bool): return mods[name]
    return default
def policy_deny(policy,kind):
    deny=policy.get("deny") if isinstance(policy,dict) else None
    if isinstance(deny,dict):
        val=deny.get(kind,[])
        if isinstance(val,list): return [x for x in val if isinstance(x,str)]
    return []
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
def _cached_ed25519_public():
    """安装期/入网期缓存的控制台 ed25519 公钥（base64，公开信息，644 可读即可）。"""
    for cand in (BASE_DIR/"ed25519-public.b64", Path(os.path.expanduser("~"))/".aegis-agent"/"ed25519-public.b64"):
        try:
            v=cand.read_text(encoding="utf-8").strip()
            if v: return v
        except OSError:
            continue
    return ""
def _verify_ed25519_with_pub(data,pub):
    sig=data.get("ed25519_signature")
    if not (isinstance(sig,str) and sig): return False
    try:
        pub_b=base64.b64decode(pub); sig_b=base64.b64decode(sig)
    except Exception:
        return False
    body={k:v for k,v in data.items() if k not in ("ed25519_signature","ed25519_public","ed25519_key_id")}
    return ed25519_verify(pub_b, canonical_json(body).encode("utf-8"), sig_b)
def load_policy(path,verify_key=None,require_signature=False):
    data=json.loads(Path(path).read_text())
    data=validate_policy(data)
    if "signature" in data:
        ring={"default":verify_key} if verify_key else policy_verify_keyring()
        if not ring:
            # HMAC 验签环缺失是终端的**正常状态**（对称密钥绝不下发终端）。回落非对称通道：
            # ed25519 公钥必须来自带外可信源（env AEGIS_POLICY_ED25519_PUBLIC 或安装期缓存文件），
            # 绝不把策略体自携公钥单独当信任根；两者皆无则 fail-closed（保持防篡改强度）。
            # 真机事故(2026-09-24): 控制台开始签发带 signature 字段的策略后，无验签环的终端
            # 每周期 SystemExit("valid Aegis policy is required") → 停止上报 → 控制台误判"过期"。
            pub=os.getenv("AEGIS_POLICY_ED25519_PUBLIC","").strip() or _cached_ed25519_public()
            if not pub: raise ValueError("policy_signed_but_no_verify_key")
            if not _verify_ed25519_with_pub(data,pub): raise ValueError("policy_ed25519_invalid")
            return data
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
BASELINE=BASE_DIR / "aegis-security-baseline.md"
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
        # mac 的 /home 是 autofs 挂载点, 即便 root iterdir 也 EPERM(真机崩溃教训); darwin 只扫 /Users。
        bases=[Path("/Users")] if sys.platform=="darwin" else [Path("/Users"),Path("/home")]
        for base in bases:
            if not base.exists(): continue
            try: homes.extend(p for p in base.iterdir() if p.is_dir() and not p.name.startswith("."))
            except OSError: pass
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
# 测试/夹具路径特征：tests/specs/fixtures/__tests__/testing 目录，或 .test./.spec./_test. 文件名。
# 这些路径里的"硬编码凭据"多为 dummy fixture，hardcoded_secret 降为 medium（仍上报）。
_TEST_PATH_RE = re.compile(r"(?i)([\\/])(tests?|specs?|fixtures?|__tests__|testing)([\\/])|\.test\.|\.spec\.|_test[_.]|(^|[\\/])test_")
_PROHIBIT_RE=re.compile(r"(禁止|不得|严禁|勿|never|prohibit|forbid|❌)",re.I)
def _in_prohibition_context(text,match):
    """命中是否落在同一行、且位于"禁止/不得/never…"否定语境之后。

    安全基线文档(AGENTS.md/CLAUDE.md 等)常以"禁止关闭 TLS 校验（verify=False, …）"的
    **禁用示例**形式引用坏写法；scanner 若按字面匹配会把"在禁止该写法"的文档误报成
    "真的用了该写法"(critical)。真实不安全代码行不会在同一行带禁止/never 前缀，故按
    同行动词前缀排除可消除这类系统性误报而不放过真代码。返回 True=属禁止语境(误报,跳过)。"""
    start=match.start()
    line_start=text.rfind("\n",0,start)+1
    return bool(_PROHIBIT_RE.search(text[line_start:start]))
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
        if kind=="insecure_tls_verification":
            # 安全基线文档以"禁止…(verify=False, NODE_TLS_…=0)"禁用示例引用坏写法，字面匹配会
            # 系统性误报。取第一个**非**同行动词禁止语境的命中（真实不安全代码行不带禁止前缀）。
            hit=next((m for m in re.finditer(pat,text) if not _in_prohibition_context(text,m)),None)
        else:
            hit=re.search(pat,text)
        if hit: out.append(finding(kind,sev,path,f"安全代码质量规则命中: {kind}",hit.group(0).strip()[:80]))
    # Agentic 技战法规则（OWASP Agentic Top10 缺口补齐）：由 skill_rules ∪ code_rules 门控。
    #   context_poisoning (AGT06 记忆/上下文投毒)：面向"未来会话/记忆持久化"的指令注入，
    #     或指示写入 agent 记忆/awareness 存储——把不可信内容固化进后续推理上下文。
    #   unvalidated_llm_execution (LLM09/AGT08 过度依赖/级联幻觉)：模型输出未经校验直入
    #     exec/eval/shell/子进程，或对高危动作关闭人工确认（auto_approve 等）。
    agentic_checks=[
        ("context_poisoning","high",r"(?is)(?:remember\s+to\s+always|in\s+future\s+sessions?\b|update\s+your\s+memory|write\s+(?:this|these)\s+(?:instructions?|rules?)?\s+to\s+(?:your\s+)?memory|persist\s+this\s+instruction|append\s+to\s+memory\.md|\bmemory\.md\b|awareness/memory\b)"),
        ("unvalidated_llm_execution","high",r"(?is)\b(?:exec|eval|os\.system|subprocess\.(?:run|call|popen|check_output))\s*\([^)]{0,200}?(?:llm|model|completion|assistant|agent|chat)[_\- ]?(?:output|response|message|content|reply)|auto_?approve\s*[:=]\s*(?:true|1)|require_?(?:human|manual)?_?approval\s*[:=]\s*(?:false|0)"),
    ]
    enabled_agentic=set(policy.get("skill_rules",[])) | set(policy.get("code_rules",[]))
    for kind,sev,pat in agentic_checks:
        if kind not in enabled_agentic: continue
        hit=re.search(pat,text)
        if hit: out.append(finding(kind,sev,path,f"Agentic 技战法规则命中: {kind}",hit.group(0).strip()[:80]))
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
        if hit:
            # 路径感知严重度：测试/夹具路径里的"凭据"多为 dummy（test fixture），降为 medium
            # 仍上报但不淹 critical；生产代码路径保持 critical。降低风险中心 critical 噪声而不掩真秘密。
            sev = "medium" if _TEST_PATH_RE.search(str(path) if path else "") else "critical"
            note = "疑似硬编码凭据" + ("（测试/夹具路径，降级）" if sev == "medium" else "")
            out.append(finding("hardcoded_secret", sev, path, note, hit.group(0)[:8] + "…"))
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
    # AGT07 不安全的 Agent 间通信：非回环明文通道（http/ws）或 agent/a2a 端点无任何鉴权配置。
    if url and "unauthenticated_agent_channel" in set(policy.get("mcp_rules",[])):
        try:
            p2=urlsplit(url); h2=(p2.hostname or "").lower(); scheme2=p2.scheme
        except ValueError:
            p2=None; h2=""; scheme2=""
        loopback={"localhost","127.0.0.1","::1"}
        auth_cfg=bool(cfg.get("headers")) or any(re.search(r"TOKEN|SECRET|AUTH",str(k),re.I) for k in (cfg.get("env") or {}))
        is_agent_endpoint=bool(re.search(r"agent|a2a|inter-?agent",url,re.I))
        if scheme2 in ("http","ws") and h2 not in loopback:
            out.append(finding("unauthenticated_agent_channel","high",path,f"MCP/Agent 通道 {name} 使用非回环明文传输: {scheme2}"))
        elif is_agent_endpoint and scheme2!="https" and not auth_cfg:
            out.append(finding("unauthenticated_agent_channel","high",path,f"Agent 端点 {name} 未配置 TLS/鉴权"))
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
SKILL_GOVERNANCE_KINDS={"prompt_override","credential_access","context_poisoning","hidden_instruction"}
def scan_skill_governance(path,text,policy):
    """Skill behavioral signals, independent of optional project code quality.
    Do not include matched content in evidence: Skill text can contain secrets.
    These are detection signals; actual enforcement remains a separate decision.
    """
    if text.startswith("\ufeff"): text=text[1:]  # UTF-8 BOM is an encoding marker, not an instruction.
    checks=[
        ("prompt_override",r"(?i)ignore (all |any )?(previous|prior) instructions"),
        ("credential_access",r"(?i)(?:~/|\$home[\\/])(?:\.ssh|\.aws)|security\s+find-(?:generic|internet)-password"),
        ("context_poisoning",r"(?is)(?:remember\s+to\s+always|update\s+your\s+memory|write\s+(?:this|these)\s+(?:instructions?|rules?)?\s+to\s+(?:your\s+)?memory|persist\s+this\s+instruction|append\s+to\s+memory\.md)"),
        ("hidden_instruction",r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"),
    ]
    enabled=set(policy.get("skill_rules",[]))
    return [finding(kind,"high",path,"Skill governance signal: "+kind)
            for kind,pattern in checks if kind in enabled and re.search(pattern,text)]

def retain_finding_without_code_scan(item):
    return item.get("kind") not in CODE_QUALITY_KINDS or (
        item.get("asset_type")=="skill" and bool(item.get("asset_key"))
        and item.get("kind") in SKILL_GOVERNANCE_KINDS)

def scan_skill(skill_file,policy,max_files=500,m_code=None):
    """Scan the complete Skill package without following links outside its root.
    m_code=None 沿用 policy 缺省(code_scan 默认关); False=包内代码质量扫描关闭
    (skill 身份/风险信号仍扫——那是 skill 治理, 不是代码质量)。"""
    root=skill_file.parent; out=[]; scanned=0; name=root.name
    if m_code is None: m_code=policy_module(policy,"code_scan",False)
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
                    text=path.read_text(errors="ignore")
                    out.extend(scan_skill_governance(path,text,policy))
                    if m_code: out.extend(f for f in scan_text(path,text,policy) if f["kind"] not in SKILL_GOVERNANCE_KINDS)
                    if path.name in DEPENDENCY_MANIFESTS: out.extend(scan_dependency_manifest(path,text))
                else: out.append(finding("oversized_file_skipped","medium",path,f"Skill 文件超过扫描字节上限 {max_file_bytes(policy)}",str(size)))
            except OSError: out.append(finding("unreadable","low",path,"Skill 文件存在但无法读取"))
        if scanned>=max_files: out.append(finding("skill_scan_truncated","medium",root,f"Skill 文件数超过扫描上限 {max_files}")); break
    for f in out: f["asset_type"]="skill"; f["asset_key"]=str(name)[:128]
    return out,scanned
# ── 执行器(enforcement)：Skill 隔离 / MCP 配置移除，带备份+可回滚+回执 ──────────
# 不依赖任何外部 EDR，封禁=终端自身原子操作：
#   Skill：整目录 os.replace 移到 ~/.aegis-quarantine/<ts>-<name>/，旁置 manifest；
#          名单解除后 reconcile 只恢复"带 aegis manifest 的自己隔离物"，原样归位。
#   MCP ：先备份原配置为 <cfg>.aegis-bak，再原子改写 JSON 移除被禁 server；
#          名单解除后从备份把该 server 合并回（不整文件回滚，避免覆盖期间其它改动）。
# 门控：modules.skill_enforce / modules.mcp_enforce 为 True 才执行（缺省 False，防止
#       自主破坏，符合"不可逆操作须人工审批"）；名单=签名策略 deny.*（发布即审批）。
#       只封显式名单，不封"未知"：未知资产仅产出发现项供人工决策（真机演练教训）。
QUARANTINE_DIRNAME=".aegis-quarantine"
QUARANTINE_MANIFEST_SUFFIX=".aegis-quarantine.json"
MCP_BACKUP_SUFFIX=".aegis-bak"
MCP_SERVER_KEYS=("mcpServers","servers","mcp_servers")
# 封禁语义(用户口径: 封禁就真的封禁, 不是"搬走一次"): 从工具可加载位置移除 + 每个执行
# tick 自动再执行(复发即再封, 无需人工反复操作); 备份仅供管理员回滚。全扫描是小时级,
# 故另设高频 tick 只做轻量封禁对账, 把"复发窗口"从一小时压到秒级。
ENFORCE_TICK_SECONDS=30
ENFORCE_RECEIPTS=[]
def scan_sleep_seconds(interval,rng=None):
    """P1-3(30k 防惊群)：周期扫描睡眠加 ±10% 抖动。批量装机的终端若都用固定 interval，
    会长期对齐到同一分钟集中上报（30k 台窄窗口齐发 → 瞬时数百写/秒压垮单写采集器）。
    每周期乘 uniform(0.9,1.1) 让各终端逐周期漂移去相关，把尖峰摊平成稳态。
    仅用于计时，与令牌/会话/密钥生成无关（rng 可注入以便测试；默认 random.uniform）。"""
    base=max(int(interval),60)
    rand=rng if rng is not None else random.uniform
    return base*rand(0.9,1.1)
_DARWIN_WAITID=None
def _darwin_scan_exited(pid):
    # macOS system Python 3.9 exposes the wait constants but not os.waitid.
    # Darwin sys/signal.h puts si_pid at the fourth int in siginfo_t; reserve an
    # aligned 256-byte buffer (the supported 64-bit Darwin ABI uses 104 bytes).
    import ctypes
    global _DARWIN_WAITID
    if _DARWIN_WAITID is None:
        fn=ctypes.CDLL("/usr/lib/libSystem.B.dylib",use_errno=True).waitid
        fn.argtypes=(ctypes.c_int,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int)
        fn.restype=ctypes.c_int
        _DARWIN_WAITID=fn
    info=(ctypes.c_uint64*32)()
    if _DARWIN_WAITID(os.P_PID,pid,ctypes.byref(info),os.WEXITED|os.WNOHANG|os.WNOWAIT)!=0:
        raise OSError(ctypes.get_errno(),"scan_wait_failed")
    return ctypes.cast(info,ctypes.POINTER(ctypes.c_int))[3]==pid

def _scan_exited(process):
    # Keep a POSIX child waitable until the final group signal has been sent.
    # Reaping first would release its PID and allow signalling a reused group ID.
    if os.name=="posix":
        try:
            if hasattr(os,"waitid"):
                return os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
            if sys.platform=="darwin": return _darwin_scan_exited(process.pid)
            raise OSError("nonreaping_wait_unavailable")
        except InterruptedError:
            return False
    return process.poll() is not None

def _await_scan_exit(process,seconds):
    deadline=time.monotonic()+max(0,seconds)
    while True:
        if _scan_exited(process): return True
        remaining=deadline-time.monotonic()
        if remaining<=0: return False
        time.sleep(min(0.05,remaining))

def _signal_scan(process,force):
    try:
        if os.name=="posix":
            # Popen(start_new_session=True) makes the child's PID its group ID.
            os.killpg(process.pid,signal.SIGKILL if force else signal.SIGTERM)
        elif force: process.kill()
        else: process.terminate()
        return True
    except ProcessLookupError:
        return True
    except OSError:
        return False

def _await_scan_group_gone(process,seconds):
    if os.name!="posix": return process.returncode is not None
    deadline=time.monotonic()+max(0,seconds)
    while True:
        try: os.killpg(process.pid,0)  # Probe only; never signal after reaping.
        except ProcessLookupError: return True
        except OSError:
            # Darwin may briefly return EPERM for a group whose remaining
            # members are zombies awaiting launchd reaping. Retry, never infer
            # absence from a permission/observation error.
            if time.monotonic()>=deadline: return False
        remaining=deadline-time.monotonic()
        if remaining<=0: return False
        time.sleep(min(0.05,remaining))

def _finish_scan(process,reason,grace):
    try:
        if reason=="scan_stopped":
            _signal_scan(process,False)
            _await_scan_exit(process,grace)
        # Even if the leader exited, descendants may still be running or ignoring
        # TERM. Its unreaped PID pins the group identity until this final signal.
        # macOS can reject a signal to a group containing only a zombie leader.
        # Exit/group-disappearance checks below determine cleanup, not send status.
        _signal_scan(process,True)
        if not _await_scan_exit(process,grace): return "scan_cleanup_unconfirmed"
        result=process.wait(timeout=grace)
        if not _await_scan_group_gone(process,grace): return "scan_cleanup_unconfirmed"
        if reason=="completed": return "ok" if result==0 else "scan_failed"
        return reason
    except (OSError,subprocess.TimeoutExpired):
        return "scan_cleanup_unconfirmed"

def run_scan_cycle(child_argv,budget,grace=5,stop_requested=None):
    """Bounded supervision; stop requests clean the owned process group.

    A child stuck in kernel I/O can outlive SIGKILL. Return an explicit incomplete
    result after bounded waits instead of reporting success or waiting forever.
    POSIX groups cover descendants that remain in the scanner's session; the
    Windows Python fallback controls the direct child only.
    """
    stopped=stop_requested or (lambda: False)
    if stopped(): return "scan_stopped"
    try:
        process=subprocess.Popen(child_argv,start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except OSError:
        return "spawn_failed"
    deadline=time.monotonic()+max(0,budget)
    try:
        while True:
            if stopped(): return _finish_scan(process,"scan_stopped",grace)
            if _scan_exited(process): return _finish_scan(process,"completed",grace)
            remaining=deadline-time.monotonic()
            if remaining<=0: return _finish_scan(process,"scan_timeout",grace)
            time.sleep(min(0.05,remaining))
    except OSError:
        # Losing wait ownership means group identity is no longer safe to signal.
        return "scan_cleanup_unconfirmed"

def run_watch_loop(child_argv,budget,interval,grace=5,failure_marker=None):
    import select
    if failure_marker is not None and (Path(failure_marker).exists() or Path(failure_marker).is_symlink()):
        print("aegis prior scan cleanup requires verification; watch not started",file=sys.stderr)
        return 1
    stop_signal=[0]
    previous={}
    reader,writer=socket.socketpair()
    reader.setblocking(False); writer.setblocking(False)
    previous_wakeup=None
    def request_stop(signum,_frame):
        stop_signal[0]=signum  # No I/O, waits or locks inside a signal handler.
    try:
        previous_wakeup=signal.set_wakeup_fd(writer.fileno())
        for signum in (signal.SIGTERM,signal.SIGINT):
            previous[signum]=signal.signal(signum,request_stop)
        while not stop_signal[0]:
            status=run_scan_cycle(child_argv,budget,grace,lambda: bool(stop_signal[0]))
            if status=="scan_cleanup_unconfirmed":
                if failure_marker is not None:
                    try:
                        _atomic_write_json(Path(failure_marker),{"schema":"aegis.watch-cleanup/v1","state":"unconfirmed","at":int(time.time())},mode=0o600)
                    except OSError:
                        print("aegis could not persist scan cleanup failure",file=sys.stderr)
                print("aegis scan cleanup unconfirmed; watch stopped",file=sys.stderr)
                return 1
            if stop_signal[0] or status=="scan_stopped": return 0
            if status!="ok": print("aegis scan cycle "+status,file=sys.stderr)
            deadline=time.monotonic()+scan_sleep_seconds(interval)
            while not stop_signal[0] and time.monotonic()<deadline:
                ready,_,_=select.select([reader],[],[],max(0,deadline-time.monotonic()))
                if ready: reader.recv(4096)
        return 0
    finally:
        if previous_wakeup is not None: signal.set_wakeup_fd(previous_wakeup)
        for signum,handler in previous.items(): signal.signal(signum,handler)
        reader.close(); writer.close()
def quarantine_dir():
    return Path(os.path.expanduser("~"))/QUARANTINE_DIRNAME
def _atomic_write_json(path,obj,mode=None):
    fd,tmp=tempfile.mkstemp(prefix=".aegis-tmp-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w") as fh: json.dump(obj,fh,ensure_ascii=False,sort_keys=True,indent=2)
        os.replace(tmp,str(path))
        if mode is not None: os.chmod(str(path),mode)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise
def quarantine_skill(skill_root,reason):
    try:
        q=quarantine_dir(); q.mkdir(parents=True,exist_ok=True)
        name=Path(skill_root).name
        # dest 名带源路径哈希后缀: 多 home 同名 skill 否则 dest 碰撞, 第二个静默跳过=封禁不完整(真缺陷)。
        src_tag=hashlib.sha256(str(skill_root).encode()).hexdigest()[:8]
        dest=q/(str(int(time.time()))+"-"+name+"-"+src_tag)
        if dest.exists(): return None
        os.replace(str(skill_root),str(dest))
        manifest={"schema":"aegis.quarantine/v1","asset_type":"skill","asset_key":name,"source":str(skill_root),"dest":str(dest),"reason":reason,"at":int(time.time()),"agent_version":AGENT_VERSION}
        _atomic_write_json(q/(dest.name+QUARANTINE_MANIFEST_SUFFIX),manifest)
        return {"asset_type":"skill","asset_key":name,"action":"quarantined","target":str(skill_root),"backup":str(dest),"reason":reason,"ok":True,"at":manifest["at"]}
    except OSError:
        return None
def restore_quarantined_skill(manifest_path):
    try: m=json.loads(Path(manifest_path).read_text())
    except (OSError,ValueError): return None
    if not isinstance(m,dict) or m.get("schema")!="aegis.quarantine/v1" or m.get("asset_type")!="skill": return None
    dest=Path(m.get("dest","")); src=Path(m.get("source",""))
    if not dest.exists() or src.exists(): return None
    try:
        src.parent.mkdir(parents=True,exist_ok=True)
        os.replace(str(dest),str(src))
        os.unlink(str(manifest_path))
    except OSError: return None
    return {"asset_type":"skill","asset_key":str(m.get("asset_key","")),"action":"restored","target":str(src),"backup":str(dest),"reason":"policy_no_longer_denies","ok":True,"at":int(time.time())}
def mcp_deny_apply(config_path,server_name,reason):
    p=Path(config_path)
    try: data=json.loads(p.read_text())
    except (OSError,ValueError): return None
    if not isinstance(data,dict): return None
    holder=None
    for k in MCP_SERVER_KEYS:
        v=data.get(k)
        if isinstance(v,dict) and server_name in v: holder=k; break
    if holder is None: return None  # 已不存在=无需处理
    backup=p.with_name(p.name+MCP_BACKUP_SUFFIX)
    if not backup.exists():
        try: backup.write_bytes(p.read_bytes())
        except OSError: return None
    data[holder].pop(server_name,None)
    try: _atomic_write_json(p,data,mode=(os.stat(str(p)).st_mode & 0o777))
    except OSError: return None
    return {"asset_type":"mcp","asset_key":server_name,"action":"config_removed","target":str(p),"backup":str(backup),"reason":reason,"ok":True,"at":int(time.time())}
def mcp_deny_restore(config_path,server_name):
    p=Path(config_path); backup=p.with_name(p.name+MCP_BACKUP_SUFFIX)
    if not backup.exists(): return None
    try: cur=json.loads(p.read_text()); bak=json.loads(backup.read_text())
    except (OSError,ValueError): return None
    if not isinstance(cur,dict) or not isinstance(bak,dict): return None
    src=None; holder=None
    for k in MCP_SERVER_KEYS:
        v=bak.get(k)
        if isinstance(v,dict) and server_name in v: src=v[server_name]; holder=k; break
    if src is None: return None
    for k in MCP_SERVER_KEYS:  # 用户已手动加回则不覆盖
        v=cur.get(k)
        if isinstance(v,dict) and server_name in v: return None
    cur.setdefault(holder,{})[server_name]=src
    try: _atomic_write_json(p,cur,mode=(os.stat(str(p)).st_mode & 0o777))
    except OSError: return None
    return {"asset_type":"mcp","asset_key":server_name,"action":"config_restored","target":str(p),"backup":str(backup),"reason":"policy_no_longer_denies","ok":True,"at":int(time.time())}
# ── 执行级封禁(真封禁): 终止在跑进程 + exec-deny 二进制, 弥补"移除配置"管不住已运行实例 ──
# 只针对 deny 名单内的 MCP; 进程匹配用**精确可执行路径 token**, 绝不做模糊 pattern kill。
# exec-deny 原权限记录在隔离区 store, 解封时还原。mac 不做 pf 防火墙(启用系统级 pf 风险大)。
EXEC_DENY_STORE=QUARANTINE_DIRNAME+"/.aegis-exec-deny.json"
def _exec_deny_store_path():
    return Path(os.path.expanduser("~"))/EXEC_DENY_STORE
def _load_exec_deny_store():
    try: return json.loads(_exec_deny_store_path().read_text())
    except (OSError,ValueError): return {}
def _save_exec_deny_store(store):
    try:
        p=_exec_deny_store_path(); p.parent.mkdir(parents=True,exist_ok=True)
        _atomic_write_json(p,store)
    except OSError: pass
def _mcp_server_spec(backup_path,server_name):
    try: data=json.loads(Path(backup_path).read_text())
    except (OSError,ValueError): return None
    if not isinstance(data,dict): return None
    for k in MCP_SERVER_KEYS:
        v=data.get(k)
        if isinstance(v,dict) and server_name in v and isinstance(v[server_name],dict):
            cfg=v[server_name]
            return {"command":str(cfg.get("command") or ""),"url":str(cfg.get("url") or "")}
    return None
def _resolve_bin(command):
    if not command: return None
    p=Path(command).expanduser()
    if p.is_file(): return p
    w=shutil.which(command)
    return Path(w) if w else None
def _kill_matching(binpath):
    killed=[]
    target=str(binpath)
    try: out=subprocess.run(["ps","-eo","pid=,args="],capture_output=True,text=True,timeout=10).stdout
    except Exception: return killed
    for line in out.splitlines():
        parts=line.strip().split(None,1)
        if len(parts)<2: continue
        pid_s,args=parts
        if target in args.split():
            try:
                pid=int(pid_s)
                if pid!=os.getpid(): os.kill(pid,signal.SIGTERM); killed.append(pid)
            except (ValueError,OSError,ProcessLookupError): pass
    return killed
def _mcp_hard_block(server_name,spec):
    out=[]
    if not isinstance(spec,dict): return out
    bin=_resolve_bin(spec.get("command",""))
    if not bin: return out
    now=int(time.time())
    for pid in _kill_matching(bin):
        out.append({"asset_type":"mcp","asset_key":server_name,"action":"process_killed","target":str(bin),"reason":"policy_deny","ok":True,"at":now,"pid":pid})
    store=_load_exec_deny_store()
    try:
        m=os.stat(str(bin)).st_mode & 0o777
        if m & 0o111:
            os.chmod(str(bin),m & ~0o111)
            store[str(bin)]=m; _save_exec_deny_store(store); _write_es_deny_list(store)
            out.append({"asset_type":"mcp","asset_key":server_name,"action":"exec_denied","target":str(bin),"reason":"policy_deny","ok":True,"at":now})
    except OSError: pass
    url=spec.get("url","")
    host=""
    if url:
        try: host=urlsplit(url).hostname or ""
        except Exception: host=""
    if host: out.extend(_pf_apply(server_name,host))
    return out
def _mcp_hard_unblock(server_name,spec):
    out=[]
    if not isinstance(spec,dict): return out
    out.extend(_pf_remove(server_name))  # 连接级解封与二进制无关(url 型 MCP 无 bin 也要解)
    bin=_resolve_bin(spec.get("command",""))
    if not bin: return out
    store=_load_exec_deny_store()
    m=store.get(str(bin))
    if m is None: return out
    try:
        os.chmod(str(bin),m)
        del store[str(bin)]; _save_exec_deny_store(store); _write_es_deny_list(store)
        out.append({"asset_type":"mcp","asset_key":server_name,"action":"exec_restored","target":str(bin),"reason":"policy_no_longer_denies","ok":True,"at":int(time.time())})
    except OSError: pass
    return out
# ── mac 连接级封禁: pf anchor 按 host 整机封禁(调研结论: 无 entitlement 前提下最务实) ──
# 只加载"仅含我们 deny 规则"的 anchor(com.aegis/deny), 默认策略保持 pass, 风险限制在 anchor 内;
# 启用 pf 前先 pfctl -nf 干跑校验 stock /etc/pf.conf, 失败则不启用; 加载失败回滚(冲 anchor,
# 若 pf 是我们启用的且原先关闭则 pfctl -d 复原)。仅 root 可用; 用户态 agent 优雅跳过并留回执。
# 粒度为 host 级(非 per-process): 对被禁 MCP host 而言整机都不该连, 语义正确。per-process 需
# NEFilterDataProvider 系统扩展(Apple entitlement+MDM), 另立项。
PF_ANCHOR="com.aegis/deny"
PF_ANCHOR_FILE="/etc/pf.anchors/aegis-deny.conf"
PFCTL="/sbin/pfctl"
PF_STORE=QUARANTINE_DIRNAME+"/.aegis-pf-store.json"
def _pf_store_path():
    return Path(os.path.expanduser("~"))/PF_STORE
def _pf_load_store():
    try: return json.loads(_pf_store_path().read_text())
    except (OSError,ValueError): return {}
def _pf_save_store(store):
    try:
        p=_pf_store_path(); p.parent.mkdir(parents=True,exist_ok=True); _atomic_write_json(p,store)
    except OSError: pass
def _pf_run(args):
    try: return subprocess.run([PFCTL]+args,capture_output=True,text=True,timeout=15).returncode
    except Exception: return 1
def _pf_enabled():
    try:
        out=subprocess.run([PFCTL,"-s","info"],capture_output=True,text=True,timeout=15).stdout
        return "Status: Enabled" in out
    except Exception: return False
def _pf_rules_text(hosts):
    lines=["# aegis deny anchor - generated; do not edit","anchor-only, default policy untouched"]
    for name in sorted(hosts):
        for ip in sorted(hosts[name]):
            lines.append(f"block drop out quick proto tcp from any to {ip}  # aegis-deny:{name}")
            lines.append(f"block drop out quick proto udp from any to {ip}  # aegis-deny:{name}")
    return "\n".join(lines)+"\n"
def _pf_resolve(host):
    ips=set()
    try:
        for fam,_,_,_,sa in socket.getaddrinfo(host,None):
            ips.add(sa[0])
            if len(ips)>=16: break
    except OSError: pass
    return sorted(ips)
def _pf_apply(name,host):
    now=int(time.time())
    if sys.platform!="darwin": return []
    if os.geteuid()!=0:
        return [{"asset_type":"mcp","asset_key":name,"action":"net_block_skipped","target":host,"reason":"needs_root","ok":False,"at":now}]
    ips=_pf_resolve(host)
    if not ips:
        return [{"asset_type":"mcp","asset_key":name,"action":"net_block_skipped","target":host,"reason":"dns_resolve_failed","ok":False,"at":now}]
    store=_pf_load_store()
    hosts=store.get("hosts",{}); hosts[name]=ips
    try:
        Path(PF_ANCHOR_FILE).parent.mkdir(parents=True,exist_ok=True)
        with open(PF_ANCHOR_FILE,"w") as fh: fh.write(_pf_rules_text(hosts))
    except OSError:
        return [{"asset_type":"mcp","asset_key":name,"action":"net_block_skipped","target":host,"reason":"write_anchor_failed","ok":False,"at":now}]
    was_enabled=_pf_enabled()
    if not was_enabled:
        if _pf_run(["-nf","/etc/pf.conf"])!=0:
            return [{"asset_type":"mcp","asset_key":name,"action":"net_block_skipped","target":host,"reason":"pf_conf_parse_failed","ok":False,"at":now}]
        if _pf_run(["-e"])!=0:
            return [{"asset_type":"mcp","asset_key":name,"action":"net_block_skipped","target":host,"reason":"pf_enable_failed","ok":False,"at":now}]
        store["enabled_by_aegis"]=True
    if _pf_run(["-a",PF_ANCHOR,"-f",PF_ANCHOR_FILE])!=0:
        _pf_run(["-a",PF_ANCHOR,"-F","rules"])
        if store.get("enabled_by_aegis") and not was_enabled: _pf_run(["-d"]); store["enabled_by_aegis"]=False
        _pf_save_store(store)
        return [{"asset_type":"mcp","asset_key":name,"action":"net_block_failed","target":host,"reason":"anchor_load_failed","ok":False,"at":now}]
    store["hosts"]=hosts; _pf_save_store(store)
    return [{"asset_type":"mcp","asset_key":name,"action":"net_blocked","target":host,"reason":"policy_deny","ok":True,"at":now}]
def _pf_remove(name):
    now=int(time.time())
    if sys.platform!="darwin": return []
    if os.geteuid()!=0: return []
    store=_pf_load_store(); hosts=store.get("hosts",{})
    if name not in hosts: return []
    hosts.pop(name,None); store["hosts"]=hosts
    out=[{"asset_type":"mcp","asset_key":name,"action":"net_unblocked","target":name,"reason":"policy_no_longer_denies","ok":True,"at":now}]
    try:
        if hosts:
            with open(PF_ANCHOR_FILE,"w") as fh: fh.write(_pf_rules_text(hosts))
            _pf_run(["-a",PF_ANCHOR,"-f",PF_ANCHOR_FILE])
        else:
            _pf_run(["-a",PF_ANCHOR,"-F","rules"])
            if store.get("enabled_by_aegis"):
                _pf_run(["-d"]); store["enabled_by_aegis"]=False
    except OSError: pass
    _pf_save_store(store)
    return out
# ── ES AUTH_EXEC 守护协作: Agent 写 deny-list(路径), 守护(若已授权)在 exec 时 DENY 并记 log ──
# 守护未授权/未运行时 log 不增长, 本段零副作用; 执行级封禁回退 chmod exec-deny(已有)。
ES_DENY_LIST_FILE=".aegis-exec-deny-list.json"
ES_DENY_LOG=QUARANTINE_DIRNAME+"/.aegis-es-deny.log"
ES_OFFSET_FILE=QUARANTINE_DIRNAME+"/.aegis-es-offset"
def _write_es_deny_list(store):
    try:
        p=Path(os.path.expanduser("~"))/ES_DENY_LIST_FILE
        _atomic_write_json(p,sorted(store.keys()))
    except OSError: pass
def _drain_es_deny_log():
    out=[]
    candidates=["/Library/Application Support/AegisAgent/.aegis-es-deny.log",
                str(Path(os.path.expanduser("~"))/ES_DENY_LOG)]
    offp=Path(os.path.expanduser("~"))/ES_OFFSET_FILE
    try: offsets=json.loads(offp.read_text())
    except (OSError,ValueError): offsets={}
    if not isinstance(offsets,dict): offsets={}
    for logp in candidates:
        off=int(offsets.get(logp,0) or 0)
        try:
            with open(logp,"rb") as fh:
                fh.seek(off); blob=fh.read(); newoff=fh.tell()
        except OSError: continue
        offsets[logp]=newoff
        for line in blob.splitlines():
            try: e=json.loads(line)
            except ValueError: continue
            if isinstance(e,dict) and e.get("action")=="exec_blocked_es":
                tgt=str(e.get("target",""))
                out.append({"asset_type":str(e.get("asset_type","mcp")),"asset_key":(Path(tgt).name or tgt)[:64],"action":"exec_blocked_es","target":tgt[:512],"reason":"es_auth_deny","ok":True,"at":int(e.get("at",0) or 0)})
    try:
        offp.parent.mkdir(parents=True,exist_ok=True); offp.write_text(json.dumps(offsets))
    except OSError: pass
    return out[:20]
def _es_guard_status():
    """读 ES 守护自报状态(active/degraded)。守护未装/未授权时为空 → capabilities.es=false, 不夸大。"""
    for p in ("/Library/Application Support/AegisAgent/.aegis-es-status.json",
              str(Path(os.path.expanduser("~"))/QUARANTINE_DIRNAME/".aegis-es-status.json")):
        try:
            d=json.loads(Path(p).read_text())
            if isinstance(d,dict): return d
        except (OSError,ValueError): continue
    return {}
def reconcile_enforcement(policy):
    """每周期对账：该封的封、不该封但被本 Agent 隔离/移除的自动恢复。返回回执列表。"""
    actions=[]
    actions.extend(_drain_es_deny_log())  # ES 守护(若点亮)的 exec 拒绝回执
    # 封禁豁免(签名策略一等字段): 开发主机等明确豁免设备不执行任何封禁/隔离/移除, 只报不封。
    exempt=[str(x) for x in (policy.get("enforce_exempt") or [])] if isinstance(policy,dict) else []
    if exempt and hardware_device_id() in exempt:
        return actions
    en_skill=policy_module(policy,"skill_enforce",False)
    en_mcp=policy_module(policy,"mcp_enforce",False)
    deny_skills=set(policy_deny(policy,"skills"))
    deny_mcp=set(policy_deny(policy,"mcp"))
    homes=managed_homes()
    # 终端侧独立爆炸半径闸(与控制台发布闸双闸): 本周期计划影响资产数超 cap 且签名策略未带
    # enforce_override 时, 本周期拒绝执行并留回执 cap_exceeded, 防过宽 deny 一次性大面积隔离。
    BLAST_CAP=5
    blast_override=bool(policy.get("enforce_override")) if isinstance(policy,dict) else False
    if en_skill:
        seen=set(); planned_skill=0
        for home in homes:
            for rel in SKILL_ROOTS:
                d=home/rel
                if not d.exists(): continue
                for sm in list(d.rglob("SKILL.md")):
                    sr=sm.parent.resolve()
                    if sr in seen or not sr.exists(): continue
                    seen.add(sr)
                    if sr.name in deny_skills: planned_skill+=1
        if planned_skill>BLAST_CAP and not blast_override:
            actions.append({"asset_type":"skill","asset_key":"*","action":"cap_exceeded","target":f"{planned_skill} assets > cap {BLAST_CAP}","reason":"blast_radius_cap","ok":False,"at":int(time.time())})
            en_skill=False
    if en_mcp:
        planned_mcp=0
        for home in homes:
            for rel in AGENT_CONFIGS:
                p=home/rel
                if not p.exists() or p.suffix.lower()!=".json": continue
                try: data=json.loads(p.read_text())
                except (OSError,ValueError): continue
                if not isinstance(data,dict): continue
                present=set()
                for k in MCP_SERVER_KEYS:
                    v=data.get(k)
                    if isinstance(v,dict): present|=set(v.keys())
                planned_mcp+=len(present & deny_mcp)
        if planned_mcp>BLAST_CAP and not blast_override:
            actions.append({"asset_type":"mcp","asset_key":"*","action":"cap_exceeded","target":f"{planned_mcp} assets > cap {BLAST_CAP}","reason":"blast_radius_cap","ok":False,"at":int(time.time())})
            en_mcp=False
    # 只封显式 deny 名单(签名策略下发=人工审批)。**不做**"未知即隔离": 真机演练证明
    # unknown+block 组合会在开关打开瞬间隔离全部未加白 Skill(含用户真实在用的),
    # 破坏面过大; 未知 Skill 仅产出发现项供人工决策。
    # 每周期动作上限(分期执行): 即便带 override, 单周期最多封 PER_CYCLE 个, 其余下周期继续,
    # 留观察/回滚窗口, 防"一个 tick 全量封禁"(用户: 批量识别不要自动全量封)。
    PER_CYCLE=5
    applied_mcp=0
    if en_skill:
        seen=set(); applied=0
        for home in homes:
            for rel in SKILL_ROOTS:
                d=home/rel
                if not d.exists(): continue
                # 先物化列表再遍历：隔离会把目录移走, 边 rglob 边移动会在 Python3.9 的
                # 生成器里 scandir 已消失的目录 → FileNotFoundError(真机/单测均会触发)。
                for sm in list(d.rglob("SKILL.md")):
                    sr=sm.parent.resolve()
                    if sr in seen or not sr.exists(): continue
                    seen.add(sr); nm=sr.name
                    if nm in deny_skills and applied<PER_CYCLE:
                        r=quarantine_skill(sr,"policy_deny")
                        if r: actions.append(r); applied+=1
    q=quarantine_dir()
    if q.exists():
        for mf in sorted(q.glob("*"+QUARANTINE_MANIFEST_SUFFIX)):
            try: m=json.loads(mf.read_text())
            except (OSError,ValueError): continue
            key=str(m.get("asset_key","")) if isinstance(m,dict) else ""
            still=en_skill and (key in deny_skills)
            if not still:
                r=restore_quarantined_skill(mf)
                if r: actions.append(r)
    for home in homes:
        for rel in AGENT_CONFIGS:
            p=home/rel
            if not p.exists() or p.suffix.lower()!=".json": continue
            try: data=json.loads(p.read_text())
            except (OSError,ValueError): continue
            if not isinstance(data,dict): continue
            present=set()
            for k in MCP_SERVER_KEYS:
                v=data.get(k)
                if isinstance(v,dict): present|=set(v.keys())
            backup=p.with_name(p.name+MCP_BACKUP_SUFFIX)
            if en_mcp:
                for nm in sorted(present & deny_mcp):
                    if applied_mcp>=PER_CYCLE: continue  # 分期: 本周期配额用完, 余下下周期
                    r=mcp_deny_apply(p,nm,"policy_deny")
                    if r: actions.append(r); applied_mcp+=1
                    # 执行级封禁: 终止在跑实例 + exec-deny 二进制(真封禁, 管住已运行的)
                    actions.extend(_mcp_hard_block(nm,_mcp_server_spec(backup,nm)))
            if backup.exists():
                try: bak=json.loads(backup.read_text())
                except (OSError,ValueError): bak=None
                if isinstance(bak,dict):
                    baknames=set()
                    for k in MCP_SERVER_KEYS:
                        v=bak.get(k)
                        if isinstance(v,dict): baknames|=set(v.keys())
                    for nm in sorted(baknames-present):
                        if en_mcp and nm in deny_mcp: continue
                        r=mcp_deny_restore(p,nm)
                        if r: actions.append(r)
                        actions.extend(_mcp_hard_unblock(nm,_mcp_server_spec(backup,nm)))
    return actions
def scan(root,policy):
    findings=[]; homes=managed_homes(); inventory=discover_agent_tools(homes)
    # 模块开关(真实可关): 关掉的模块不扫描也不产出 findings。缺省全开, 向后兼容。
    m_skill=policy_module(policy,"skill_scan",True); m_mcp=policy_module(policy,"mcp_scan",True)
    # code_scan 缺省 False(2026-09-25 用户决策): 代码扫描由专业扫描器负责, 终端默认不扫代码
    # 也不上报代码类发现; 控制台策略 modules.code_scan=true 可显式恢复(预留能力)。
    m_code=policy_module(policy,"code_scan",False); m_deps=policy_module(policy,"deps_scan",True)
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
                        text=p.read_text(errors="ignore")
                        if m_code: findings.extend(scan_text(p,text,policy))
                        if m_mcp: findings.extend(scan_mcp_config(p,text,policy))
                except OSError: findings.append(finding("unreadable","low",p,"配置存在但无法读取"))
        if not m_skill: continue
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
        # 自免扫描(2026-09-25 用户反馈): Aegis 自身安装目录不参与代码扫描——自己的
        # agent 含 subprocess 调用是设计使然, 扫自己只会产出 unbounded_shell 等噪音。
        _self_dirs={"aegis-agent","AegisAgent",".aegis-agent"}
        dirs[:]=[name for name in dirs if name not in [".git","node_modules","vendor","dist","build",".venv"]+sorted(_self_dirs) and not (Path(current)/name).is_symlink() and not os.path.ismount(os.path.join(current,name))]
        for name in files:
            p=Path(current)/name
            if p.is_symlink() or not (p.suffix.lower() in suffixes or p.name in DEPENDENCY_MANIFESTS): continue
            if scanned>=file_limit: truncated=True; break
            scanned+=1
            try:
                size=p.stat().st_size
                if size<=max_file_bytes(policy):
                    text=p.read_text(errors="ignore")
                    if m_code: findings.extend(scan_text(p,text,policy))
                    if m_mcp and p.name in ["mcp.json","mcp_config.json","config.toml"]: findings.extend(scan_mcp_config(p,text,policy))
                    if m_deps and p.name in DEPENDENCY_MANIFESTS: inventory.append({"type":"dependency_manifest","path":safe_path(p)}); findings.extend(scan_dependency_manifest(p,text))
                else: findings.append(finding("oversized_file_skipped","medium",p,f"代码或配置文件超过扫描字节上限 {max_file_bytes(policy)}",str(size)))
            except OSError: pass
        if truncated: break
    # 运维提示类(截断)发现: path 折叠为 ~ 形式(裸 /Users 会在控制台归一化成 "/users" 目录级
    # 资产键, 用户质疑"加白 /users 是不是全加白了"); asset_type 置空表示**非可处置资产**。
    if truncated: findings.append(finding("project_scan_truncated","medium",safe_path(root),f"项目候选文件超过扫描上限 {file_limit}"))
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
    if sys.platform == "darwin":
        if not getattr(sys, "frozen", False) and str(BASE_DIR) not in sys.path:
            sys.path.insert(0, str(BASE_DIR))
        from aegis_macos_configuration import ConfigurationError, read_config
        try:
            return read_config(path)
        except ConfigurationError as exc:
            category = {"unsafe_file": "permissions", "unsafe_install_directory": "permissions",
                        "invalid_url": "url", "invalid_credentials": "secrets",
                        "independent_credentials_required": "secrets", "invalid_contract": "contract"}.get(str(exc), "invalid")
            raise ValueError("reporting_config_" + category) from None
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
def sync_policy_from_server(report_url,token,policy_path):
    """每周期自助拉取当前签名策略, 解决"策略手动分发"导致封禁/豁免下发不到终端
    (真机教训: 演练与豁免都卡在终端本地旧策略)。仅接受带 ed25519 签名且版本高于本地
    的工件(TLS 认证服务端 + ed25519 完整性); 任何失败静默保持本地策略, 绝不破坏现网。"""
    if not report_url or not token: return False
    try:
        u=urlsplit(report_url)
        if not u.scheme or not u.netloc: return False
        base=f"{u.scheme}://{u.netloc}"
        path=u.path or ""
        if "/aegis/" in path: base=base+"/aegis"
        elif "/api/" in path: base=base+"/api"
        url=base+"/v1/policy"
        req=urllib.request.Request(url,headers={"Authorization":"Bearer "+token})
        with urllib.request.urlopen(req,timeout=20) as r:
            data=json.loads(r.read().decode("utf-8"))
        if not isinstance(data,dict) or data.get("schema")!="aegis.policy/v1": return False
        if verify_policy_ed25519(data) is not True: return False
        try: cur=json.loads(Path(policy_path).read_text())
        except (OSError,ValueError): cur={}
        def vkey(v):
            try: return [int(x) for x in str(v).split(".")]
            except ValueError: return [0]
        if vkey(data.get("version"))<=vkey(cur.get("version")): return False
        tmp=Path(str(policy_path)+".sync.tmp")
        tmp.write_text(json.dumps(data,ensure_ascii=False))
        os.replace(str(tmp),str(policy_path))
        try: os.chmod(str(policy_path),0o644)
        except OSError: pass
        return True
    except Exception: return False
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
def write_upload_status(path,url,now=None,token=None,signing_secret=None):
    host=urlsplit(url).hostname
    if not host: raise ValueError("invalid_upload_status_host")
    value={"schema":"aegis.upload-status/v1","status":"accepted","last_success":int(time.time()) if now is None else int(now),"collector_host":host.lower().rstrip(".")}
    if sys.platform == "darwin" and token is not None and signing_secret is not None:
        from aegis_macos_configuration import config_fingerprint
        value["configuration_fingerprint"] = config_fingerprint({"schema": "aegis.reporting/v1",
            "report_url": url, "report_token": token, "signing_secret": signing_secret})
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
    _BAD = {"", "to be filled by o.e.m.", "none", "default string", "unknown", "o.e.m.", "not specified",
            "system serial number", "serial number", "n/a", "na", "empty", "to be filled"}
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
            # 降级链: 系统序列号 → BIOS → 主板(BaseBoard) → SMBIOS UUID(白牌机字符串序列号
            # 常为占位, UUID 通常烧录于主板更可靠; 全0/全F 排除)。与 aegis-windows.ps1 同序。
            ps = ("$b=@('to be filled by o.e.m.','none','default string','unknown','o.e.m.','not specified','system serial number','serial number','n/a','na','empty','to be filled');"
                  "$s=$null;"
                  "try{$c=(Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber;if($c -and $b -notcontains $c.Trim().ToLower()){$s=$c.Trim()}}catch{};"
                  "if(-not $s){try{$c=(Get-CimInstance Win32_BIOS).SerialNumber;if($c -and $b -notcontains $c.Trim().ToLower()){$s=$c.Trim()}}catch{}};"
                  "if(-not $s){try{$c=(Get-CimInstance Win32_BaseBoard).SerialNumber;if($c -and $b -notcontains $c.Trim().ToLower()){$s=$c.Trim()}}catch{}};"
                  "if(-not $s){try{$u=(Get-CimInstance Win32_ComputerSystemProduct).UUID;$t=$u.Replace('-','');if($t -and $t -notmatch '^(0+|F+)$'){$s=$u}}catch{}};"
                  "if($s){$s}else{''}")
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
    return BASE_DIR / "server-override.json"
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
    if sys.platform == "darwin":
        if not getattr(sys, "frozen", False) and str(BASE_DIR) not in sys.path:
            sys.path.insert(0, str(BASE_DIR))
        from aegis_macos_enrollment import request_config
        return request_config(server + "/api/enroll", server + "/aegis/v1/reports", device_id,
                              AGENT_VERSION, os.getenv("AEGIS_ENROLLMENT_SECRET", "")), None
    body = json.dumps({"hostname": os.uname().nodename, "device_id": device_id, "agent_version": AGENT_VERSION}).encode()
    req = urllib.request.Request(server + "/api/enroll", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        d = json.loads(r.read().decode())
    tok = str(d.get("report_token") or ""); sec = str(d.get("signing_secret") or "")
    ru = str(d.get("report_url") or (server + "/aegis/v1/reports"))
    if len(tok) < 32 or len(tok) > 4096: raise ValueError("enroll_token_invalid")
    if len(sec) < 32 or len(sec) > 4096: raise ValueError("enroll_secret_invalid")
    if not ru.startswith("https://"): raise ValueError("enroll_report_url_not_https")
    # 带外信任锚缓存：控制台经 TLS 下发的 ed25519 公钥（公开信息）落盘 644，供
    # load_policy 在"策略带 signature 但无 HMAC 验签环"的正常态做非对称验签
    # （防 2026-09-24 停报事故复发）。公钥非秘密；私钥/对称密钥绝不落盘于此。
    pub = d.get("ed25519_public")
    if isinstance(pub, str) and pub.strip():
        try:
            p = BASE_DIR / "ed25519-public.b64"
            p.write_text(pub.strip(), encoding="utf-8")
            os.chmod(p, 0o644)
        except OSError:
            pass
    return {"schema": "aegis.reporting/v1", "report_url": ru, "report_token": tok, "signing_secret": sec}, (d.get("policy") if isinstance(d.get("policy"), dict) else None)
_OVERRIDE_NOTED = {"fail": False}
def apply_server_override(args, host_device_id):
    """每周期检查 server-override.json：服务器变更则重新入网并改写上报配置/策略。
    失败保持现配置（SOFT FAIL），仅记一次 finding，绝不中断扫描/上报。
    返回 rep(dict)=已切换 / False=切换失败 / None=无需切换。"""
    if sys.platform == "darwin":
        try:
            if not getattr(sys, "frozen", False) and str(BASE_DIR) not in sys.path:
                sys.path.insert(0, str(BASE_DIR))
            from aegis_macos_enrollment import migrate
            rep = migrate(BASE_DIR, host_device_id, AGENT_VERSION, args.report_config,
                          bool(getattr(args, "enrollment_config", "") or getattr(args, "enrollment_dir", "")),
                          enrollment_key=os.getenv("AEGIS_ENROLLMENT_SECRET", ""))
            if rep is not None:
                args.report_url = rep["report_url"]
                args.report_config = str(BASE_DIR / "reporting.json")
            return rep
        except (ImportError, OSError, ValueError, TypeError):
            return False
    ov = read_server_override()
    if not ov or ov == report_url_origin(args.report_url):
        return None
    rpath = Path(args.report_config) if args.report_config else BASE_DIR / "reporting.json"
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
    return BASE_DIR / "enterprise-baseline.md"
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
# ── 物理网卡采集（MAC + 本机 IP）──────────────────────────────────────────
# 只收**物理**网卡：mac 用 networksetup -listallhardwareports（系统认定的硬件端口，
# 天然排除 utun/awdl/bridge/vmenet/pktap 等虚拟口）；linux 用 /sys/class/net/<if>/device
# 符号链接存在=有真实硬件（虚拟口无 device 节点），再排除 lo 与常见虚拟前缀。
# 本机 IP 只保留可路由地址：剔除回环(127.*/::1)、链路本地(169.254./fe80)。
# 互联网出口 IP 不在此采集——由 Collector 在收到上报时记录请求源 IP（NAT 后公网视角），
# 避免终端为测出口而外联第三方 IP 回显服务。
# 全程 try/except 兜底返回 {}：采集失败绝不能影响上报（容错哲学对齐 macOS 入网脚本）。
_VIRTUAL_IFACE_PREFIXES=("lo","bridge","veth","docker","br-","virbr","vmnet","vmenet","tap","tun","utun","awdl","llw","pktap","anpi","ipsec","bond","wg","zt","tailscale")
def _run_text(argv):
    try:
        r=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        return r.stdout or ""
    except Exception:
        return ""
def _physical_nics_darwin():
    out=_run_text(["networksetup","-listallhardwareports"])
    nics=[]; name=None
    for line in out.splitlines():
        line=line.strip()
        if line.startswith("Device:"):
            name=line.split(":",1)[1].strip()
            if name.startswith(_VIRTUAL_IFACE_PREFIXES): name=None  # bridge0(Thunderbolt Bridge)等聚合口=虚拟
        elif line.startswith("Ethernet Address:"):
            mac=line.split(":",1)[1].strip().lower()
            if name and mac and mac!="00:00:00:00:00:00":
                nics.append({"name":name,"mac":mac})
            name=None
    return nics
def _physical_nics_linux():
    base="/sys/class/net"; nics=[]
    try:
        for ifn in sorted(os.listdir(base)):
            if ifn=="lo" or ifn.startswith(_VIRTUAL_IFACE_PREFIXES): continue
            if not os.path.islink(os.path.join(base,ifn,"device")): continue  # 无硬件节点=虚拟口
            try:
                mac=open(os.path.join(base,ifn,"address")).read().strip().lower()
            except OSError:
                mac=""
            if not mac or mac=="00:00:00:00:00:00": continue
            nics.append({"name":ifn,"mac":mac})
    except OSError:
        pass
    return nics
def _iface_ips():
    ips={}
    if platform.system()=="Darwin":
        cur=None
        for line in _run_text(["ifconfig"]).splitlines():
            if line and not line[0].isspace():
                cur=line.split(":",1)[0].strip(); ips.setdefault(cur,[])
            else:
                s=line.strip()
                if cur and s.startswith("inet "):
                    a=s.split()[1].split("%")[0]
                    if not a.startswith("127.") and not a.startswith("169.254."): ips[cur].append(a)
                elif cur and s.startswith("inet6 "):
                    a=s.split()[1].split("%")[0]
                    if not a.startswith("fe80") and a!="::1": ips[cur].append(a)
    else:
        for line in _run_text(["ip","-o","addr","show"]).splitlines():
            f=line.split()
            if len(f)>=4 and f[2] in ("inet","inet6"):
                a=f[3].split("/")[0].split("%")[0]
                if a.startswith("127.") or a.startswith("169.254.") or a.startswith("fe80") or a=="::1": continue
                ips.setdefault(f[1],[]).append(a)
    return ips
def collect_physical_network():
    try:
        nics=_physical_nics_darwin() if platform.system()=="Darwin" else _physical_nics_linux()
        ips=_iface_ips(); out=[]
        for n in nics:
            n=dict(n); n["ips"]=ips.get(n["name"],[]); out.append(n)
        return {"physical_nics":out,"macs":[n["mac"] for n in out],"local_ips":[i for n in out for i in n["ips"]]}
    except Exception:
        return {}
# 代码质量类发现 kind 清单(code_scan 关闭时的 report 兜底过滤)。与 scan_text 的
# checks/quality_checks/agentic_checks 对应; skill 治理类(unknown_skill/skill_symlink_escape)
# 与运维类(project_scan_truncated 等)不在此列——关代码扫描≠关 skill 治理与运维可见性。
CODE_QUALITY_KINDS={"prompt_override","credential_access","unbounded_shell","dynamic_eval",
 "insecure_tls_verification","unsafe_deserialization","debug_mode_enabled","empty_exception_handler",
 "context_poisoning","unvalidated_llm_execution","hardcoded_secret","weak_random_token",
 "dependency_unpinned","missing_lockfile","blocked_command","hidden_instruction"}
def build_report(root,policy):
    inventory,findings=scan(root,policy)
    baseline_inv,baseline_findings=verify_user_baselines()
    inventory.extend(baseline_inv); findings.extend(baseline_findings)
    # code_scan only controls code quality; identified Skill governance survives.
    if not policy_module(policy,"code_scan",False):
        findings=[f for f in findings if retain_finding_without_code_scan(f)]
    # 用户级安装已取消(2026-09): mac 非 root 运行=历史用户级安装, 能力受限(仅扫当前用户、
    # 无 pf 连接级封禁)。产出发现项让控制台可见, 驱动迁移到系统级 .pkg。(置于截断上限之前)
    if sys.platform=="darwin" and os.geteuid()!=0:
        findings.append(finding("user_level_deprecated","medium",str(BASE_DIR),"用户级安装已取消: 本机以非 root 运行, 仅扫当前用户且无连接级封禁; 请用系统级 .pkg 重装"))
    if len(inventory)>REPORT_INVENTORY_LIMIT:
        inventory=inventory[:REPORT_INVENTORY_LIMIT-1]+[{"type":"inventory_truncated","omitted":len(inventory)-REPORT_INVENTORY_LIMIT+1}]
    if len(findings)>REPORT_FINDING_LIMIT:
        omitted=len(findings)-REPORT_FINDING_LIMIT+1; findings=findings[:REPORT_FINDING_LIMIT-1]+[finding("findings_truncated","medium",root,f"报告发现项超限，省略 {omitted} 项")]
    network=collect_physical_network() if policy_module(policy,"network_collect",True) else {}
    # 能力诚实化(#3): 上报运行态与真实封禁能力, 控制台按设备标注, 不夸大。
    run_mode="system" if (hasattr(os,"geteuid") and os.geteuid()==0) else "user"
    _esst=_es_guard_status()
    caps={"pf":(sys.platform=="darwin" and run_mode=="system"),"es":(_esst.get("state")=="active")}
    # 回执=本周期对账 + 高频 tick 累积的未上报回执(一次性 drain, 避免重复上报)。
    enforcement=reconcile_enforcement(policy)
    if ENFORCE_RECEIPTS: enforcement=ENFORCE_RECEIPTS+enforcement; del ENFORCE_RECEIPTS[:]
    enforcement=enforcement[:40]
    report = {"schema":"aegis.report/v1","agent_version":AGENT_VERSION,"policy_version":policy["version"],"device_id":hardware_device_id(),"hostname":os.uname().nodename,"os_user":interactive_os_user(),"owner":(os.environ.get("AEGIS_DEVICE_OWNER") or "")[:64],"os":platform.system().lower()[:16],"serial":device_serial()[:64],"network":network,"enforcement":enforcement,"run_mode":run_mode,"capabilities":caps,"enterprise_baseline_version":ENTERPRISE_BASELINE_VERSION,"scanned_at":int(time.time()),"scan_root":safe_path(root),"inventory":inventory,"summary":{s:sum(f["severity"]==s for f in findings) for s in ["critical","high","medium","low"]},"findings":findings}
    # 自更非例行结果（updated/preflight_failed/rolled_back/apply_failed）随报告上报；例行不上报。
    if _SELF_UPDATE_RESULT is not None: report["self_update"] = _SELF_UPDATE_RESULT
    return report
def add_report_finding(report,item):
    if len(report["findings"])<REPORT_FINDING_LIMIT: report["findings"].append(item)
    else: report["findings"][-1]=item
    report["summary"]={severity:sum(f["severity"]==severity for f in report["findings"]) for severity in ["critical","high","medium","low"]}
AGENT_VERSION = "0.37.3"

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


def self_update_binary_artifact_name() -> str:
    """冻结二进制自更新的工件名：aegis-agent-<os>-<arch>，与 release manifest 的 binary 工件键一致。
    os=platform.system().lower()(darwin/linux/windows)；arch 归一 x86_64/amd64→x64、aarch64→arm64。"""
    os_name = platform.system().lower()[:16]
    m = (platform.machine() or "").lower()
    arch = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(m, m)
    return f"aegis-agent-{os_name}-{arch}"


def _binary_selftest_preflight(path, timeout=20):
    """Check executable health before replacement; this is not authenticity validation.

    Mac candidates must pass both client and embedded maintenance checks within
    one time budget. Legacy CLI compatibility is retained only on other systems.
    """
    deadline = time.monotonic() + timeout
    try:
        os.chmod(path, 0o755)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        result = subprocess.run([path, "--selftest"], capture_output=True,
                                timeout=remaining, check=False)
        if sys.platform == "darwin":
            if result.returncode != 0:
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            maintenance = subprocess.run([path, "--maintenance-selftest"], capture_output=True,
                                         timeout=remaining, check=False)
            return maintenance.returncode == 0
        if result.returncode == 0:
            return True
        error = (result.stderr or b"").decode("utf-8", "replace").lower()
        return result.returncode == 2 and any(word in error for word in ("unrecognized", "usage", "invalid"))
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


# 本进程最近一次自更新的"非例行"结果（updated / preflight_failed / rolled_back:* /
# apply_failed:*）。例行结果(up_to_date/already_current/not_in_rollout)不上报，避免刷屏；
# 非例行结果随报告上报，让"坏更新被 preflight 拒绝 / 自动回滚"在控制台可观测（canary 监控闭环）。
_SELF_UPDATE_RESULT = None


def maybe_self_update(policy, report_url):
    """无桌管环境的自更新兜底通道；主通道永远是桌管/MDM 推送。

    仅当策略 agent_self_update.enabled=true 且能推导 manifest URL 时执行。
    best-effort：任何失败静默返回，绝不影响本轮扫描/上报。
    """
    global _SELF_UPDATE_RESULT
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
    frozen = getattr(sys, "frozen", False)
    try:
        script_dir = str(BASE_DIR)
        if not frozen and script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import aegis_self_update as su
    except Exception:
        return
    device_id = hardware_device_id()
    # pinned 设备(开发主机等)永不自动更新, 只接受人工/桌管更新: 防坏更新打到主力开发机。
    pinned = [str(x) for x in (cfg.get("pinned") or [])]
    if device_id in pinned:
        return
    # 冻结二进制(去-python 化 B)：热替换 sys.executable 自身。mac/linux 上 os.replace 覆盖运行中的
    # 可执行文件是安全的(运行进程留旧 inode，下次 exec 用新文件；已实测)，无需重装 pkg——即
    # "手动装用 pkg、后台热更直接换二进制文件"的分工。工件按 os/arch 取；python3 形态仍换 aegis_agent.py。
    if frozen:
        artifact_name = self_update_binary_artifact_name()
        target = sys.executable
        preflight = _binary_selftest_preflight  # 冻结二进制：exec 新工件 --selftest 校验后再替换
    else:
        artifact_name = "aegis_agent.py"
        target = str(BASE_DIR / "aegis_agent.py")
        preflight = None  # 脚本形态：用 check_and_apply 内置的 .py 语法解析 preflight
    try:
        res = su.check_and_apply(
            manifest_url,
            AGENT_VERSION,
            device_id,
            artifact_name,
            target,
            rollout_percent=int(cfg.get("rollout_percent", 100)),
            preflight=preflight,
        )
        if res.get("updated"):
            receipt_status = "ok"
            if frozen and sys.platform == "darwin":
                try:
                    digest = res.get("sha256")
                    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                        raise ValueError("invalid_applied_digest")
                    write_private_atomic(BASE_DIR / "aegis-update-receipt.json", json.dumps({
                        "schema": "aegis.update-receipt/v1", "artifact": artifact_name,
                        "agent_version": res.get("to"), "sha256": digest}))
                except (OSError, ValueError):
                    receipt_status = "updated_receipt_unavailable"
            print(f"aegis agent self-updated {res.get('from')} -> {res.get('to')}; next run uses new version", file=sys.stderr)
            _SELF_UPDATE_RESULT = {"updated": True, "reason": receipt_status, "from": res.get("from"), "to": res.get("to"), "at": int(time.time())}
        elif res.get("reason") not in ("up_to_date", "already_current", "not_in_rollout", None):
            # 让 preflight 拒绝 / 自动回滚 / 应用失败这些"非例行"结果在服务日志里可见（运维/应急据此排查），
            # 但不刷屏例行的 up_to_date/already_current/not_in_rollout。同时记入 _SELF_UPDATE_RESULT 随报告上报。
            print(f"aegis self-update not applied: {res.get('reason')} (latest={res.get('latest')})", file=sys.stderr)
            _SELF_UPDATE_RESULT = {"updated": False, "reason": res.get("reason"), "latest": res.get("latest"), "at": int(time.time())}
    except Exception:
        return


def install_config(argv):
    """Mac enrollment uses the protected embedded reporting writer.

    Non-Mac legacy callers retain their existing configuration behavior.
    """
    if sys.platform == "darwin":
        if not getattr(sys, "frozen", False) and str(BASE_DIR) not in sys.path:
            sys.path.insert(0, str(BASE_DIR))
        from aegis_macos_enrollment import main as enroll_main
        return enroll_main(argv, BASE_DIR)
    import socket, secrets, urllib.error
    install_dir, collector_url, enroll_url, device_id, interval, token, agent_ver = argv[:7]
    interval = int(interval); manual = bool(token)
    report_url = collector_url.rstrip("/") + "/v1/reports"
    signing_secret = os.environ.get("AEGIS_REPORT_SIGNING_SECRET", "")
    policy = None
    if manual:
        if "<" in token and ">" in token:
            print("  x 令牌是占位符（如 '<令牌>'）。请填真实令牌，或留空以零接触自动入网。", file=sys.stderr); raise SystemExit(2)
        if not (32 <= len(token) <= 4096):
            print("  x 令牌长度 %d 不在 32-4096。请填真实令牌，或留空以自动入网。" % len(token), file=sys.stderr); raise SystemExit(2)
        if not signing_secret: signing_secret = secrets.token_hex(32)
    else:
        req = urllib.request.Request(enroll_url, data=json.dumps({"hostname": socket.gethostname(), "device_id": device_id, "agent_version": agent_ver}).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r: d = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            print("  x 自动入网失败 HTTP %s: %s" % (e.code, e.read().decode()[:200]), file=sys.stderr); raise SystemExit(3)
        except Exception as e:
            print("  x 自动入网失败 %s（请检查能否访问 %s）" % (type(e).__name__, enroll_url), file=sys.stderr); raise SystemExit(3)
        token = d.get("report_token") or ""
        signing_secret = d.get("signing_secret") or signing_secret or secrets.token_hex(32)
        report_url = d.get("report_url") or report_url
        pol = d.get("policy")
        if isinstance(pol, dict) and pol.get("schema") == "aegis.policy/v1": policy = pol
        if not (32 <= len(token) <= 4096):
            print("  x 入网响应缺少有效 report_token（服务端未配置 AEGIS_COLLECTOR_TOKEN？）", file=sys.stderr); raise SystemExit(4)
    if policy is not None:
        p = os.path.join(install_dir, "aegis-policy.json")
        open(p, "w", encoding="utf-8").write(json.dumps(policy, ensure_ascii=False)); os.chmod(p, 0o600)
    os.makedirs(install_dir, exist_ok=True)
    cfg = {"collectorURL": collector_url, "reportURL": report_url, "deviceId": device_id, "token": token, "hmacSecret": signing_secret, "scanIntervalSeconds": interval, "scanRoot": None}
    open(os.path.join(install_dir, "config.json"), "w", encoding="utf-8").write(json.dumps(cfg, ensure_ascii=False)); os.chmod(os.path.join(install_dir, "config.json"), 0o600)
    rpt = {"schema": "aegis.reporting/v1", "report_url": report_url, "report_token": token, "signing_secret": signing_secret}
    open(os.path.join(install_dir, "reporting.json"), "w", encoding="utf-8").write(json.dumps(rpt, ensure_ascii=False)); os.chmod(os.path.join(install_dir, "reporting.json"), 0o600)
    print("  + 凭据来源: %s | 上报: %s | 策略: %s" % ("手动令牌" if manual else "自动入网", report_url, (policy or {}).get("version", "包内出厂")))


def run_selftest():
    """轻量自检：证明"这份 Agent（脚本或冻结二进制）本身可用"，供自更新 preflight 在
    原子替换前校验下载到的新工件、以及 CI 冻结烟雾使用。

    只验证：核心符号可调用、内嵌/同目录的 aegis_self_update 可导入、AGENT_VERSION 合法、
    同目录出厂策略(若存在)可解析。**绝不联网、不扫描、不写盘、不需要 root**，秒级返回。
    成功 exit 0；任何异常 exit 1（preflight 据此拒绝坏工件、保留旧版本，绝不把机队更新成砖）。
    """
    try:
        script_dir = str(BASE_DIR)
        if not getattr(sys, "frozen", False) and script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import aegis_self_update as _su
        if sys.platform == "darwin":
            import aegis_macos_maintenance as _maintenance
            if not _maintenance.selftest():
                raise ValueError("maintenance_selftest_failed")
            import aegis_macos_configuration as _configuration
            if not _configuration.selftest():
                raise ValueError("configuration_selftest_failed")
            import aegis_macos_enrollment as _enrollment
            if not _enrollment.selftest():
                raise ValueError("enrollment_selftest_failed")
            import aegis_macos_service_migration as _service_migration
            if not _service_migration.selftest():
                raise ValueError("service_migration_selftest_failed")
            import aegis_macos_runtime_activation as _activation
            if not _activation.selftest():
                raise ValueError("runtime_activation_selftest_failed")
            import aegis_macos_user_retirement as _user_retirement
            if not _user_retirement.selftest():
                raise ValueError("user_retirement_selftest_failed")
            import aegis_macos_diagnostics as _diagnostics
            if not _diagnostics.selftest():
                raise ValueError("diagnostics_selftest_failed")
        for fn in (build_report, hardware_device_id, _su.check_and_apply, _su.in_rollout):
            if not callable(fn):
                raise ValueError("missing_callable:%r" % (fn,))
        if not (isinstance(AGENT_VERSION, str) and AGENT_VERSION):
            raise ValueError("bad_agent_version")
        # 同目录出厂策略若随包分发则确认可解析；缺失/不可读不算失败（自检只证明二进制自身可用）。
        try:
            if DEFAULT_POLICY.is_file():
                json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        print("aegis-selftest-ok", AGENT_VERSION)
        return 0
    except Exception as e:  # noqa: BLE001 - 自检必须捕获一切并如实报错
        print("aegis-selftest-fail: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1


def main():
    activation_modes = {"--stage-native-runtime": "stage", "--confirm-native-runtime": "confirm", "--restore-native-runtime": "restore", "--runtime-activation-selftest": "selftest"}
    if any(arg.split("=", 1)[0] in activation_modes for arg in sys.argv[1:]):
        if len(sys.argv) != 2 or sys.argv[1] not in activation_modes or sys.platform != "darwin":
            print("Aegis runtime activation requires macOS and one exclusive mode", file=sys.stderr)
            return 2
        try:
            import aegis_macos_runtime_activation as activation
            if activation_modes[sys.argv[1]] == "selftest":
                if not activation.selftest():
                    return 1
                print("aegis-runtime-activation-selftest-ok")
                return 0
            return activation.main(BASE_DIR, activation_modes[sys.argv[1]], AGENT_VERSION)
        except ImportError:
            print("Aegis runtime activation is unavailable", file=sys.stderr)
            return 1
    retirement_flags = ("--user-retirement-selftest", "--retire-legacy-user")
    if any(arg.split("=", 1)[0] in retirement_flags for arg in sys.argv[1:]):
        if len(sys.argv) != 2 or sys.argv[1] not in retirement_flags or sys.platform != "darwin":
            print("Aegis user retirement requires macOS and one exclusive mode", file=sys.stderr)
            return 2
        try:
            import aegis_macos_user_retirement as retirement
            if sys.argv[1] == "--user-retirement-selftest":
                if not retirement.selftest():
                    return 1
                print("aegis-user-retirement-selftest-ok")
                return 0
            return retirement.main()
        except (ImportError, AttributeError):
            print("Aegis user retirement runtime is unavailable", file=sys.stderr)
            return 1
    migration_flags = ("--service-migration-selftest", "--prepare-legacy-services", "--restore-legacy-services")
    if any(arg.split("=", 1)[0] in migration_flags for arg in sys.argv[1:]):
        if len(sys.argv) != 2 or sys.argv[1] not in migration_flags or sys.platform != "darwin":
            print("Aegis service migration requires macOS and one exclusive mode", file=sys.stderr)
            return 2
        try:
            import aegis_macos_service_migration as migration
            if sys.argv[1] == "--service-migration-selftest":
                if not migration.selftest():
                    return 1
                print("aegis-service-migration-selftest-ok")
                return 0
            return migration.main(BASE_DIR, restore=sys.argv[1] == "--restore-legacy-services")
        except ImportError:
            print("Aegis service migration runtime is unavailable", file=sys.stderr)
            return 1
    if sys.platform == "darwin" and any(arg.split("=", 1)[0] == "--install-config" for arg in sys.argv[1:]):
        if len(sys.argv) != 9 or sys.argv[1] != "--install-config":
            print('{"schema":"aegis.enrollment-result/v1","status":"invalid_install_invocation","applied":false,"health_verified":false}')
            return 2
        return install_config(sys.argv[2:])
    configuration_flags = ("--configure-reporting", "--configuration-selftest")
    if any(arg.split("=", 1)[0] in configuration_flags for arg in sys.argv[1:]):
        if len(sys.argv) != 2 or sys.argv[1] not in configuration_flags or sys.platform != "darwin":
            print("Aegis configuration requires macOS and one exclusive mode", file=sys.stderr)
            return 2
        try:
            import aegis_macos_configuration as configuration
            if sys.argv[1] == "--configuration-selftest":
                if not configuration.selftest():
                    return 1
                print("aegis-configuration-selftest-ok")
                return 0
            return configuration.main(BASE_DIR)
        except ImportError:
            print("Aegis configuration runtime is unavailable", file=sys.stderr)
            return 1
    diagnostic_flags = ("--diagnostics", "--diagnostics-selftest")
    if any(arg.split("=", 1)[0] in diagnostic_flags for arg in sys.argv[1:]):
        if len(sys.argv) != 2 or sys.argv[1] not in diagnostic_flags or sys.platform != "darwin":
            print("Aegis diagnostics requires macOS and one exclusive mode", file=sys.stderr)
            return 2
        try:
            import aegis_macos_diagnostics as diagnostics
            if sys.argv[1] == "--diagnostics-selftest":
                if not diagnostics.selftest():
                    return 1
                print("aegis-diagnostics-selftest-ok")
                return 0
            return diagnostics.main(BASE_DIR, AGENT_VERSION, validate_policy)
        except (ImportError, AttributeError):
            print("Aegis diagnostics runtime is unavailable", file=sys.stderr)
            return 1
    # Maintenance is an exclusive mode. Reject mixed arguments before parsing
    # scan/enrollment options or touching machine identity, services or files.
    maintenance_flags = ("--maintenance-selftest", "--uninstall-system")
    if any(arg.split("=", 1)[0] in maintenance_flags for arg in sys.argv[1:]):
        if len(sys.argv) != 2 or sys.argv[1] not in maintenance_flags or sys.platform != "darwin":
            print("Aegis maintenance requires macOS and one exclusive mode", file=sys.stderr)
            return 2
        try:
            import aegis_macos_maintenance as maintenance
            return maintenance.main(["--selftest"] if sys.argv[1] == "--maintenance-selftest" else [])
        except (ImportError, AttributeError):
            print("Aegis maintenance runtime is unavailable; repair the installation", file=sys.stderr)
            return 1
    ap=argparse.ArgumentParser(description="Aegis AI Agent 安全扫描器"); ap.add_argument("scan_path",nargs="?",default="."); ap.add_argument("--policy",default=str(DEFAULT_POLICY)); ap.add_argument("--output"); ap.add_argument("--install-baseline",action="store_true"); ap.add_argument("--auto-enroll",action="store_true"); ap.add_argument("--watch",action="store_true"); ap.add_argument("--interval",type=int,default=300); ap.add_argument("--report-url",default=os.getenv("AEGIS_REPORT_URL","")); ap.add_argument("--report-config",default=os.getenv("AEGIS_REPORT_CONFIG","")); ap.add_argument("--spool-dir",default=os.getenv("AEGIS_SPOOL_DIR","")); ap.add_argument("--enrollment-config",default=os.getenv("AEGIS_ENROLLMENT_CONFIG","")); ap.add_argument("--enrollment-dir",default=os.getenv("AEGIS_ENROLLMENT_DIR","")); ap.add_argument("--install-config",nargs=7,metavar=("INSTALL_DIR","COLLECTOR_URL","ENROLL_URL","DEVICE_ID","INTERVAL","TOKEN","AGENT_VER"),help=argparse.SUPPRESS); ap.add_argument("--selftest",action="store_true",help=argparse.SUPPRESS); args=ap.parse_args()
    # 自检模式：证明"本工件（脚本/冻结二进制）自身可用"，供自更新 preflight 在替换前校验下载的
    # 新工件、以及 CI 冻结烟雾使用；成功 exit 0，任何异常 exit 1。不联网/不扫描/不写盘/不需 root。
    if args.selftest: return run_selftest()
    # 安装期一次性配置模式（去-python 化 B）：安装器以冻结二进制跑本模式完成入网+写配置后立即退出，
    # 使 .run/.pkg 安装全程无需系统 python3。
    if args.install_config: return install_config(args.install_config)
    # 扫描看门狗（watch 模式）：每个周期在**子进程**内跑一次性扫描+上报，父进程以
    # 时间预算(AEGIS_SCAN_BUDGET_SECONDS,默认1800s)监督；子进程挂死(如阻塞在 hung/
    # 网络挂载的 open())会被 kill，父进程记录 scan_timeout 并进入下一周期，绝不让
    # 守护循环整体挂死。配合 scan() 跳过子目录挂载点，双保险。
    if args.watch:
        try: budget=min(max(int(os.getenv("AEGIS_SCAN_BUDGET_SECONDS","1800")),60),86400)
        except (TypeError,ValueError): budget=1800
        child_argv=([sys.executable] if getattr(sys,"frozen",False) else [sys.executable,str(Path(__file__).resolve())])+[a for a in sys.argv[1:] if a!="--watch"]
        return run_watch_loop(child_argv,budget,args.interval,failure_marker=BASE_DIR/"watch-cleanup-pending.json")
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
            candidate=BASE_DIR / "reporting.json"
            if candidate.is_file(): args.report_config=str(candidate)
        if args.report_config:
            try: reporting=load_reporting_config(args.report_config); args.report_url=reporting["report_url"]
            except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError): reporting_error=True; args.report_url=""
    # 自更新必须在 report_url 定稿之后调用：LaunchDaemon/Agent 以 --report-config 传入上报配置，
    # args.report_url 要到上面 load_reporting_config 才被赋值；此前在赋值前调用 → manifest_url
    # 恒空 → 自更新静默不执行（用户手动装新客户端后"未来自更新"不生效的根因）。
    if policy_module(policy,"self_update",True): maybe_self_update(policy, args.report_url)
    if args.install_baseline and policy_module(policy,"baseline_install",True): install_baseline(root)
    while True:
        # Mac uses a protected administrator migration intent and credential writer.
        # Policy/trust changes are separate; failure cannot bypass device enrollment.
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
        # 策略自助同步(默认开, 可以 modules.policy_auto_sync 关): 拉签名策略, 版本更新才落盘,
        # 使封禁/豁免/模块开关能下发到终端(此前手动分发导致终端永远停在旧策略)。
        if policy_module(policy,"policy_auto_sync",True):
            _tok=(enrollment or {}).get("report_token") or (reporting or {}).get("report_token") or os.getenv("AEGIS_REPORT_TOKEN","")
            sync_policy_from_server(args.report_url,_tok,args.policy)
        policy,reload_failed=reload_policy(args.policy,policy,require_signature=require_signature)
        # 先拉取企业级 MD（按灰度范围）再注入基线：保证本轮注入即用最新企业 MD，
        # 否则新发布的企业 MD 要延迟一个扫描周期才生效（注入早于拉取的历史缺陷）。
        eb_token=(enrollment or {}).get("report_token") or (reporting or {}).get("report_token") or os.getenv("AEGIS_REPORT_TOKEN","")
        eb_base=(args.report_url or "").replace("/v1/reports","")
        eb_dept=(enrollment or {}).get("department") or os.environ.get("AEGIS_DEVICE_DEPARTMENT","")
        if policy_module(policy,"baseline_install",True): sync_enterprise_baseline(eb_base, eb_token, host_device_id, eb_dept)
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
            add_report_finding(report,finding("server_override_failed","medium",str(server_override_path()),"控制台迁移未完成；请检查受保护迁移请求、凭据模式及网络状态，本轮未替换上报配置")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if isinstance(_ov, dict) and _ov.get("_migration_status") == "applied_durability_unconfirmed":
            add_report_finding(report,finding("server_migration_durability_unconfirmed","medium",str(server_override_path()),"迁移配置已替换，但目录同步未确认；本轮使用新配置，需核实持久性与上报健康")); data=json.dumps(report,ensure_ascii=False,indent=2)
        if args.output: write_private_atomic(args.output,data)
        can_report=bool(args.report_url) and not reporting_error and not enrollment_error and not enrollment_mismatch
        if can_report:
            if enrollment: token=enrollment["report_token"]; signing=enrollment["signing_secret"]
            elif reporting: token=reporting["report_token"]; signing=reporting["signing_secret"]
            else: token=os.getenv("AEGIS_REPORT_TOKEN",""); signing=None
            spool=Path(args.spool_dir) if args.spool_dir else (Path(args.output).parent/"spool" if args.output else Path.home()/".aegis-agent/spool")
            # 离线队列上限：签名策略 limits.offline_queue_max 优先（控制台全局配置下发），回落 env/默认。
            spool_cap=(policy.get("limits") or {}).get("offline_queue_max") if isinstance(policy,dict) else None
            status_path=(Path(args.output).parent if args.output else spool.parent)/"upload-status.json"
            try: flush_spool(spool,args.report_url,token,signing); post_report(args.report_url,token,report,signing); write_upload_status(status_path,args.report_url,token=token,signing_secret=signing)
            except Exception as exc:
                # 凭据被拒(401/403)时一次自愈：重新入网刷新凭据并重试一轮；否则本地排队。
                refreshed=maybe_reenroll_on_auth_failure(exc,args,root,enroll_path,host_device_id)
                if refreshed is not None:
                    enrollment=refreshed
                    try: post_report(args.report_url,refreshed["report_token"],report,refreshed["signing_secret"]); write_upload_status(status_path,args.report_url,token=refreshed["report_token"],signing_secret=refreshed["signing_secret"])
                    except Exception: queue_report(spool,report,spool_cap); print("report upload failed after re-enroll; queued locally",file=sys.stderr)
                else:
                    queue_report(spool,report,spool_cap); print(f"report upload failed; queued locally: {exc}",file=sys.stderr)
        print(data)
        if not args.watch: return 2 if report["summary"]["critical"] or report["summary"]["high"] else 0
        # 高频封禁 tick: 把睡眠切成 ENFORCE_TICK_SECONDS 段, 段间做轻量封禁对账,
        # 使"被禁资产复发"在秒级被再封(而非等下一轮小时级全扫描)。回执累积进下次上报。
        remain=max(args.interval,60)
        while remain>0:
            step=min(ENFORCE_TICK_SECONDS,remain)
            time.sleep(step); remain-=step
            if remain>0:
                try:
                    tick_actions=reconcile_enforcement(policy)
                    if tick_actions:
                        ENFORCE_RECEIPTS.extend(tick_actions); del ENFORCE_RECEIPTS[:-40]
                except Exception:
                    pass
if __name__=="__main__": sys.exit(main())
