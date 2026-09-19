#!/usr/bin/env python3
"""
verify-evidence-bundle.py — Aegis 证据包（aegis.evidence/v1）离线验签器（权威路径）。

接收方无需登录控制台、无需任何密钥即可验证一个证据包是否被篡改：
  1) schema 校验；
  2) manifest 逐节校验：对每个 section 重算 sha256(canonical_json(section)) 与包内比对；
  3) ed25519 验签：剔除 ed25519_* 字段后重算 canonical_json(core)，用包内公钥验签。

任一字节被改 → 验签失败。签名约定与控制台 lib/policy.ts、lib/evidence.ts 完全一致，
ed25519 与 canonical_json 实现直接沿用终端 Agent（public/downloads/aegis_agent.py）
的纯 Python 版本，不引入任何第三方依赖（对齐 SEC-AGT-05 供应链约束）。

用法:
  python3 scripts/verify-evidence-bundle.py <bundle.json>
  python3 scripts/verify-evidence-bundle.py --quiet <bundle.json>   # 只输出 OK/FAIL

退出码: 0=验证通过; 1=验证失败(篡改/签名无效/manifest 不符); 2=用法/读取错误;
        3=未签名包(integrity=unsigned, 无 ed25519 可验)。
"""
import base64
import hashlib
import json
import sys

SCHEMA = "aegis.evidence/v1"
ED_FIELDS = ("ed25519_signature", "ed25519_public", "ed25519_key_id")


# ── canonical_json：必须与控制台 lib/policy.ts canonicalJson 逐字节一致 ──
def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def section_sha256(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# ── Ed25519 (RFC8032) 纯 Python 验签（沿用 aegis_agent.py 实现）──────────
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
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _ED_P:
        return None
    x = _ed_recover_x(y, sign)
    if (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_P != 0:
        return None
    return (x, y, 1, (x * y) % _ED_P)


_ED_BY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
_ED_B = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_P)


def _ed_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (2 * t1 * t2 * _ED_D) % _ED_P
    dd = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (dd - c) % _ED_P
    g = (dd + c) % _ED_P
    h = (b + a) % _ED_P
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mult(P, e):
    R = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            R = _ed_add(R, P)
        P = _ed_add(P, P)
        e >>= 1
    return R


def _ed_equal(P, Q):
    x1, y1, z1, _t1 = P
    x2, y2, z2, _t2 = Q
    return (x1 * z2 - x2 * z1) % _ED_P == 0 and (y1 * z2 - y2 * z1) % _ED_P == 0


def ed25519_verify(pub, msg, sig):
    """RFC8032 Ed25519 验签（仅验签）。pub/msg/sig 为 bytes。"""
    if len(sig) != 64 or len(pub) != 32:
        return False
    R = _ed_decode_point(sig[:32])
    A = _ed_decode_point(pub)
    if R is None or A is None:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _ED_L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _ED_L
    return _ed_equal(_ed_mult(_ED_B, S), _ed_add(R, _ed_mult(A, k)))


# ── 验证主逻辑 ──────────────────────────────────────────────────────────
def verify(bundle):
    """返回 (ok: bool, report: dict)。report 含 schema_ok/manifest_ok/ed25519_ok/mismatched/reason。"""
    rep = {"schema_ok": False, "manifest_ok": False, "ed25519_ok": None, "mismatched": [], "reason": "", "unsigned": False}
    if not isinstance(bundle, dict):
        rep["reason"] = "not_an_object"
        return False, rep

    rep["schema_ok"] = bundle.get("schema") == SCHEMA
    if not rep["schema_ok"]:
        rep["reason"] = "bad_schema:%r" % (bundle.get("schema"),)
        return False, rep

    # manifest 逐节校验
    sections = bundle.get("sections") or {}
    manifest = bundle.get("manifest") or {}
    if not isinstance(sections, dict) or not isinstance(manifest, dict):
        rep["reason"] = "bad_sections_or_manifest"
        return False, rep
    for name, meta in manifest.items():
        if name not in sections:
            rep["mismatched"].append("%s:missing" % name)
            continue
        expected = (meta or {}).get("sha256") if isinstance(meta, dict) else None
        if section_sha256(sections[name]) != expected:
            rep["mismatched"].append(name)
    rep["manifest_ok"] = len(rep["mismatched"]) == 0

    # ed25519 验签（公钥随包携带，离线可验）
    pub_b64 = bundle.get("ed25519_public")
    sig_b64 = bundle.get("ed25519_signature")
    if not (isinstance(pub_b64, str) and pub_b64 and isinstance(sig_b64, str) and sig_b64):
        rep["unsigned"] = bundle.get("integrity") == "unsigned"
        rep["ed25519_ok"] = None
        rep["reason"] = "unsigned_bundle" if rep["unsigned"] else "missing_signature"
        return False, rep
    try:
        pub = base64.b64decode(pub_b64)
        sig = base64.b64decode(sig_b64)
    except Exception:
        rep["ed25519_ok"] = False
        rep["reason"] = "bad_base64"
        return False, rep
    core = {k: v for k, v in bundle.items() if k not in ED_FIELDS}
    rep["ed25519_ok"] = ed25519_verify(pub, canonical_json(core).encode("utf-8"), sig)
    if not rep["ed25519_ok"]:
        rep["reason"] = "ed25519_invalid"
        return False, rep

    ok = rep["schema_ok"] and rep["manifest_ok"] and rep["ed25519_ok"] is True
    if not ok and not rep["reason"]:
        rep["reason"] = "manifest_mismatch"
    return ok, rep


def main(argv):
    quiet = False
    args = []
    for a in argv[1:]:
        if a in ("--quiet", "-q"):
            quiet = True
        elif a in ("--help", "-h"):
            print(__doc__)
            return 0
        else:
            args.append(a)
    if len(args) != 1:
        sys.stderr.write("usage: verify-evidence-bundle.py [--quiet] <bundle.json>\n")
        return 2
    try:
        with open(args[0], "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except OSError as e:
        sys.stderr.write("read error: %s\n" % e)
        return 2
    except ValueError as e:
        sys.stderr.write("invalid JSON: %s\n" % e)
        return 2

    ok, rep = verify(bundle)
    if quiet:
        print("OK" if ok else "FAIL")
        return 0 if ok else (3 if rep.get("unsigned") else 1)

    counts = {k: (v or {}).get("count") for k, v in (bundle.get("manifest") or {}).items()} if isinstance(bundle, dict) else {}
    print("Aegis 证据包验证")
    print("  文件        : %s" % args[0])
    if isinstance(bundle, dict):
        print("  schema      : %s" % bundle.get("schema"))
        print("  生成时间    : %s" % bundle.get("generated_at"))
        print("  生成者      : %s" % bundle.get("generated_by"))
        print("  范围        : %s" % json.dumps(bundle.get("scope"), ensure_ascii=False))
        print("  脱敏级别    : %s" % bundle.get("redaction"))
        print("  各节条数    : %s" % json.dumps(counts, ensure_ascii=False))
    print("  schema 校验 : %s" % ("通过" if rep["schema_ok"] else "失败"))
    print("  manifest    : %s%s" % ("通过" if rep["manifest_ok"] else "失败", ("（不符: %s）" % ",".join(rep["mismatched"])) if rep["mismatched"] else ""))
    ed = rep["ed25519_ok"]
    ed_txt = "通过" if ed is True else ("未签名" if ed is None else "失败")
    print("  ed25519 验签: %s" % ed_txt)
    if rep["reason"]:
        print("  结论原因    : %s" % rep["reason"])
    print("  最终结论    : %s" % ("✅ 完整可信，未被篡改" if ok else "❌ 验证未通过"))
    if ok:
        return 0
    return 3 if rep.get("unsigned") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
