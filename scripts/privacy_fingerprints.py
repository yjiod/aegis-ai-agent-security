#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
# privacy_fingerprints.py — 隐私门禁「HMAC 指纹」层（CI 兜底，无需在仓内公开任何字面量）。
#
# 为什么不用明文正则：具体敏感标识符（工号/真实姓名/用户名/机器名/设备序列号/真实域名/
# 厂商名）一旦写进被跟踪的扫描脚本，就等于把它们公开到 GitHub。本文件只提交这些字面量的
# HMAC-SHA256 十六进制指纹；密钥来自环境变量 AEGIS_PRIVACY_HMAC_KEY 或 gitignored 的
# scripts/.privacy-hmac-key（两者都不入库）。无密钥不可逆推——即便 8 位工号、CJK 二字这类
# 低熵值，缺少密钥也无法暴力反查（这正是用 HMAC 而非裸 sha256 的原因）。
#
# 检测方式：从每个被跟踪文本文件按行抽取候选 token（拉丁词/域名/序列号、长数字串、长十六
# 进制串、CJK 2~4 字滑窗），对候选做归一化后计算 HMAC，与指纹集比对。命中即报告 文件:行号
# 并回填脱敏上下文（把命中片段替换为 [REDACTED]，绝不再打印原始字面量）。
#
# 局限（已知、可接受）：指纹按「独立 token」比对，拉丁字面量被嵌进更长单词（如 transsioncorp）
# 时不会命中；这类子串场景由本地 gitignored scripts/privacy-blocklist.local 的明文 substring
# 正则兜住（推送前本地必跑）。CJK 用 2~4 字滑窗，故嵌在句中的中文厂商名仍可命中。
#
# 无密钥时：打印告警并退出 0（跳过指纹层），由 privacy-scan.sh 的通用模式 + 本地 blocklist 兜底。
# ═══════════════════════════════════════════════════════════════════
import hashlib
import hmac
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 类别 -> HMAC-SHA256(key, 归一化字面量) 十六进制指纹（真实字面量从不入仓）。
FORBIDDEN = {
    "employee": {
        "a2c4cc3c97735aaa53602949c8378f13a94ad388156dec5e1e326a93137c2f2f",
    },
    "personal": {
        "33695eb1e29db2af79f421f7484dc222ab663c236fd90013004f83850d9bd3df",
        "5ea14d84c751483f85b0ab40aaf643e62275c2d5ffde28035edf13317323cf3f",
        "7b30a5c8703c7141a533283f466357be5be0f25875ce8b2dfc5817f931912b06",
        "a0cd1d8f6a14f43310df2efd11cc7f875bfd8935679794151717b6dcecd1f975",
        "ca1d03b29a6336613b2856fe044c899c39e3147ba33a216c8675be85f1caf50e",
        "d3df498974eca218cb31dff53a762d1428cc4bb4af201fe5dbb7595138ae8ee4",
    },
    "domain": {
        "1c62f3e818b612ab8d21b3061a751b6c76211abe8c0c98691c1b035bf943119e",
        "9674de705d2dd13d98d70386813ba364e99a9a206637a0c4d6cabfba8a092073",
    },
    "vendor": {
        "115d34cae6a962afc92e63f2203ff38141a9bcee6a019e925fab27684fd4cfc5",
        "12ad94a559af4510f2a142e340634ceaabe7d037b09262a923e435f6ccc0524e",
        "69de4bbdddec93a7872775f5b307e78dbdb2f334d9b5f9ec7555a8cb0a98a465",
        "7fbfcd980a908bda67d8ab08cbcea53b0cb06584327f5441c26d8fc2a68ece23",
        "86d8c9ccb0f261d97f0f5a5ff4a28c5ae1a4d994d7e995cf691f2dae064ada81",
        "a7a7b795e9937e134747376a03c81014f02aa1a78439f93c1bebb88d62e62d25",
        "bf455c2912dc81fcba658fd17c260f3a5ebf568724e2de59dbbeddf3722b899f",
    },
    "device": {
        "1ad36dc895f8f4df23c16a77924897584e2f1a1d32eeccabb6c0b8a777886701",
        "4d74865f8a1eaafa6411ad361f2498a6fb03831ceff953c593735c144b71757c",
        "5fc1051a4aae0f96548bde643168e94cba52ce07bd1f24b82522eb4e876cb7df",
        "6375e7b782597f560b473de5a21915ac5f35dea7aa15e7dee1ac477a1a97de53",
        "68138781a7986537bfb77a260adf57ccf7a841cc29781a38162f31b4478ebdc5",
        "99d7c03c9c2cbbe6fc90170b8195c346db011dafc63efda5f238d9e8dd1fd18d",
        "c6adeda121f7442926cef00ea91fc43ee697eb5c2c1a397dab0ee92ac16f7670",
        "d3f60b348a95d0861a16e54c25afd71293fbab5dca49eea87886ac01503c13f9",
    },
}

# 扫描器自身文件排除（其内容为指纹/通用模式，且避免自匹配噪声）。
SELF_EXCLUDE = {
    "scripts/privacy_fingerprints.py",
    "scripts/privacy-scan.sh",
}

TOK_LATIN = re.compile(r"[A-Za-z][A-Za-z0-9._-]{1,}")
TOK_DIGIT = re.compile(r"[0-9]{5,}")
TOK_HEX = re.compile(r"[0-9a-fA-F]{12,}")
TOK_CJK = re.compile(r"[\u4e00-\u9fff]+")


def load_key():
    k = os.environ.get("AEGIS_PRIVACY_HMAC_KEY")
    if k:
        return k.strip()
    p = os.path.join(HERE, ".privacy-hmac-key")
    try:
        with open(p, "r", encoding="utf-8") as f:
            v = f.read().strip()
            return v or None
    except OSError:
        return None


def build_index(key):
    kb = key.encode("utf-8")
    idx = {}
    for cat, digests in FORBIDDEN.items():
        for d in digests:
            idx[d] = cat

    def fp(s):
        return hmac.new(kb, s.encode("utf-8"), hashlib.sha256).hexdigest()

    return idx, fp


def candidates(line):
    """抽取候选 token（已归一化：拉丁/十六进制小写，数字与 CJK 原样）。"""
    out = []
    for m in TOK_LATIN.finditer(line):
        out.append((m.group(0), m.group(0).lower()))
    for m in TOK_DIGIT.finditer(line):
        out.append((m.group(0), m.group(0)))
    for m in TOK_HEX.finditer(line):
        out.append((m.group(0), m.group(0).lower()))
    for m in TOK_CJK.finditer(line):
        run = m.group(0)
        for n in (2, 3, 4):
            for i in range(0, len(run) - n + 1):
                sub = run[i:i + n]
                out.append((sub, sub))
    return out


def tracked_files():
    r = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True)
    if r.returncode != 0:
        return []
    return [p for p in r.stdout.decode("utf-8", "replace").split("\0") if p]


def mask(line, token):
    try:
        return line.replace(token, "[REDACTED]")
    except Exception:
        return "[REDACTED-line]"


def main():
    key = load_key()
    if not key:
        print("privacy-fingerprint: WARN 无 HMAC 密钥（设 AEGIS_PRIVACY_HMAC_KEY 或建 scripts/.privacy-hmac-key），跳过指纹层")
        return 0
    idx, fp = build_index(key)
    fail = 0
    reported = 0
    for path in tracked_files():
        if path in SELF_EXCLUDE:
            continue
        full = os.path.join(ROOT, path)
        try:
            with open(full, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError):
            continue  # 二进制或不可读，跳过
        for ln, line in enumerate(lines, 1):
            hit_cat = None
            hit_tok = None
            for raw, norm in candidates(line):
                if fp(norm) in idx:
                    hit_cat = idx[fp(norm)]
                    hit_tok = raw
                    break
            if hit_cat:
                fail = 1
                reported += 1
                if reported <= 40:
                    print("!! privacy leak [%s]: %s:%d: %s" % (hit_cat, path, ln, mask(line.rstrip("\n"), hit_tok)))
    if reported > 40:
        print("   …（另有 %d 处命中未展开）" % (reported - 40))
    return fail


if __name__ == "__main__":
    sys.exit(main())
