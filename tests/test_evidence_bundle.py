"""
tests/test_evidence_bundle.py — 证据包离线验签器（scripts/verify-evidence-bundle.py）单测。

验签器只有 verify（沿用 Agent 的纯 Python ed25519），故本测试自带一个 RFC8032
ed25519 **签名器**（复用验签器的曲线常量/点运算），用以构造"合法签名"的正例，
再验证篡改/缺签名/坏 schema 等负例一律 fail。不引入任何第三方依赖。

canonical_json 与 ed25519 的跨语言一致性由 tests/test_aegis.py 既有对拍用例保证
（验签器与控制台 lib/policy.ts、Agent aegis_agent.py 共用同一实现）。
"""
import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "scripts"
VERIFIER = SCRIPTS / "verify-evidence-bundle.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("aegis_evidence_verifier", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V = load_verifier()


# ── RFC8032 ed25519 签名（仅测试用；复用验签器的曲线参数与点运算）──────────
def _encode_point(P):
    x, y, z, _t = P
    zinv = pow(z, V._ED_P - 2, V._ED_P)
    x = (x * zinv) % V._ED_P
    y = (y * zinv) % V._ED_P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _public_from_seed(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= ~0b111
    a &= ~(1 << 255)
    a |= 1 << 254
    return a, _encode_point(V._ed_mult(V._ED_B, a))


def ed25519_sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a, pub = _public_from_seed(seed)
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % V._ED_L
    R_enc = _encode_point(V._ed_mult(V._ED_B, r))
    k = int.from_bytes(hashlib.sha512(R_enc + pub + msg).digest(), "little") % V._ED_L
    S = (r + k * a) % V._ED_L
    return pub, R_enc + S.to_bytes(32, "little")


SEED = bytes(range(32))  # 固定测试种子（非生产密钥）


def make_core():
    """构造一个形态与 lib/evidence.ts buildEvidenceBundle 一致的最小 core。"""
    sections = {
        "inventory": [{"device_id": "dev-abc", "hostname": "HOST", "os_user": "user:deadbeef"}],
        "findings": [{"device_id": "dev-abc", "kind": "hardcoded_secret", "severity": "critical", "message": "token=[REDACTED]"}],
        "policy": [{"policy_version": "4.29.0", "devices_reported": 1}],
    }
    manifest = {name: {"count": len(val), "sha256": V.section_sha256(val)} for name, val in sections.items()}
    return {
        "schema": V.SCHEMA,
        "generated_at": 1_789_829_440_695,
        "generated_by": "auditor-1",
        "scope": {"device_id": None, "since": None, "until": None},
        "redaction": "standard",
        "console": {"collector_connected": True, "version": "0.36.2"},
        "sections": sections,
        "manifest": manifest,
        "report_markdown": "# Aegis 证据包\n- critical 1 条\n",
    }


def sign_core(core):
    canonical = V.canonical_json(core).encode("utf-8")
    pub, sig = ed25519_sign(SEED, canonical)
    return {
        **core,
        "ed25519_signature": base64.b64encode(sig).decode(),
        "ed25519_public": base64.b64encode(pub).decode(),
        "ed25519_key_id": hashlib.sha256(pub).hexdigest()[:12],
    }


class EvidenceBundleVerifyTests(unittest.TestCase):
    def test_signer_matches_verifier_primitive(self):
        # 自检：测试签名器产出的签名必须能被验签器的 ed25519_verify 接受。
        pub, sig = ed25519_sign(SEED, b"hello aegis")
        self.assertTrue(V.ed25519_verify(pub, b"hello aegis", sig))
        self.assertFalse(V.ed25519_verify(pub, b"hello aegiz", sig))

    def test_valid_bundle_passes(self):
        bundle = sign_core(make_core())
        ok, rep = V.verify(bundle)
        self.assertTrue(ok, rep)
        self.assertTrue(rep["schema_ok"])
        self.assertTrue(rep["manifest_ok"])
        self.assertIs(rep["ed25519_ok"], True)
        self.assertEqual(rep["mismatched"], [])

    def test_tampered_section_fails_manifest_and_signature(self):
        bundle = sign_core(make_core())
        # 篡改一个 section 的内容（不改 manifest）→ manifest 不符 + ed25519 失败。
        bundle["sections"]["findings"][0]["severity"] = "low"
        ok, rep = V.verify(bundle)
        self.assertFalse(ok)
        self.assertFalse(rep["manifest_ok"])
        self.assertIn("findings", rep["mismatched"])

    def test_tampered_markdown_fails_signature_only(self):
        bundle = sign_core(make_core())
        # report_markdown 在 core canonical 内但不在任何 section → manifest 仍过，ed25519 必失败。
        bundle["report_markdown"] += "篡改结论：一切正常\n"
        ok, rep = V.verify(bundle)
        self.assertFalse(ok)
        self.assertTrue(rep["manifest_ok"])  # sections 未动
        self.assertIs(rep["ed25519_ok"], False)
        self.assertEqual(rep["reason"], "ed25519_invalid")

    def test_tampered_manifest_hash_fails(self):
        bundle = sign_core(make_core())
        # 同时改 section 与其 manifest 哈希（伪造一致）→ 局部哈希自洽，但整包 ed25519 仍失败。
        bundle["sections"]["inventory"][0]["hostname"] = "EVIL"
        bundle["manifest"]["inventory"]["sha256"] = V.section_sha256(bundle["sections"]["inventory"])
        ok, rep = V.verify(bundle)
        self.assertFalse(ok)
        self.assertTrue(rep["manifest_ok"])  # 攻击者让 manifest 自洽
        self.assertIs(rep["ed25519_ok"], False)  # 但签名覆盖整包，仍被识破

    def test_unsigned_bundle_reports_unsigned(self):
        core = make_core()
        bundle = {**core, "integrity": "unsigned"}
        ok, rep = V.verify(bundle)
        self.assertFalse(ok)
        self.assertIsNone(rep["ed25519_ok"])
        self.assertTrue(rep["unsigned"])
        self.assertEqual(rep["reason"], "unsigned_bundle")

    def test_missing_signature_field(self):
        bundle = sign_core(make_core())
        del bundle["ed25519_signature"]
        ok, rep = V.verify(bundle)
        self.assertFalse(ok)
        self.assertEqual(rep["reason"], "missing_signature")

    def test_bad_schema_rejected(self):
        bundle = sign_core(make_core())
        bundle["schema"] = "aegis.evidence/v999"
        ok, rep = V.verify(bundle)
        self.assertFalse(ok)
        self.assertFalse(rep["schema_ok"])
        self.assertTrue(rep["reason"].startswith("bad_schema"))

    def test_not_an_object_rejected(self):
        ok, rep = V.verify(["not", "a", "bundle"])
        self.assertFalse(ok)
        self.assertEqual(rep["reason"], "not_an_object")

    def test_cli_exit_codes(self):
        good = sign_core(make_core())
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bundle.json"
            p.write_text(json.dumps(good), encoding="utf-8")
            r = subprocess.run([sys.executable, str(VERIFIER), str(p)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("未被篡改", r.stdout)

            # 篡改后 CLI 退出码 1
            bad = sign_core(make_core())
            bad["sections"]["findings"][0]["severity"] = "low"
            p.write_text(json.dumps(bad), encoding="utf-8")
            r2 = subprocess.run([sys.executable, str(VERIFIER), "--quiet", str(p)], capture_output=True, text=True)
            self.assertEqual(r2.returncode, 1)
            self.assertEqual(r2.stdout.strip(), "FAIL")

            # 未签名包 CLI 退出码 3
            unsigned = {**make_core(), "integrity": "unsigned"}
            p.write_text(json.dumps(unsigned), encoding="utf-8")
            r3 = subprocess.run([sys.executable, str(VERIFIER), "--quiet", str(p)], capture_output=True, text=True)
            self.assertEqual(r3.returncode, 3)


if __name__ == "__main__":
    unittest.main()
