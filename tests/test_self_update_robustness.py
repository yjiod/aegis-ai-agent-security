"""
tests/test_self_update_robustness.py — 自更新 preflight + 自动回滚 + --selftest 单测（PM#2）。

覆盖 aegis_self_update.check_and_apply 的健壮性新增路径与 aegis_agent 的 --selftest /
冻结二进制 preflight 钩子：
  - preflight 拒绝语法损坏的 .py 工件（保留旧版本、清理 staging）；
  - 自定义 preflight 钩子 reject/accept；
  - 应用后 sha256 复核不符 → 自动回滚到 .prev（绝不留在坏状态）；
  - --selftest 退出码 0 且打印 aegis-selftest-ok；
  - _binary_selftest_preflight 对 exit0 / 旧格式(exit2+unrecognized) / 损坏(exit1) 的判定。
不联网（file:// manifest）、不依赖真实冻结二进制（用假可执行脚本驱动钩子逻辑）。
"""
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
DOWNLOADS = ROOT / "public" / "downloads"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, DOWNLOADS / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write_manifest(d: Path, artifact_name: str, art_path: Path, agent_version: str, url: str | None = None) -> Path:
    man = d / "update-manifest.json"
    man.write_text(json.dumps({
        "schema": "aegis.update/v1",
        "release": "0.99.0",
        "agent_version": agent_version,
        "artifacts": {artifact_name: {"url": url or ("file://" + str(art_path)), "sha256": sha(art_path.read_bytes())}},
    }))
    return man


class SelfUpdateRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.su = load("su_robust", "aegis_self_update.py")
        self.agent = load("agent_robust", "aegis_agent.py")

    def test_preflight_rejects_syntactically_broken_script(self):
        su = self.su
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            broken = d / "new.py"
            broken.write_text("def oops(:\n    pass\n")  # 语法错误
            man = write_manifest(d, "aegis_agent.py", broken, "0.99.0")
            target = d / "agent.py"
            target.write_text('print("old-good")')
            res = su.check_and_apply("file://" + str(man), "0.36.3", "dev1", "aegis_agent.py", str(target))
            self.assertFalse(res["updated"])
            self.assertEqual(res["reason"], "preflight_failed")
            self.assertEqual(target.read_text(), 'print("old-good")')  # 旧版本保留
            self.assertFalse(os.path.exists(str(target) + ".staging"))  # staging 已清理
            self.assertFalse(os.path.exists(str(target) + ".prev"))  # 从未替换 → 无 .prev

    def test_preflight_hook_reject_keeps_old(self):
        su = self.su
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            new = d / "new.py"
            new.write_text('print("v99")')
            man = write_manifest(d, "aegis_agent.py", new, "0.99.0")
            target = d / "agent.py"
            target.write_text('print("old")')
            res = su.check_and_apply("file://" + str(man), "0.36.3", "dev1", "aegis_agent.py", str(target), preflight=lambda p: False)
            self.assertFalse(res["updated"])
            self.assertEqual(res["reason"], "preflight_failed")
            self.assertEqual(target.read_text(), 'print("old")')

    def test_preflight_hook_accept_allows_update(self):
        su = self.su
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            new = d / "new.py"
            new.write_text('print("v99")')
            man = write_manifest(d, "aegis_agent.py", new, "0.99.0")
            target = d / "agent.py"
            target.write_text('print("old")')
            res = su.check_and_apply("file://" + str(man), "0.36.3", "dev1", "aegis_agent.py", str(target), preflight=lambda p: True)
            self.assertTrue(res["updated"])
            self.assertEqual(res["to"], "0.99.0")
            self.assertEqual(res["sha256"], sha(new.read_bytes()))
            self.assertEqual(target.read_text(), 'print("v99")')

    def test_preflight_hook_exception_is_fail_closed(self):
        su = self.su
        def boom(_p):
            raise RuntimeError("hook exploded")
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            new = d / "new.py"
            new.write_text('print("v99")')
            man = write_manifest(d, "aegis_agent.py", new, "0.99.0")
            target = d / "agent.py"
            target.write_text('print("old")')
            res = su.check_and_apply("file://" + str(man), "0.36.3", "dev1", "aegis_agent.py", str(target), preflight=boom)
            self.assertFalse(res["updated"])
            self.assertEqual(res["reason"], "preflight_failed")  # 钩子异常 → fail-closed 拒绝
            self.assertEqual(target.read_text(), 'print("old")')

    def test_post_apply_sha_mismatch_triggers_auto_rollback(self):
        # preflight 钩子在 sha 校验通过后篡改 staging → apply 后 target 的 sha 与期望不符 → 自动回滚到 .prev。
        su = self.su
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            new = d / "new.bin"
            new.write_bytes(b"GOOD-BINARY")
            man = write_manifest(d, "aegis-agent", new, "0.99.0")
            target = d / "aegis-agent"
            target.write_bytes(b"OLD-BINARY")

            def mutating_preflight(path):
                with open(path, "ab") as fh:
                    fh.write(b"CORRUPT")  # 篡改已下载工件，破坏 sha 一致性
                return True

            res = su.check_and_apply("file://" + str(man), "0.36.3", "dev1", "aegis-agent", str(target), preflight=mutating_preflight)
            self.assertFalse(res["updated"])
            self.assertEqual(res["reason"], "rolled_back:sha_mismatch")
            self.assertEqual(target.read_bytes(), b"OLD-BINARY")  # 已自动回滚到旧版本

    def test_selftest_flag_exits_zero(self):
        # 直接调用 run_selftest()
        self.assertEqual(self.agent.run_selftest(), 0)
        # 子进程 --selftest（脚本形态）：退出码 0 且打印标记
        r = subprocess.run([sys.executable, str(DOWNLOADS / "aegis_agent.py"), "--selftest"], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("aegis-selftest-ok", r.stdout)

    def _fake_exe(self, d: Path, name: str, body: str) -> str:
        p = d / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return str(p)

    def test_binary_selftest_preflight_decision_matrix(self):
        agent = self.agent
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            ok = self._fake_exe(d, "ok.sh", "#!/bin/sh\nexit 0\n")
            old = self._fake_exe(d, "old.sh", '#!/bin/sh\necho "unrecognized arguments: --selftest" >&2\nexit 2\n')
            bad = self._fake_exe(d, "bad.sh", "#!/bin/sh\nexit 1\n")
            self.assertTrue(agent._binary_selftest_preflight(ok))    # 健康
            with patch.object(sys, "platform", "darwin"):
                self.assertFalse(agent._binary_selftest_preflight(old))
            with patch.object(sys, "platform", "linux"):
                self.assertTrue(agent._binary_selftest_preflight(old))
            self.assertFalse(agent._binary_selftest_preflight(bad))  # 损坏 → 拒绝
            self.assertFalse(agent._binary_selftest_preflight(str(d / "missing.sh")))  # 不存在 → 拒绝

    def test_mac_update_without_maintenance_preserves_client_and_existing_backup(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, "platform", "darwin"):
            root = Path(temp)
            candidate = Path(self._fake_exe(root, "candidate", '#!/bin/sh\n[ "$1" = --selftest ]\n'))
            manifest = write_manifest(root, "aegis-agent-darwin-arm64", candidate, "0.99.0")
            target = root / "aegis-agent"
            target.write_bytes(b"current-client")
            backup = root / "aegis-agent.prev"
            backup.write_bytes(b"last-known-good")
            result = self.su.check_and_apply("file://" + str(manifest), "0.37.3", "fixture-device",
                                            "aegis-agent-darwin-arm64", str(target),
                                            preflight=self.agent._binary_selftest_preflight)
            self.assertEqual(result["reason"], "preflight_failed")
            self.assertFalse(result["updated"])
            self.assertEqual(target.read_bytes(), b"current-client")
            self.assertEqual(backup.read_bytes(), b"last-known-good")
            self.assertFalse((root / "aegis-agent.staging").exists())

    def test_mac_preflight_checks_maintenance_under_remaining_budget(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, "platform", "darwin"):
            candidate = self._fake_exe(Path(temp), "candidate", "#!/bin/sh\nexit 0\n")
            ok = subprocess.CompletedProcess([], 0, b"", b"")
            with patch.object(self.agent.time, "monotonic", side_effect=[100, 101, 104]), patch.object(self.agent.subprocess, "run", return_value=ok) as run:
                self.assertTrue(self.agent._binary_selftest_preflight(candidate, timeout=20))
                self.assertEqual([call.args[0] for call in run.call_args_list],
                                 [[candidate, "--selftest"], [candidate, "--maintenance-selftest"]])
                self.assertEqual([call.kwargs["timeout"] for call in run.call_args_list], [19, 16])
            with patch.object(self.agent.subprocess, "run", side_effect=[ok, subprocess.TimeoutExpired(candidate, 1)]):
                self.assertFalse(self.agent._binary_selftest_preflight(candidate))
            with patch.object(self.agent.time, "monotonic", side_effect=[100, 101, 121]), patch.object(self.agent.subprocess, "run", return_value=ok) as run:
                self.assertFalse(self.agent._binary_selftest_preflight(candidate))
                self.assertEqual(run.call_count, 1)

    @unittest.skipUnless(sys.platform == "darwin" and os.environ.get("AEGIS_FROZEN_AGENT"), "requires an explicit Mac frozen candidate")
    def test_real_frozen_candidate_passes_both_update_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "candidate"
            candidate.write_bytes(Path(os.environ["AEGIS_FROZEN_AGENT"]).read_bytes())
            self.assertTrue(self.agent._binary_selftest_preflight(str(candidate)))


    def test_report_includes_nonroutine_self_update_only(self):
        agent = self.agent
        policy = json.loads((DOWNLOADS / "aegis-policy.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as td:
            # 例行（None）→ 报告不带 self_update（不刷屏）
            agent._SELF_UPDATE_RESULT = None
            rep = agent.build_report(Path(td), policy)
            self.assertNotIn("self_update", rep)
            # 非例行（preflight 拒绝）→ 报告携带 self_update，供 collector/控制台观测
            agent._SELF_UPDATE_RESULT = {"updated": False, "reason": "preflight_failed", "latest": "0.36.4", "at": 1}
            try:
                rep2 = agent.build_report(Path(td), policy)
                self.assertIn("self_update", rep2)
                self.assertEqual(rep2["self_update"]["reason"], "preflight_failed")
                self.assertFalse(rep2["self_update"]["updated"])
            finally:
                agent._SELF_UPDATE_RESULT = None

    def test_collector_validates_self_update_field(self):
        col = load("col_robust", "aegis_collector.py")
        now = 1_700_000_000
        base = {
            "schema": "aegis.report/v1",
            "agent_version": "0.36.4",
            "policy_version": "4.29.0",
            "device_id": "0123456789ab",
            "scanned_at": now,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
        }
        good = dict(base, self_update={"updated": False, "reason": "rolled_back:sha_mismatch", "latest": "0.36.4", "at": now})
        self.assertTrue(col.valid_report(good, now=now))
        # 缺 reason / reason 过长 / updated 非 bool → 拒收
        self.assertFalse(col.valid_report(dict(base, self_update={"updated": False}), now=now))
        self.assertFalse(col.valid_report(dict(base, self_update={"updated": False, "reason": "x" * 65}), now=now))
        self.assertFalse(col.valid_report(dict(base, self_update={"updated": "no", "reason": "ok"}), now=now))
        # 未知顶层字段仍拒收（白名单不变，仅新增 self_update）
        self.assertFalse(col.valid_report(dict(base, bogus=1), now=now))


    def test_drill_preflight_reject_flows_into_report_and_collector(self):
        # 端到端演练（安全形态，temp 目录、file:// manifest、不碰真实 home/舰队）：
        # 坏工件(.py 语法损坏) → check_and_apply 经 maybe_self_update 被 preflight 拒绝 →
        # _SELF_UPDATE_RESULT 记录 preflight_failed → build_report 携带 → collector 校验通过。
        # 证明"坏更新被终端拦截"这件事既发生、又可被服务端观测（canary 监控闭环）。
        agent = self.agent
        col = load("col_drill", "aegis_collector.py")
        policy = json.loads((DOWNLOADS / "aegis-policy.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as dd:
            d = Path(dd)
            broken = d / "new.py"
            broken.write_text("def oops(:\n    pass\n")  # 语法损坏 → preflight 必拒
            man = write_manifest(d, "aegis_agent.py", broken, "0.99.0")
            target = d / "aegis_agent.py"
            target.write_text('print("old-good")')
            agent._SELF_UPDATE_RESULT = None
            # 直接驱动 check_and_apply（maybe_self_update 的 manifest 推导依赖 report_url/网络，
            # 这里用 file:// manifest 等价覆盖"拉清单→preflight→拒绝"链路），再模拟 maybe_self_update 的记账。
            res = check_and_apply_fresh("file://" + str(man), "0.36.4", "dev-drill-01", "aegis_agent.py", str(target))
            self.assertFalse(res["updated"])
            self.assertEqual(res["reason"], "preflight_failed")
            self.assertEqual(target.read_text(), 'print("old-good")')  # 旧版本保留
            # 记账 + 上报 + 服务端校验
            agent._SELF_UPDATE_RESULT = {"updated": False, "reason": res["reason"], "latest": res.get("latest"), "at": 1}
            try:
                rep = agent.build_report(d, policy)
                self.assertEqual(rep["self_update"]["reason"], "preflight_failed")
                now = 1_700_000_000
                base = {
                    "schema": "aegis.report/v1", "agent_version": "0.36.4", "policy_version": policy["version"],
                    "device_id": "0123456789ab", "scanned_at": now,
                    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "findings": [],
                    "self_update": rep["self_update"],
                }
                self.assertTrue(col.valid_report(base, now=now))  # 服务端接受该上报
            finally:
                agent._SELF_UPDATE_RESULT = None


def check_and_apply_fresh(*args, **kwargs):
    import importlib.util as _iu
    spec = _iu.spec_from_file_location("su_drill2", DOWNLOADS / "aegis_self_update.py")
    m = _iu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.check_and_apply(*args, **kwargs)


if __name__ == "__main__":
    unittest.main()
