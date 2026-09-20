#!/usr/bin/env python3
"""
run_enforce_drill.py — 一键 enforce 封禁/恢复演练（隔离的非豁免测试端点）。

在真实终端上端到端验证 enforcement 闭环，且不触碰任何豁免(exempt)开发主机：
  1) 在测试端点放置 1 个夹具 skill + N 个 filler skill（使 deny 只占该端点资产的小比例，
     天然通过控制台爆炸半径闸：1/(N+1) <= 10% 且 <= 50% 绝对上限）。
  2) 发布 scoped deny(仅夹具) + modules.skill_enforce=true。
  3) 验证：终端 quarantine 夹具 + 上报 quarantined 回执 + 磁盘 .aegis-quarantine 有 manifest。
  4) un-deny(改 monitor) + 发布 → 验证 auto-restore 回执 + 夹具回位 + manifest 清理。
  5) 清理：skill_enforce 关、清 deny、发布基线、删除夹具/filler。

目标端点通过 --exec 指定的"guest 命令运行器"操作（如 Parallels:
  --exec '/Applications/Parallels Desktop.app/Contents/MacOS/prlctl exec "Windows 11" powershell -NoProfile -Command'
或 SSH: --exec 'ssh drillhost' 配合该主机把 stdin/参数当 shell 命令执行）。
当前命令模板面向 Windows PowerShell guest；其它 guest 可自备等价 --exec。

安全边界：脚本只 deny 它自己创建的夹具名（唯一随机后缀），对其它资产零影响；
绝不选择/操作 exempt 设备（步骤 2 会校验目标设备 exempt=false，否则中止）。

退出码：0=quarantine+restore 均验证通过；非 0=任一环节失败（已尽力清理）。
"""
import argparse
import json
import os
import secrets
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

FAIL = []


def log(msg):
    print("[drill] " + msg, flush=True)


def fail(msg):
    FAIL.append(msg)
    log("FAIL: " + msg)


class Console:
    def __init__(self, base, user, password):
        self.base = base.rstrip("/")
        self.cookie = None
        self.user = user
        self.password = password

    def login(self):
        body = json.dumps({"username": self.user, "password": self.password}).encode()
        req = urllib.request.Request(self.base + "/api/auth/login", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            sc = r.headers.get("Set-Cookie", "")
        self.cookie = sc.split(";")[0] if sc else None
        if not self.cookie or "aegis_session=" not in self.cookie:
            raise SystemExit("login failed (no session cookie); MFA-enabled accounts unsupported for drill")

    def api(self, method, path, body=None, timeout=40, retries=4):
        data = json.dumps(body).encode() if body is not None else None
        last = None
        for _ in range(retries):
            try:
                req = urllib.request.Request(self.base + path, data=data, method=method,
                                             headers={"Cookie": self.cookie, "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.status, json.loads(r.read().decode() or "{}")
            except urllib.error.HTTPError as e:
                try:
                    return e.code, json.loads(e.read().decode() or "{}")
                except Exception:
                    return e.code, {}
            except Exception as e:  # 瞬态(冷启/网络)重试，避免一次超时打断整个演练
                last = e
                time.sleep(5)
        raise last


def guest(exec_prefix, cmd, timeout=120):
    argv = shlex.split(exec_prefix) + [cmd]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return (p.stdout or "") + (p.stderr or "")


def poll(fn, desc, timeout=180, interval=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:  # 瞬态错误不中断轮询
            log("poll " + desc + " transient: " + str(e)[:80])
        time.sleep(interval)
    fail("timeout waiting for " + desc)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--console", default=os.environ.get("AEGIS_CONSOLE", "https://aegis.example.com"),
                    help="console base URL; real value via --console or AEGIS_CONSOLE (repo keeps placeholder)")
    ap.add_argument("--user", default=os.environ.get("AEGIS_DRILL_USER", ""))
    ap.add_argument("--password", default=os.environ.get("AEGIS_DRILL_PASSWORD", ""))
    ap.add_argument("--exec", required=True, help="guest command runner prefix")
    ap.add_argument("--guest-home", default="C:\\Users\\drill-target",
                    help="guest user home holding the skill roots; pass the real test-endpoint home")
    ap.add_argument("--service", default="AegisAgent")
    ap.add_argument("--fillers", type=int, default=10)
    args = ap.parse_args()
    if not args.user or not args.password:
        raise SystemExit("provide --user/--password or AEGIS_DRILL_USER/AEGIS_DRILL_PASSWORD")

    fixture = "aegis-drill-fixture-" + secrets.token_hex(3)
    skills_dir = args.guest_home + "\\.claude\\skills"
    c = Console(args.console, args.user, args.password)
    c.login()
    log("logged in; fixture=" + fixture)

    device_id = None
    try:
        # 1) place fixtures + restart agent
        ps = (
            "1..{n} | ForEach-Object {{ $n='aegis-drill-filler-'+$_; New-Item -ItemType Directory -Force -Path \"{sd}\\$n\" | Out-Null; "
            "Set-Content -Path \"{sd}\\$n\\SKILL.md\" -Value '# filler' }}; "
            "New-Item -ItemType Directory -Force -Path \"{sd}\\{fx}\" | Out-Null; "
            "Set-Content -Path \"{sd}\\{fx}\\SKILL.md\" -Value '# fixture'; "
            "Restart-Service {svc} -Force; 'placed'"
        ).format(n=args.fillers, sd=skills_dir, fx=fixture, svc=args.service)
        out = guest(args.exec, ps)
        if "placed" not in out:
            fail("place fixtures: " + out.strip()[:200])
            return 1
        log("fixtures placed + service restarted")

        # 2) find the non-exempt device that reports the fixture
        def find_device():
            st, d = c.api("GET", "/api/devices?limit=200")
            if st != 200:
                return None
            for dev in d.get("devices", []):
                if dev.get("exempt"):
                    continue
                if fixture in (dev.get("skills") or []):
                    return dev
            return None

        dev = poll(find_device, "device reporting fixture", timeout=240)
        if not dev:
            return 1
        device_id = dev["device_id"]
        log("drill device=" + device_id + " (non-exempt, skills=" + str(len(dev.get("skills") or [])) + ")")

        # 3) publish scoped deny + enforce on
        st, _ = c.api("PUT", "/api/settings/modules", {"modules": {"skill_enforce": True}})
        if st != 200:
            fail("enable skill_enforce: " + str(st))
            return 1
        st, _ = c.api("POST", "/api/labels", {"asset_type": "skill", "asset_key": fixture, "disposition": "deny", "note": "drill"})
        if st != 200:
            fail("deny label: " + str(st))
            return 1
        st, pub = c.api("POST", "/api/policy/publish", {"note": "enforce drill: deny " + fixture})
        if st != 200:
            fail("publish deny: " + str(st) + " " + json.dumps(pub)[:200])
            return 1
        log("published deny policy v" + str(pub.get("version")))
        guest(args.exec, "Restart-Service {svc} -Force; 'r'".format(svc=args.service))

        # 4) verify quarantine receipt + on-disk
        def quarantined():
            st, d = c.api("GET", "/api/devices?limit=200")
            if st != 200:
                return None
            for dv in d.get("devices", []):
                if dv.get("device_id") != device_id:
                    continue
                for e in dv.get("enforcement") or []:
                    if e.get("action") == "quarantined" and e.get("asset_key") == fixture:
                        return e
            return None

        rec = poll(quarantined, "quarantined receipt", timeout=240)
        if not rec:
            return 1
        log("quarantined receipt ok: " + json.dumps(rec, ensure_ascii=False)[:200])
        gone = guest(args.exec, "Test-Path '{sd}\\{fx}'".format(sd=skills_dir, fx=fixture))
        if "False" not in gone:
            fail("fixture still on disk after quarantine: " + gone.strip()[:100])
        qm = guest(args.exec, "(@(Get-ChildItem '{h}\\.aegis-quarantine' -Filter '*.aegis-quarantine.json' -ErrorAction SilentlyContinue | Where-Object {{ (Get-Content $_.FullName -Raw) -match '{fx}' }})).Count".format(h=args.guest_home, fx=fixture))
        if not any(ch.isdigit() and int(ch) >= 1 for ch in qm if ch.isdigit()):
            fail("no quarantine manifest on disk: " + qm.strip()[:100])
        log("on-disk quarantine verified")

        # 5) un-deny + publish + verify restore
        st, _ = c.api("POST", "/api/labels", {"asset_type": "skill", "asset_key": fixture, "disposition": "monitor", "note": "drill un-deny"})
        if st != 200:
            fail("un-deny label: " + str(st))
            return 1
        st, pub = c.api("POST", "/api/policy/publish", {"note": "enforce drill: un-deny " + fixture})
        if st != 200:
            fail("publish un-deny: " + str(st))
            return 1
        log("published un-deny policy v" + str(pub.get("version")))
        guest(args.exec, "Restart-Service {svc} -Force; 'r'".format(svc=args.service))

        def restored():
            st, d = c.api("GET", "/api/devices?limit=200")
            if st != 200:
                return None
            for dv in d.get("devices", []):
                if dv.get("device_id") != device_id:
                    continue
                for e in dv.get("enforcement") or []:
                    if e.get("action") == "restored" and e.get("asset_key") == fixture:
                        return e
            return None

        rec2 = poll(restored, "restored receipt", timeout=240)
        if not rec2:
            return 1
        log("restored receipt ok: " + json.dumps(rec2, ensure_ascii=False)[:200])
        back = guest(args.exec, "Test-Path '{sd}\\{fx}'".format(sd=skills_dir, fx=fixture))
        if "True" not in back:
            fail("fixture not restored on disk: " + back.strip()[:100])
        log("on-disk restore verified")
    finally:
        # 6) cleanup: baseline policy + remove fixtures
        try:
            c.api("PUT", "/api/settings/modules", {"modules": {"skill_enforce": False, "mcp_enforce": False}})
            c.api("POST", "/api/labels", {"asset_type": "skill", "asset_key": fixture, "disposition": "monitor", "note": "drill cleanup"})
            st, pub = c.api("POST", "/api/policy/publish", {"note": "drill cleanup: baseline"})
            log("cleanup policy v" + str(pub.get("version")))
        except Exception as e:
            log("cleanup policy error: " + str(e))
        try:
            guest(args.exec, "Remove-Item -Recurse -Force '{sd}\\{fx}','{sd}\\aegis-drill-filler-*' -ErrorAction SilentlyContinue; 'cleaned'".format(sd=skills_dir, fx=fixture))
            log("fixtures removed")
        except Exception as e:
            log("cleanup fixtures error: " + str(e))

    if FAIL:
        log("DRILL FAILED: " + "; ".join(FAIL))
        return 1
    log("DRILL PASSED: deny->quarantine->receipt and un-deny->auto-restore->receipt verified on " + str(device_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
