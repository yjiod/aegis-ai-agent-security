#!/usr/bin/env python3
"""
run_canary_release.py — Agent 自更新灰度(canary)发布/推进/回滚的操作侧工具。

与 scripts/run_enforce_drill.py（演练侧）配套，构成「灰度发布 → 演练 → 观察 → 放量/回滚」
标准流程的两个可执行支点（完整 SOP 见 docs/CANARY-DRILL-RUNBOOK.md）。

模式：
  --status            展示当前灰度配置 + 逐设备 canary 队列（在放量内/版本/自更结果/可封禁资产/
                      exempt/pinned）+ 推进门禁判定（有无坏自更回执）。只读，不改状态。
  --rollout N         设置放量比例（0-100）并经 /api/settings/rollout 保存；加 --publish 则
                      随即发布策略使其生效。N=0 即冻结自更（回滚自更通道）。
  --advance [--step N]  在当前比例上 +step（默认 +25，封顶 100）。前置门禁：全舰队无
                      preflight_failed / rolled_back:* / apply_failed:* 自更回执，否则拒绝推进。
  --rollback          等价 --rollout 0 --publish：冻结自更通道（已更新设备不回退二进制；
                      如需回退 enforce 封禁见 run_enforce_drill.py 的清理或手动 un-deny）。

安全边界：
  - 只操作灰度比例/通道与发布；不直接改 deny 名单（deny 走处置中心/演练脚本）。
  - pinned 设备永不自动更新；exempt 设备只报不封但仍可自更——不想让某台自更请 pinned 它
    （控制台设备页或 /api/settings/pinned）。推进前 --status 会列出 exempt/pinned 供核对。
  - 真实控制台地址/凭据经 --console / AEGIS_CONSOLE 与 --user/--password 或
    AEGIS_DRILL_USER/AEGIS_DRILL_PASSWORD 传入；仓库只留占位默认。

退出码：0 成功；非 0 失败或门禁拒绝。
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BAD_REASONS = ("preflight_failed", "rolled_back", "apply_failed")


class Console:
    def __init__(self, base, user, password):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.cookie = None

    def login(self):
        body = json.dumps({"username": self.user, "password": self.password}).encode()
        req = urllib.request.Request(self.base + "/api/auth/login", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            sc = r.headers.get("Set-Cookie", "")
        self.cookie = sc.split(";")[0] if sc else None
        if not self.cookie or "aegis_session=" not in self.cookie:
            raise SystemExit("login failed (no session cookie)")

    def api(self, method, path, body=None, timeout=40, retries=3):
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
            except Exception as e:
                last = e
                time.sleep(4)
        raise last


def bad_self_updates(devices):
    out = []
    for d in devices:
        r = (d.get("self_update") or {}).get("reason") or ""
        if r and r != "ok" and r.startswith(BAD_REASONS):
            out.append((d.get("device_id"), r))
    return out


def fetch_state(c):
    st, roll = c.api("GET", "/api/settings/rollout")
    st2, devs = c.api("GET", "/api/devices?limit=500")
    if st != 200 or st2 != 200:
        raise SystemExit("fetch state failed: %s/%s" % (st, st2))
    return roll.get("rollout", {}), devs.get("devices", [])


def print_status(roll, devices):
    pct = roll.get("rollout_percent")
    print("== canary config: enabled=%s channel=%s rollout=%s%% ==" % (
        roll.get("enabled"), roll.get("channel"), pct))
    bad = bad_self_updates(devices)
    in_canary = [d for d in devices if d.get("in_canary")]
    ok_upd = [d for d in devices if (d.get("self_update") or {}).get("updated") is True]
    print("cohort in_canary=%d / total=%d ; self-updated ok=%d ; bad self-update=%d" % (
        len(in_canary), len(devices), len(ok_upd), len(bad)))
    for d in devices:
        su = d.get("self_update") or {}
        print("  %-14s in_canary=%-5s ver=%-7s exempt=%-5s pinned=%-5s skills=%-3d self_update=%s" % (
            d.get("device_id"), d.get("in_canary"), d.get("agent_version"),
            d.get("exempt"), d.get("pinned"), len(d.get("skills") or []),
            (su.get("reason") or ("-" if not su else "updated")) ))
    if bad:
        print("GATE: BLOCKED — bad self-update receipts present: %s" % bad)
        print("      do NOT advance; investigate/rollback first (see runbook stage 5).")
    else:
        print("GATE: OK — no bad self-update receipts; advance allowed.")
    return bad


def set_rollout_and_publish(c, pct, channel, publish, note):
    st, saved = c.api("PUT", "/api/settings/rollout", {"enabled": True, "channel": channel, "rollout_percent": pct})
    if st != 200:
        raise SystemExit("set rollout failed: %s %s" % (st, json.dumps(saved)[:200]))
    print("rollout saved: %s" % json.dumps(saved.get("rollout"), ensure_ascii=False))
    if not publish:
        print("(not published; run with --publish to make it effective)")
        return
    st, pub = c.api("POST", "/api/policy/publish", {"note": note})
    if st != 200:
        raise SystemExit("publish failed: %s %s" % (st, json.dumps(pub)[:200]))
    pol = pub.get("policy") or {}
    print("published v%s agent_self_update=%s" % (
        pub.get("version"), json.dumps(pol.get("agent_self_update"), ensure_ascii=False)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--console", default=os.environ.get("AEGIS_CONSOLE", "https://aegis.example.com"))
    ap.add_argument("--user", default=os.environ.get("AEGIS_DRILL_USER", ""))
    ap.add_argument("--password", default=os.environ.get("AEGIS_DRILL_PASSWORD", ""))
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--rollout", type=int)
    ap.add_argument("--advance", action="store_true")
    ap.add_argument("--step", type=int, default=25)
    ap.add_argument("--rollback", action="store_true")
    ap.add_argument("--channel", default="pilot")
    ap.add_argument("--publish", action="store_true")
    args = ap.parse_args()
    if not args.user or not args.password:
        raise SystemExit("provide --user/--password or AEGIS_DRILL_USER/AEGIS_DRILL_PASSWORD")
    c = Console(args.console, args.user, args.password)
    c.login()
    roll, devices = fetch_state(c)

    if args.status:
        print_status(roll, devices)
        return 0
    if args.rollback:
        print_status(roll, devices)
        set_rollout_and_publish(c, 0, roll.get("channel", args.channel), True, "canary rollback: freeze self-update")
        print("self-update frozen (rollout=0). For enforce rollback use run_enforce_drill.py cleanup / un-deny.")
        return 0
    if args.advance:
        bad = print_status(roll, devices)
        if bad:
            return 2
        cur = roll.get("rollout_percent", 0) or 0
        nxt = min(100, cur + args.step)
        set_rollout_and_publish(c, nxt, roll.get("channel", args.channel), args.publish,
                                "canary advance %s%%->%s%%" % (cur, nxt))
        return 0
    if args.rollout is not None:
        if not 0 <= args.rollout <= 100:
            raise SystemExit("rollout must be 0-100")
        bad = bad_self_updates(devices)
        if bad and args.rollout > (roll.get("rollout_percent", 0) or 0):
            print("GATE: BLOCKED (bad self-update %s); refusing to increase rollout" % bad)
            return 2
        set_rollout_and_publish(c, args.rollout, args.channel, args.publish,
                                "canary set rollout=%s%%" % args.rollout)
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
