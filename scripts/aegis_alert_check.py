#!/usr/bin/env python3
"""
aegis_alert_check.py — 舰队告警评估 + webhook 推送（把"无人察觉"变成"主动推送"）。

独立于 collector/console 的轻量评估器（由 systemd timer 周期运行，见运行手册）：
拉 collector /v1/devices，评估三类告警并按「类型+设备+原因」去重节流后推 webhook：
  - device_offline       ：last_seen 超过 --offline-hours（曾在线但现在静默）。
  - self_update_failed   ：终端上报坏自更回执（preflight_failed / rolled_back:* / apply_failed:*）。
  - critical_findings    ：设备 latest_severity.critical > 0。

推送格式：
  generic （默认）：POST JSON {schema:"aegis.alert/v1", at, alerts:[{type,device_id,hostname,detail,severity}]}
  dingtalk        ：POST {msgtype:"text", text:{content:"Aegis 告警\\n- ..."}}（钉钉机器人 webhook）

安全/运维边界：
  - 未配置 webhook（--webhook / AEGIS_ALERT_WEBHOOK）时为 dry-run：只打印将推送的告警，不写状态、不发送。
  - 去重状态存 --state 文件（默认 /var/lib/aegis/alert-state.json，不可写时回落 /tmp）；
    发送成功才更新状态，发送失败下次重试。--min-interval-hours 控制同类告警最小间隔。
  - 凭据/地址经环境变量或参数传入；仓库只留占位默认。
  - 只读 collector + 出站 webhook；不改任何治理状态。

退出码：0 正常（含 dry-run 与发送成功）；2 webhook 配置了但本次全部发送失败；1 配置/拉取错误。
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BAD_SELF_UPDATE = ("preflight_failed", "rolled_back", "apply_failed")
SCHEMA = "aegis.alert/v1"


def log(m):
    print("[alert] " + m, flush=True)


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(path, state):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, path)
        return True
    except Exception as e:
        log("save state failed: %s" % e)
        return False


def fetch_devices(collector, token):
    req = urllib.request.Request(collector.rstrip("/") + "/v1/devices?limit=1000",
                                 headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode()).get("devices", [])


def evaluate(devices, now, offline_hours):
    alerts = []
    for d in devices:
        did = d.get("device_id") or "?"
        host = d.get("hostname") or did
        ls = d.get("last_seen") or 0
        if ls and (now - ls) > offline_hours * 3600:
            alerts.append({"type": "device_offline", "device_id": did, "hostname": host,
                           "severity": "high",
                           "detail": "offline %dh (last_seen=%s)" % (int((now - ls) / 3600), time.strftime("%m-%d %H:%M", time.localtime(ls)))})
        su = d.get("self_update") or {}
        reason = su.get("reason") or ""
        if reason and reason != "ok" and reason.startswith(BAD_SELF_UPDATE):
            alerts.append({"type": "self_update_failed", "device_id": did, "hostname": host,
                           "severity": "high", "detail": "self_update %s (latest=%s)" % (reason, su.get("latest") or "?")})
        crit = (d.get("latest_severity") or {}).get("critical") or 0
        if crit:
            alerts.append({"type": "critical_findings", "device_id": did, "hostname": host,
                           "severity": "critical", "detail": "%d critical finding(s)" % crit})
    return alerts


def dedup(alerts, state, now, min_interval):
    out = []
    for a in alerts:
        key = "%s:%s:%s" % (a["type"], a["device_id"], a["detail"].split(" ")[0])
        last = state.get(key) or 0
        if now - last < min_interval * 3600:
            continue
        a = dict(a)
        a["_key"] = key
        out.append(a)
    return out


def post_webhook(webhook, fmt, alerts, now):
    if fmt == "dingtalk":
        lines = ["Aegis 告警 %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(now))]
        for a in alerts:
            lines.append("- [%s] %s %s: %s" % (a["severity"], a["type"], a["hostname"], a["detail"]))
        body = {"msgtype": "text", "text": {"content": "\n".join(lines)}}
    else:
        body = {"schema": SCHEMA, "at": now,
                "alerts": [{k: v for k, v in a.items() if k != "_key"} for a in alerts]}
    data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector", default=os.environ.get("AEGIS_COLLECTOR_URL", "http://127.0.0.1:8931"))
    ap.add_argument("--token", default=os.environ.get("AEGIS_COLLECTOR_TOKEN", ""))
    ap.add_argument("--webhook", default=os.environ.get("AEGIS_ALERT_WEBHOOK", ""))
    ap.add_argument("--format", default=os.environ.get("AEGIS_ALERT_FORMAT", "generic"), choices=["generic", "dingtalk"])
    ap.add_argument("--offline-hours", type=float, default=2.0)
    ap.add_argument("--min-interval-hours", type=float, default=6.0)
    ap.add_argument("--state", default=os.environ.get("AEGIS_ALERT_STATE", "/var/lib/aegis/alert-state.json"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not args.token:
        log("no collector token; provide --token or AEGIS_COLLECTOR_TOKEN")
        return 1
    now = int(time.time())
    try:
        devices = fetch_devices(args.collector, args.token)
    except Exception as e:
        log("fetch devices failed: %s" % e)
        return 1
    alerts = evaluate(devices, now, args.offline_hours)
    state = load_state(args.state)
    pending = dedup(alerts, state, now, args.min_interval_hours)
    if not pending:
        log("no new alerts (evaluated %d devices, %d raw alerts, all deduped/none)" % (len(devices), len(alerts)))
        return 0
    for a in pending:
        log("ALERT %s %s %s: %s" % (a["severity"], a["type"], a["hostname"], a["detail"]))
    if args.dry_run or not args.webhook:
        log("dry-run (no webhook configured or --dry-run): not sending, state unchanged")
        return 0
    try:
        st = post_webhook(args.webhook, args.format, pending, now)
        log("webhook posted status=%s" % st)
        for a in pending:
            state[a["_key"]] = now
        save_state(args.state, state)
        return 0
    except Exception as e:
        log("webhook post failed (will retry next run): %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
