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
  email（并行通道）：控制台 alert_config.email 非空 + 服务器 AEGIS_ALERT_SMTP_* env 时，
                    同批告警同时发邮件（smtplib+TLS；凭据只从 env 读，绝不入库/入对话）。

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
    """P1-4：游标翻页遍历**全量**舰队。旧实现 `limit=1000` 单页封顶 → 30k 下告警只覆盖前
    1000 台（2.9 万台静默无告警，正确性红线）。cursor 即 device_id(hex12, URL 安全)。"""
    base = collector.rstrip("/") + "/v1/devices"
    devices, cursor = [], ""
    for _ in range(1000):                      # 有界翻页护栏：1000 页 × 1000 = 100 万台，远超 30k
        qs = "limit=1000" + ("&cursor=" + cursor if cursor else "")
        req = urllib.request.Request(base + "?" + qs,
                                     headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
        devices.extend(data.get("devices", []))
        cursor = data.get("next_cursor") or ""
        if data.get("complete") or not cursor:
            break
    return devices


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


def send_email(to_addrs, alerts, now):
    """邮件通道：SMTP 凭据只从 AEGIS_ALERT_SMTP_* env 读取（运维在 unit/env 配置），
    控制台只存收件人列表（逗号分隔）。任一 env 缺失视为邮件通道未配置，跳过不报错。"""
    host = os.environ.get("AEGIS_ALERT_SMTP_HOST", "")
    user = os.environ.get("AEGIS_ALERT_SMTP_USER", "")
    pwd = os.environ.get("AEGIS_ALERT_SMTP_PASS", "")
    sender = os.environ.get("AEGIS_ALERT_SMTP_FROM", user)
    if not (host and user and pwd and sender):
        return None  # 未配置 SMTP env → 邮件通道关闭
    import smtplib
    from email.mime.text import MIMEText
    lines = ["Aegis 舰队告警 %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(now)), ""]
    for a in alerts:
        lines.append("[%s] %s %s: %s" % (a["severity"], a["type"], a["hostname"], a["detail"]))
    msg = MIMEText("\n".join(lines), "plain", "utf-8")
    msg["Subject"] = "Aegis 告警：critical/high %d 条" % len(alerts)
    msg["From"] = sender
    msg["To"] = to_addrs
    port = int(os.environ.get("AEGIS_ALERT_SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        smtp.starttls()
        smtp.login(user, pwd)
        smtp.sendmail(sender, [x.strip() for x in to_addrs.split(",") if x.strip()], msg.as_string())
    return len(alerts)


def fetch_console_config(collector_token, console_base):
    """从控制台拉告警配置（Collector bearer 只读）。失败返回 None（回落 env/默认）。"""
    if not console_base or not collector_token:
        return None
    try:
        req = urllib.request.Request(
            console_base.rstrip("/") + "/api/settings/alerting",
            headers={"Authorization": "Bearer " + collector_token})
        with urllib.request.urlopen(req, timeout=20) as r:
            return (json.loads(r.read().decode()) or {}).get("config")
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector", default=os.environ.get("AEGIS_COLLECTOR_URL", "http://127.0.0.1:8931"))
    ap.add_argument("--token", default=os.environ.get("AEGIS_COLLECTOR_TOKEN", ""))
    ap.add_argument("--console", default=os.environ.get("AEGIS_CONSOLE", "https://aegis.example.com"),
                    help="console base for reading alert config (collector-bearer read-only)")
    ap.add_argument("--webhook", default=None, help="override console config webhook")
    ap.add_argument("--format", default=None, choices=["generic", "dingtalk"])
    ap.add_argument("--offline-hours", type=float, default=None)
    ap.add_argument("--min-interval-hours", type=float, default=None)
    ap.add_argument("--state", default=os.environ.get("AEGIS_ALERT_STATE", "/var/lib/aegis/alert-state.json"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not args.token:
        log("no collector token; provide --token or AEGIS_COLLECTOR_TOKEN")
        return 1
    # 配置优先级：CLI 显式 > 控制台 alert_config（PG）> 环境变量 > 内置默认。
    cc = fetch_console_config(args.token, args.console) or {}
    enabled = cc.get("enabled", True)
    webhook = args.webhook if args.webhook is not None else (cc.get("webhook") or os.environ.get("AEGIS_ALERT_WEBHOOK", ""))
    fmt = args.format or cc.get("format") or os.environ.get("AEGIS_ALERT_FORMAT", "generic")
    offline_hours = args.offline_hours if args.offline_hours is not None else float(cc.get("offline_hours", 2.0))
    min_interval = args.min_interval_hours if args.min_interval_hours is not None else float(cc.get("min_interval_hours", 6.0))
    email_to = str(cc.get("email") or os.environ.get("AEGIS_ALERT_EMAIL_TO", "")).strip()
    if not enabled:
        log("alerting disabled in console config; skip")
        return 0
    now = int(time.time())
    try:
        devices = fetch_devices(args.collector, args.token)
    except Exception as e:
        log("fetch devices failed: %s" % e)
        return 1
    alerts = evaluate(devices, now, offline_hours)
    state = load_state(args.state)
    pending = dedup(alerts, state, now, min_interval)
    if not pending:
        log("no new alerts (evaluated %d devices, %d raw alerts, all deduped/none)" % (len(devices), len(alerts)))
        return 0
    for a in pending:
        log("ALERT %s %s %s: %s" % (a["severity"], a["type"], a["hostname"], a["detail"]))
    if args.dry_run or (not webhook and not email_to):
        log("dry-run (no webhook/email configured or --dry-run): not sending, state unchanged")
        return 0
    sent_any, failed = False, False
    if webhook:
        try:
            st = post_webhook(webhook, fmt, pending, now)
            log("webhook posted status=%s" % st)
            sent_any = True
        except Exception as e:
            log("webhook post failed (will retry next run): %s" % e)
            failed = True
    if email_to:
        try:
            n = send_email(email_to, pending, now)
            if n is None:
                log("email channel: SMTP env not configured (AEGIS_ALERT_SMTP_*), skipped")
            else:
                log("email sent to %s (%d alerts)" % (email_to, n))
                sent_any = True
        except Exception as e:
            log("email send failed (will retry next run): %s" % e)
            failed = True
    # 任一通道成功即记去重状态；全部失败保留状态下轮重试。
    if sent_any:
        for a in pending:
            state[a["_key"]] = now
        save_state(args.state, state)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
