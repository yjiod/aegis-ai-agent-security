"""tests/test_alert_check.py — 告警评估器单测（条件/去重节流/webhook payload）。"""
import importlib.util
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).parents[1]


def load_alert():
    spec = importlib.util.spec_from_file_location("aegis_alert_check", ROOT / "scripts" / "aegis_alert_check.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


A = load_alert()


def dev(did="dev1", last_seen=None, self_update=None, critical=0, hostname="host1"):
    return {"device_id": did, "hostname": hostname, "last_seen": last_seen or 0,
            "self_update": self_update, "latest_severity": {"critical": critical, "high": 0, "medium": 0, "low": 0}}


class AlertEvaluateTests(unittest.TestCase):
    def test_offline_detected(self):
        now = 1_800_000_000
        alerts = A.evaluate([dev(last_seen=now - 5 * 3600)], now, offline_hours=2)
        self.assertEqual([a["type"] for a in alerts], ["device_offline"])
        self.assertEqual(alerts[0]["severity"], "high")

    def test_recent_online_not_alerted(self):
        now = 1_800_000_000
        alerts = A.evaluate([dev(last_seen=now - 600)], now, offline_hours=2)
        self.assertEqual(alerts, [])

    def test_never_seen_not_offline_alert(self):
        # last_seen=0（从未上报）不算"曾在线后静默"，避免新注册未上报设备误报离线
        now = 1_800_000_000
        alerts = A.evaluate([dev(last_seen=0)], now, offline_hours=2)
        self.assertEqual(alerts, [])

    def test_bad_self_update_detected(self):
        now = 1_800_000_000
        for reason in ("preflight_failed", "rolled_back:sha_mismatch", "apply_failed:OSError"):
            alerts = A.evaluate([dev(last_seen=now - 60, self_update={"updated": False, "reason": reason, "latest": "0.36.5"})], now, 2)
            self.assertEqual([a["type"] for a in alerts], ["self_update_failed"], reason)
        # ok / 例行不上报 → 无告警
        self.assertEqual(A.evaluate([dev(last_seen=now - 60, self_update={"updated": True, "reason": "ok"})], now, 2), [])
        self.assertEqual(A.evaluate([dev(last_seen=now - 60)], now, 2), [])

    def test_critical_findings_detected(self):
        now = 1_800_000_000
        alerts = A.evaluate([dev(last_seen=now - 60, critical=2)], now, 2)
        self.assertEqual([a["type"] for a in alerts], ["critical_findings"])
        self.assertEqual(alerts[0]["severity"], "critical")

    def test_dedup_within_interval(self):
        now = 1_800_000_000
        alerts = A.evaluate([dev(last_seen=now - 5 * 3600)], now, 2)
        state = {}
        p1 = A.dedup(alerts, state, now, min_interval=6)
        self.assertEqual(len(p1), 1)
        # 未发送（state 未更新）时再次评估仍 pending；发送后更新 state 则节流
        for a in p1:
            state[a["_key"]] = now
        p2 = A.dedup(alerts, state, now + 3600, min_interval=6)
        self.assertEqual(p2, [])
        p3 = A.dedup(alerts, state, now + 7 * 3600, min_interval=6)
        self.assertEqual(len(p3), 1)


class _Sink(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        _Sink.received.append(json.loads(self.rfile.read(n).decode()))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class WebhookPayloadTests(unittest.TestCase):
    def _serve(self):
        srv = HTTPServer(("127.0.0.1", 0), _Sink)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, "http://127.0.0.1:%d/" % srv.server_address[1]

    def test_generic_payload(self):
        srv, url = self._serve()
        try:
            now = 1_800_000_000
            alerts = [{"type": "device_offline", "device_id": "d1", "hostname": "h1", "severity": "high", "detail": "offline 3h", "_key": "k"}]
            st = A.post_webhook(url, "generic", alerts, now)
            self.assertEqual(st, 200)
            body = _Sink.received[-1]
            self.assertEqual(body["schema"], "aegis.alert/v1")
            self.assertEqual(body["at"], now)
            self.assertEqual(body["alerts"][0]["type"], "device_offline")
            self.assertNotIn("_key", body["alerts"][0])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_dingtalk_payload(self):
        srv, url = self._serve()
        try:
            now = 1_800_000_000
            alerts = [{"type": "critical_findings", "device_id": "d1", "hostname": "h1", "severity": "critical", "detail": "2 critical finding(s)", "_key": "k"}]
            st = A.post_webhook(url, "dingtalk", alerts, now)
            self.assertEqual(st, 200)
            body = _Sink.received[-1]
            self.assertEqual(body["msgtype"], "text")
            self.assertIn("critical_findings", body["text"]["content"])
            self.assertIn("h1", body["text"]["content"])
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()


class AlertEmailTests(unittest.TestCase):
    """邮件通道：env 缺失→None(跳过)；配置齐→走 smtplib 且凭据仅来自 env。"""

    def test_send_email_without_smtp_env_returns_none(self):
        import os
        saved = {k: os.environ.pop(k, None) for k in
                 ("AEGIS_ALERT_SMTP_HOST", "AEGIS_ALERT_SMTP_USER", "AEGIS_ALERT_SMTP_PASS", "AEGIS_ALERT_SMTP_FROM")}
        try:
            self.assertIsNone(A.send_email("a@example.com", [], 1_800_000_000))
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_send_email_posts_via_smtp(self):
        import os
        from unittest.mock import patch, MagicMock
        alerts = [{"type": "critical_findings", "device_id": "d1", "hostname": "h1",
                   "severity": "critical", "detail": "2 critical finding(s)"}]
        env = {"AEGIS_ALERT_SMTP_HOST": "smtp.example.com", "AEGIS_ALERT_SMTP_USER": "u@example.com",
               "AEGIS_ALERT_SMTP_PASS": "pw", "AEGIS_ALERT_SMTP_FROM": "aegis@example.com"}
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            with patch("smtplib.SMTP") as Smtp:
                inst = MagicMock()
                Smtp.return_value.__enter__.return_value = inst
                n = A.send_email("ops@example.com, sec@example.com", alerts, 1_800_000_000)
                self.assertEqual(n, 1)
                Smtp.assert_called_once_with("smtp.example.com", 587, timeout=20)
                inst.starttls.assert_called_once()
                inst.login.assert_called_once_with("u@example.com", "pw")
                self.assertEqual(inst.sendmail.call_count, 1)
                args = inst.sendmail.call_args[0]
                self.assertEqual(args[0], "aegis@example.com")
                self.assertEqual(args[1], ["ops@example.com", "sec@example.com"])
                import base64
                body = base64.b64decode(args[2].split("\n\n", 1)[1]).decode("utf-8")
                self.assertIn("critical_findings", body)
                self.assertIn("h1", body)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
