#!/usr/bin/env python3
"""Minimal fail-closed enterprise 4A security-event receiver.

This reference service covers the audit boundary of a 4A integration. It accepts
only Aegis's minimized posture event and never performs an access-control
action; enforcement stays behind an external approval workflow.
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 2_000_000
MAX_TOKEN = 4096
EVENT_FIELDS = {"schema", "event_id", "event_type", "source", "tenant", "subject", "risk", "authorization", "audit"}


def valid_event(value):
    if not isinstance(value, dict) or set(value) != EVENT_FIELDS:
        return False
    subject = value.get("subject")
    risk = value.get("risk")
    authorization = value.get("authorization")
    audit = value.get("audit")
    return (
        value.get("schema") == "aegis.enterprise-4a.event/v1"
        and value.get("event_type") == "ai_agent_security_posture"
        and value.get("source") == "aegis"
        and isinstance(value.get("event_id"), str)
        and bool(re.fullmatch(r"[0-9a-f]{40}", value["event_id"]))
        and isinstance(value.get("tenant"), str)
        and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value["tenant"]))
        and isinstance(subject, dict) and set(subject) == {"type", "id"}
        and subject.get("type") == "device"
        and isinstance(subject.get("id"), str) and 8 <= len(subject["id"]) <= 128
        and isinstance(risk, dict) and set(risk) == {"level", "finding_count", "policy_version", "observed_at"}
        and risk.get("level") in {"critical", "high", "medium", "low", "normal"}
        and type(risk.get("finding_count")) is int and 0 <= risk["finding_count"] <= 10_000
        and isinstance(risk.get("policy_version"), str) and 1 <= len(risk["policy_version"]) <= 64
        and type(risk.get("observed_at")) is int and risk["observed_at"] >= 0
        and isinstance(authorization, dict) and set(authorization) == {"decision", "enforcement"}
        and authorization.get("decision") in {"observe", "alert", "access_review_pending", "containment_pending_approval"}
        and authorization.get("enforcement") == "external_approval_required"
        and isinstance(audit, dict) and set(audit) == {"correlation_id", "data_classification"}
        and audit.get("correlation_id") == value["event_id"]
        and audit.get("data_classification") == "internal_security_metadata"
    )


def open_db(path):
    db = sqlite3.connect(path, timeout=5)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("""CREATE TABLE IF NOT EXISTS security_events(
        id INTEGER PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
        event_id TEXT NOT NULL UNIQUE, tenant TEXT NOT NULL, subject_id TEXT NOT NULL,
        risk_level TEXT NOT NULL, finding_count INTEGER NOT NULL,
        policy_version TEXT NOT NULL, observed_at INTEGER NOT NULL,
        decision TEXT NOT NULL, received_at INTEGER NOT NULL)""")
    db.commit()
    return db


class Receiver(BaseHTTPRequestHandler):
    server_version = "Aegis4AReceiver/0.1"

    def log_message(self, fmt, *args):
        return

    def send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        expected = os.environ.get("AEGIS_4A_ACCESS_TOKEN", "")
        return 32 <= len(expected) <= MAX_TOKEN and hmac.compare_digest(supplied, expected)

    def do_GET(self):
        if self.path != "/health":
            return self.send_json(404, {"error": "not_found"})
        try:
            with open_db(self.server.db_path) as db:
                db.execute("SELECT 1").fetchone()
            return self.send_json(200, {"status": "ok", "database": "ok"})
        except sqlite3.Error:
            return self.send_json(503, {"status": "error", "database": "error"})

    def do_POST(self):
        if self.path != "/api/v1/security-events":
            return self.send_json(404, {"error": "not_found"})
        if not self.authorized():
            return self.send_json(401, {"error": "unauthorized"})
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isdigit() or not 1 <= int(raw_length) <= MAX_BODY:
            return self.send_json(413, {"error": "invalid_body_size"})
        body = self.rfile.read(int(raw_length))
        digest = hashlib.sha256(body).hexdigest()
        idem = self.headers.get("Idempotency-Key", "")
        if not re.fullmatch(r"[0-9a-f]{64}", idem) or not hmac.compare_digest(idem, digest):
            return self.send_json(400, {"error": "invalid_idempotency_key"})
        try:
            event = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return self.send_json(400, {"error": "invalid_json"})
        if not valid_event(event):
            return self.send_json(422, {"error": "invalid_event"})
        received = int(time.time())
        try:
            with open_db(self.server.db_path) as db:
                duplicate = db.execute("SELECT 1 FROM security_events WHERE idempotency_key=?", (idem,)).fetchone() is not None
                if not duplicate:
                    db.execute(
                        "INSERT INTO security_events(idempotency_key,event_id,tenant,subject_id,risk_level,finding_count,policy_version,observed_at,decision,received_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (idem, event["event_id"], event["tenant"], event["subject"]["id"], event["risk"]["level"], event["risk"]["finding_count"], event["risk"]["policy_version"], event["risk"]["observed_at"], event["authorization"]["decision"], received),
                    )
                    db.commit()
        except sqlite3.IntegrityError:
            duplicate = True
        except sqlite3.Error:
            return self.send_json(503, {"error": "storage_unavailable"})
        return self.send_json(200 if duplicate else 202, {"accepted": True, "duplicate": duplicate, "event_id": event["event_id"]})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--db", default="/var/lib/aegis/4a-audit.db")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.listen, args.port), Receiver)
    server.db_path = args.db
    with open_db(args.db):
        pass
    server.serve_forever()


if __name__ == "__main__":
    main()
