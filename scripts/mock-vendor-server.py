#!/usr/bin/env python3
"""Mock vendor server for local Aegis adapter testing.

Simulates VendorEdr EDR and VendorMdm desktop management API endpoints.
Run alongside dev-collector.sh to test the full adapter pipeline locally.

Usage:
    python3 scripts/mock-vendor-server.py [--port 9443]

Endpoints:
    POST /api/aegis/events     — VendorEdr EDR event ingestion (returns 200 + JSON ack)
    POST /api/aegis/posture    — VendorMdm compliance posture update (returns 200 + JSON ack)
    POST /hooks/aegis          — Generic security webhook (returns 200 + JSON ack)
    GET  /health               — Health check

All endpoints validate Authorization header (Bearer token) and log received payloads.
"""
import argparse
import json
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Demo tokens matching .dev/vendor.env
VENDOR_EDR_TOKEN = "mock-vendor_edr-edr-token-for-local-dev-only-32chars"
VENDOR_MDM_TOKEN = "mock-vendor_mdm-token-for-local-dev-only-32chars-min"
WEBHOOK_SECRET = "mock-aegis-webhook-secret-for-local-dev-32chars-min"

received_events = []


class MockVendorHandler(BaseHTTPRequestHandler):
    """Handles mock vendor API requests."""

    def log_message(self, format, *args):
        """Override to use structured logging."""
        sys.stderr.write(f"[mock-vendor] {args[0]}\n")

    def _check_auth(self, expected_token):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._respond(401, {"error": "missing_authorization"})
            return False
        token = auth[7:]
        if token != expected_token:
            self._respond(403, {"error": "invalid_token"})
            return False
        return True

    def _read_body(self, limit=65536):
        length = int(self.headers.get("Content-Length", 0))
        if length > limit:
            self._respond(413, {"error": "payload_too_large"})
            return None
        body = self.rfile.read(length)
        try:
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {"error": "invalid_json"})
            return None

    def _respond(self, status, body):
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {
                "status": "ok",
                "service": "mock-vendor-server",
                "received_events": len(received_events),
                "uptime_seconds": int(time.time() - START_TIME),
            })
        elif self.path == "/events":
            # Debug: show all received events
            self._respond(200, {"events": received_events[-50:]})
        else:
            self._respond(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/api/aegis/events":
            # VendorEdr EDR event ingestion
            if not self._check_auth(VENDOR_EDR_TOKEN):
                return
            payload = self._read_body()
            if payload is None:
                return
            # Validate minimum fields
            required = {"event_type", "source", "device_id", "severity", "recommended_action"}
            if not required.issubset(payload.keys()):
                self._respond(422, {"error": "missing_required_fields", "required": sorted(required)})
                return
            if payload.get("source") != "aegis":
                self._respond(422, {"error": "invalid_source", "expected": "aegis"})
                return
            event_id = f"edr-{int(time.time()*1000)}-{len(received_events)+1:04d}"
            record = {
                "vendor": "vendor_edr_edr",
                "event_id": event_id,
                "received_at": int(time.time()),
                "payload": payload,
            }
            received_events.append(record)
            print(f"  [VendorEdr EDR] {payload.get('severity','?').upper()} | "
                  f"{payload.get('device_id','?')} | "
                  f"action={payload.get('recommended_action','?')} | "
                  f"findings={payload.get('finding_count',0)}")
            self._respond(200, {
                "accepted": True,
                "event_id": event_id,
                "action_taken": "logged",
                "message": "Mock EDR: event recorded, no real isolation performed",
            })

        elif self.path == "/api/aegis/posture":
            # VendorMdm compliance posture
            if not self._check_auth(VENDOR_MDM_TOKEN):
                return
            payload = self._read_body()
            if payload is None:
                return
            required = {"source", "device_id", "compliant", "risk_level"}
            if not required.issubset(payload.keys()):
                self._respond(422, {"error": "missing_required_fields", "required": sorted(required)})
                return
            event_id = f"leag-{int(time.time()*1000)}-{len(received_events)+1:04d}"
            record = {
                "vendor": "vendor_mdm",
                "event_id": event_id,
                "received_at": int(time.time()),
                "payload": payload,
            }
            received_events.append(record)
            status = "合规" if payload.get("compliant") else "不合规"
            print(f"  [厂商桌管] {status} | "
                  f"{payload.get('device_id','?')} | "
                  f"risk={payload.get('risk_level','?')} | "
                  f"reason={payload.get('reason','?')}")
            self._respond(200, {
                "accepted": True,
                "event_id": event_id,
                "compliance_updated": True,
                "message": "Mock VendorMdm: posture recorded, no real enforcement applied",
            })

        elif self.path == "/hooks/aegis":
            # Generic security webhook
            if not self._check_auth(WEBHOOK_SECRET):
                return
            payload = self._read_body()
            if payload is None:
                return
            event_id = f"hook-{int(time.time()*1000)}-{len(received_events)+1:04d}"
            record = {
                "vendor": "security_webhook",
                "event_id": event_id,
                "received_at": int(time.time()),
                "payload": payload,
            }
            received_events.append(record)
            print(f"  [Webhook] schema={payload.get('schema','?')} | "
                  f"device={payload.get('device_id','?')} | "
                  f"findings={len(payload.get('findings',[]))}")
            self._respond(200, {
                "accepted": True,
                "event_id": event_id,
                "message": "Mock webhook: payload recorded",
            })

        else:
            self._respond(404, {"error": "not_found"})


START_TIME = time.time()


def write_vendor_env(dev_dir: Path):
    """Write .dev/vendor.env with mock credentials for adapter testing."""
    dev_dir.mkdir(parents=True, exist_ok=True)
    env_file = dev_dir / "vendor.env"
    env_file.write_text(f"""# Mock vendor credentials for local adapter testing
# Source this file or export these vars before running aegis_adapter_worker.py
VENDOR_EDR_EDR_TOKEN={VENDOR_EDR_TOKEN}
VENDOR_MDM_TOKEN={VENDOR_MDM_TOKEN}
AEGIS_WEBHOOK_SECRET={WEBHOOK_SECRET}

# Mock vendor server URL (HTTPS not enforced in mock mode)
AEGIS_VENDOR_BASE_URL=http://127.0.0.1:{{port}}
""")
    return env_file


def main():
    parser = argparse.ArgumentParser(description="Mock vendor server for Aegis adapter testing")
    parser.add_argument("--port", type=int, default=9443, help="Listen port (default: 9443)")
    parser.add_argument("--write-env", action="store_true", help="Write .dev/vendor.env with mock credentials")
    args = parser.parse_args()

    if args.write_env:
        root = Path(__file__).resolve().parent.parent
        env_file = write_vendor_env(root / ".dev")
        # Fix the port placeholder
        content = env_file.read_text().replace("{port}", str(args.port))
        env_file.write_text(content)
        print(f"wrote {env_file}")

    server = HTTPServer(("127.0.0.1", args.port), MockVendorHandler)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  Aegis Mock Vendor Server                                   ║
║  Listening: http://127.0.0.1:{args.port}                          ║
╠══════════════════════════════════════════════════════════════╣
║  POST /api/aegis/events   — VendorEdr EDR (Bearer token)      ║
║  POST /api/aegis/posture  — VendorMdm 桌管 (Bearer token)    ║
║  POST /hooks/aegis        — Security Webhook (Bearer secret) ║
║  GET  /health             — Health check                    ║
║  GET  /events             — View received events (debug)    ║
╠══════════════════════════════════════════════════════════════╣
║  Tokens (also in .dev/vendor.env):                          ║
║    VENDOR_EDR_EDR_TOKEN={VENDOR_EDR_TOKEN[:20]}...  ║
║    VENDOR_MDM_TOKEN={VENDOR_MDM_TOKEN[:20]}...     ║
║    AEGIS_WEBHOOK_SECRET={WEBHOOK_SECRET[:16]}...  ║
╚══════════════════════════════════════════════════════════════╝

Adapter config for local testing (aegis-adapters.example.json):
  allowed_hosts: ["127.0.0.1"]
  vendor_edr.url:   http://127.0.0.1:{args.port}/api/aegis/events
  vendor_mdm.url:  http://127.0.0.1:{args.port}/api/aegis/posture
  webhook.url:   http://127.0.0.1:{args.port}/hooks/aegis

NOTE: The production adapter enforces HTTPS. For local mock testing,
set AEGIS_ADAPTER_ALLOW_HTTP=1 or use the --dry-run flag.
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[mock-vendor] shutting down ({len(received_events)} events received)")
        server.shutdown()


if __name__ == "__main__":
    main()
