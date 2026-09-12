#!/usr/bin/env python3
"""PacketFence REST 契约 mock —— 仅用于在 ARM lab 验证 PacketFenceAdapter 链路。

真实 PacketFence 无官方 arm64 镜像/包，真实准入验证需 x86 + 办公网位置。
本 mock 只实现适配器用到的最小端点：
  GET  /api/v1/nodes            列表
  GET  /api/v1/node/<id>        单节点
  PUT  /api/v1/node/<id>        回写状态/类别(准入/隔离)
  GET  /api/v1/config/switches  健康检查
Bearer token 由环境变量 VENDOR_NAC_TOKEN 指定(默认 mock-nac-token)。
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ.get("VENDOR_NAC_TOKEN", "mock-nac-token")
NODES = {
    "aa:bb:cc:dd:ee:01": {"mac": "aa:bb:cc:dd:ee:01", "hostname": "lab-mac-01",
                          "status": "reg", "category": "aegis-pass", "last_seen": "2026-09-12 10:00:00"},
}


class H(BaseHTTPRequestHandler):
    def _auth(self):
        return self.headers.get("Authorization", "") == "Bearer " + TOKEN

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        if self.path.startswith("/api/v1/nodes"):
            return self._send(200, {"items": list(NODES.values())})
        m = re.match(r"/api/v1/node/([^/?]+)", self.path)
        if m:
            n = NODES.get(m.group(1))
            return self._send(200, {"item": n} if n else {})
        if self.path.startswith("/api/v1/config/switches"):
            return self._send(200, {"items": []})
        self._send(404, {"error": "not_found"})

    def do_PUT(self):
        if not self._auth():
            return self._send(401, {"error": "unauthorized"})
        m = re.match(r"/api/v1/node/([^/?]+)", self.path)
        if m:
            ln = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(ln) or b"{}")
            NODES.setdefault(m.group(1), {"mac": m.group(1), "hostname": "unknown", "last_seen": ""}).update(body)
            return self._send(200, {"item": NODES[m.group(1)]})
        self._send(404, {"error": "not_found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 9999), H).serve_forever()
