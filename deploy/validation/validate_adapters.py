#!/usr/bin/env python3
"""端到端验证 Wazuh(EDR) + PacketFence(NAC mock) 适配器 against lab 服务端。

用法(lab 上): python3 validate_adapters.py
环境变量: WAZUH_URL / PF_URL / WAZUH_USER / WAZUH_PASS; 自动设 AEGIS_ADAPTER_INSECURE_TLS=1(仅验证)。
"""
import base64
import json
import os
import ssl
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("AEGIS_ADAPTER_INSECURE_TLS", "1")

from aegis_4a_interface import SecurityEvent, ComplianceResult  # noqa: E402
from aegis_4a_reference_adapters import WazuhAdapter, PacketFenceAdapter  # noqa: E402

WAZUH = os.environ.get("WAZUH_URL", "https://127.0.0.1:15500")
PF = os.environ.get("PF_URL", "http://127.0.0.1:19999")
WUSER = os.environ.get("WAZUH_USER", "aegis")
WPASS = os.environ.get("WAZUH_PASS", "Wazuh-validation-123")


def wazuh_jwt() -> str:
    req = urllib.request.Request(WAZUH + "/security/user/login", data=b"", method="POST")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{WUSER}:{WPASS}".encode()).decode())
    ctx = ssl._create_unverified_context()
    d = json.load(urllib.request.urlopen(req, context=ctx, timeout=20))
    return (d.get("data") or {}).get("token", "")


print("== Wazuh (EDR) ==")
try:
    tok = wazuh_jwt()
    print("  jwt_len:", len(tok))
    os.environ["VENDOR_EDR_TOKEN"] = tok
    w = WazuhAdapter(base_url=WAZUH)
    print("  health:", w.health_check())
    devs = w.list_devices(limit=5)
    print("  devices:", [(d.device_id, d.hostname, d.compliance_status) for d in devs])
    if devs:
        r = w.check_compliance(devs[0].device_id, "aegis-policy")
        print("  compliance:", r.compliant, "| reason:", r.reason, "| evidence:", r.evidence)
        ev = SecurityEvent(event_id="val-e1", event_type="ai_agent_security_finding",
                           severity="high", device_id=devs[0].device_id)
        print("  forward_event:", w.forward_event(ev))
    else:
        print("  (no agents enrolled yet; list_devices empty is expected pre-enrollment)")
except Exception as e:  # noqa: BLE001
    print("  WAZUH_ERROR:", type(e).__name__, e)

print("== PacketFence (NAC, contract-mock) ==")
try:
    os.environ["VENDOR_NAC_TOKEN"] = "mock-nac-token"
    p = PacketFenceAdapter(base_url=PF)
    print("  health:", p.health_check())
    nds = p.list_devices()
    print("  nodes:", [(d.device_id, d.hostname, d.compliance_status) for d in nds])
    if nds:
        nid = nds[0].device_id
        r = p.check_compliance(nid, "aegis-policy")
        print("  compliance:", r.compliant, "| evidence:", r.evidence)
        ok = p.report_compliance(ComplianceResult(device_id=nid, policy_id="aegis-policy", compliant=False))
        print("  report_compliance(non-compliant):", ok)
        after = p.get_device(nid)
        print("  node after writeback:", after.compliance_status, "| category:", after.raw.get("category"))
except Exception as e:  # noqa: BLE001
    print("  PF_ERROR:", type(e).__name__, e)

print("VALIDATION_DONE")
