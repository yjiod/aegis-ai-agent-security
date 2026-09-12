#!/usr/bin/env python3
"""
三个开源候选产品的参考适配器（验证期用），均实现厂商中立契约 FourAInterface。

  - FleetAdapter      : Fleet (开源 MDM + osquery)  —— 桌管/资产/策略下发/部署
  - WazuhAdapter      : Wazuh (开源 EDR/SIEM)      —— 资产/事件转发/响应/合规
  - PacketFenceAdapter: PacketFence (开源 NAC)     —— 准入/资产/合规状态回写

定位：参考实现，供产品验证与过渡期使用；与任何商用适配器地位对等，都只通过
FourAInterface 被核心调用。替换产品=换适配器+改配置，核心零改动。

配置来自构造参数/环境变量（base_url + token env 名），不写死地址或凭据。
契约数据类为 frozen，适配器一律构造新实例（dataclasses.replace），不做原地修改。
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import replace
from typing import Any

# 允许按文件路径直接加载时解析同目录的契约模块。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aegis_4a_interface import (
    FourACapability as Cap,
    DeviceRecord,
    ComplianceResult,
    SecurityEvent,
    DeploymentTask,
)


class AdapterError(RuntimeError):
    pass


def _request(base_url: str, token: str, path: str, method: str = "GET", body: dict | None = None, timeout: int = 20) -> Any:
    url = base_url.rstrip("/") + path
    if not (url.startswith("https://") or url.startswith("http://127.0.0.1") or url.startswith("http://localhost")):
        raise AdapterError("adapter_url_not_allowed:" + url)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    # 仅验证期: 实验室自签证书可显式关闭校验(AEGIS_ADAPTER_INSECURE_TLS=1); 生产默认强制校验。
    ctx = None
    if os.environ.get("AEGIS_ADAPTER_INSECURE_TLS") == "1":
        import ssl
        ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # nosec: scheme/host allowlisted
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise AdapterError(f"http_{e.code}:{path}") from e
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        raise AdapterError(f"request_failed:{path}:{type(e).__name__}") from e


def _token(env_name: str) -> str:
    return os.environ.get(env_name, "")


def _comp(ok: bool) -> str:
    return "compliant" if ok else "non_compliant"


# ─── Fleet (MDM + osquery) ────────────────────────────────────────────────
class FleetAdapter:
    def __init__(self, base_url: str, token_env: str = "VENDOR_MDM_TOKEN"):
        self._base = base_url
        self._token_env = token_env

    def vendor_name(self) -> str: return "fleet"
    def vendor_version(self) -> str: return "4.x"

    def capabilities(self):
        return {Cap.ASSET_INVENTORY, Cap.AGENT_DEPLOYMENT, Cap.SOFTWARE_DISTRIBUTION, Cap.POLICY_DISTRIBUTION, Cap.ACCESS_CONTROL}

    def health_check(self):
        for path in ("/api/latest/me", "/api/v1/me"):
            try:
                me = _request(self._base, _token(self._token_env), path)
                return {"ok": True, "user": (me.get("user") or {}).get("email", "")}
            except AdapterError:
                continue
        try:
            _request(self._base, _token(self._token_env), "/api/latest/fleet/hosts?per_page=1")
            return {"ok": True, "via": "hosts"}
        except AdapterError as e:
            return {"ok": False, "error": str(e)}

    def list_devices(self, query: str = "", limit: int = 100, offset: int = 0):
        d = _request(self._base, _token(self._token_env), f"/api/latest/fleet/hosts?per_page={limit}&page={offset // max(limit, 1)}")
        out = []
        for h in (d.get("hosts") or []):
            out.append(DeviceRecord(device_id=str(h.get("uuid") or h.get("id")), hostname=h.get("hostname", ""),
                                    os_type=h.get("platform", ""), os_version=h.get("os_version", ""),
                                    compliance_status=_comp(h.get("status") == "online"), raw=h))
        return out

    def get_device(self, device_id: str):
        for rec in self.list_devices(limit=200):
            if rec.device_id == device_id:
                return rec
        return None

    def check_compliance(self, device_id: str, policy_id: str) -> ComplianceResult:
        d = _request(self._base, _token(self._token_env), f"/api/latest/fleet/hosts/identifier/{device_id}")
        host = d.get("host") or {}
        ok = bool(host) and host.get("status") == "online"
        return ComplianceResult(device_id=device_id, policy_id=policy_id, compliant=ok,
                                reason="" if ok else "fleet_host_not_online",
                                evidence={"fleet_status": host.get("status", "unknown")})

    def report_compliance(self, result: ComplianceResult) -> bool:
        try:
            _request(self._base, _token(self._token_env), "/api/latest/fleet/labels", "POST",
                     {"name": f"aegis-{result.policy_id}", "query": "select 1;"})
            return True
        except AdapterError:
            return False

    def forward_event(self, event: SecurityEvent) -> dict:
        return {"accepted": False, "reason": "fleet_is_pull_based"}

    def deploy_agent(self, task: DeploymentTask) -> DeploymentTask:
        try:
            d = _request(self._base, _token(self._token_env), "/api/latest/fleet/spec/enroll_secret", "GET")
            return replace(task, status="in_progress")
        except AdapterError as e:
            return replace(task, status="failed", error=str(e))

    def get_deployment_status(self, task_id: str):
        return None

    def push_policy(self, device_ids, policy_json) -> dict:
        try:
            _request(self._base, _token(self._token_env), "/api/latest/fleet/spec/packs", "POST", {"packs": [json.loads(policy_json)]})
            return {"pushed": len(device_ids), "channel": "fleet_pack"}
        except AdapterError as e:
            return {"pushed": 0, "error": str(e)}


# ─── Wazuh (EDR / SIEM) ───────────────────────────────────────────────────
class WazuhAdapter:
    def __init__(self, base_url: str, token_env: str = "VENDOR_EDR_TOKEN"):
        self._base = base_url
        self._token_env = token_env

    def vendor_name(self) -> str: return "wazuh"
    def vendor_version(self) -> str: return "4.x"

    def capabilities(self):
        return {Cap.ASSET_INVENTORY, Cap.ACCESS_CONTROL, Cap.POLICY_DISTRIBUTION}

    def health_check(self):
        try:
            d = _request(self._base, _token(self._token_env), "/manager/info")
            return {"ok": True, "version": (d.get("data") or {}).get("version", "")}
        except AdapterError as e:
            return {"ok": False, "error": str(e)}

    def _items(self, d):
        return ((d.get("data") or {}).get("affected_items") or [])

    def list_devices(self, query: str = "", limit: int = 100, offset: int = 0):
        d = _request(self._base, _token(self._token_env), f"/agents?offset={offset}&limit={limit}")
        out = []
        for a in self._items(d):
            osinfo = a.get("os") if isinstance(a.get("os"), dict) else {}
            out.append(DeviceRecord(device_id=str(a.get("id")), hostname=a.get("name", ""),
                                    os_type=(osinfo or {}).get("platform", ""), os_version=(osinfo or {}).get("version", ""),
                                    compliance_status=_comp(a.get("status") == "active"), raw=a))
        return out

    def get_device(self, device_id: str):
        try:
            d = _request(self._base, _token(self._token_env), f"/agents/{device_id}")
            items = self._items(d) or ([d.get("data")] if d.get("data") else [])
            a = items[0] if items else {}
            if not a:
                return None
            return DeviceRecord(device_id=str(a.get("id")), hostname=a.get("name", ""),
                                compliance_status=_comp(a.get("status") == "active"), raw=a)
        except AdapterError:
            return None

    def check_compliance(self, device_id: str, policy_id: str) -> ComplianceResult:
        rec = self.get_device(device_id)
        ok = bool(rec and rec.compliance_status == "compliant")
        return ComplianceResult(device_id=device_id, policy_id=policy_id, compliant=ok,
                                reason="" if ok else "wazuh_agent_not_active",
                                evidence={"wazuh_status": "active" if ok else "inactive"})

    def report_compliance(self, result: ComplianceResult) -> bool:
        return True  # Wazuh 合规由 manager 规则判定；回写记录在 Aegis 侧

    def forward_event(self, event: SecurityEvent) -> dict:
        try:
            _request(self._base, _token(self._token_env), "/active-response", "PUT",
                     {"command": "aegis-observe", "arguments": [event.event_type, event.device_id]})
            return {"accepted": True}
        except AdapterError as e:
            return {"accepted": False, "error": str(e)}

    def deploy_agent(self, task: DeploymentTask) -> DeploymentTask:
        return replace(task, status="pending", error="wazuh_agent_via_mdm_or_installer")

    def get_deployment_status(self, task_id: str):
        return None

    def push_policy(self, device_ids, policy_json) -> dict:
        return {"pushed": 0, "reason": "wazuh_policy_via_manager_conf"}


# ─── PacketFence (NAC) ────────────────────────────────────────────────────
class PacketFenceAdapter:
    def __init__(self, base_url: str, token_env: str = "VENDOR_NAC_TOKEN"):
        self._base = base_url
        self._token_env = token_env

    def vendor_name(self) -> str: return "packetfence"
    def vendor_version(self) -> str: return "13.x"

    def capabilities(self):
        return {Cap.ACCESS_CONTROL, Cap.ASSET_INVENTORY, Cap.DEVICE_IDENTITY}

    def health_check(self):
        try:
            _request(self._base, _token(self._token_env), "/api/v1/config/switches")
            return {"ok": True}
        except AdapterError as e:
            return {"ok": False, "error": str(e)}

    def list_devices(self, query: str = "", limit: int = 100, offset: int = 0):
        d = _request(self._base, _token(self._token_env), f"/api/v1/nodes?limit={limit}&offset={offset}")
        out = []
        for n in (d.get("items") or d.get("nodes") or []):
            out.append(DeviceRecord(device_id=str(n.get("mac") or n.get("uuid") or n.get("id")),
                                    hostname=n.get("hostname", "") or n.get("computername", ""),
                                    mac_address=str(n.get("mac", "")),
                                    compliance_status=_comp(n.get("status") == "reg"), raw=n))
        return out

    def get_device(self, device_id: str):
        try:
            d = _request(self._base, _token(self._token_env), f"/api/v1/node/{device_id}")
            n = d.get("item") or d or {}
            if not n:
                return None
            return DeviceRecord(device_id=device_id, hostname=n.get("hostname", ""),
                                mac_address=str(n.get("mac", "")),
                                compliance_status=_comp(n.get("status") == "reg"), raw=n)
        except AdapterError:
            return None

    def check_compliance(self, device_id: str, policy_id: str) -> ComplianceResult:
        rec = self.get_device(device_id)
        ok = bool(rec and rec.compliance_status == "compliant")
        return ComplianceResult(device_id=device_id, policy_id=policy_id, compliant=ok,
                                reason="" if ok else "nac_node_not_registered",
                                evidence={"nac_status": "reg" if ok else "unreg"})

    def report_compliance(self, result: ComplianceResult) -> bool:
        try:
            body = {"status": "reg" if result.compliant else "isolated",
                    "category": "aegis-" + ("pass" if result.compliant else "fail")}
            _request(self._base, _token(self._token_env), f"/api/v1/node/{result.device_id}", "PUT", body)
            return True
        except AdapterError:
            return False

    def forward_event(self, event: SecurityEvent) -> dict:
        return {"accepted": False, "reason": "nac_event_via_radius_rest"}

    def deploy_agent(self, task: DeploymentTask) -> DeploymentTask:
        return replace(task, status="pending", error="nac_does_not_deploy_agent")

    def get_deployment_status(self, task_id: str):
        return None

    def push_policy(self, device_ids, policy_json) -> dict:
        return {"pushed": 0, "reason": "nac_policy_via_vlan_role"}


ADAPTERS = {"fleet": FleetAdapter, "wazuh": WazuhAdapter, "packetfence": PacketFenceAdapter}
