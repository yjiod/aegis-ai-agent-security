#!/usr/bin/env python3
"""
Aegis 4A Enterprise Interface — Vendor-Neutral Abstraction Layer.

4A = Authentication, Authorization, Accounting, Audit.
This module defines the standard enterprise integration contract WITHOUT
binding to any specific vendor (Intune, Sangfor, Leagsoft, etc.).

Deployments implement one or more adapters behind this interface.
The Aegis console and adapter worker only depend on THIS contract.

Usage:
    from aegis_4a_interface import FourAInterface, FourACapability

    class MyMDMAdapter(FourAInterface):
        def capabilities(self): return {FourACapability.DEVICE_MANAGEMENT, ...}
        def deploy_agent(self, device_id, package_url): ...
        ...
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# ─── Capability Enumeration ────────────────────────────────────────────────

class FourACapability(enum.Enum):
    """Standard 4A capabilities any enterprise platform may provide."""

    # Authentication (认证)
    DEVICE_IDENTITY = "device_identity"           # 设备身份认证
    USER_IDENTITY = "user_identity"               # 用户身份认证
    CERTIFICATE_MANAGEMENT = "certificate_mgmt"   # 证书生命周期

    # Authorization (授权)
    POLICY_DISTRIBUTION = "policy_distribution"   # 策略下发
    ACCESS_CONTROL = "access_control"             # 访问控制
    ROLE_MANAGEMENT = "role_management"           # 角色管理

    # Accounting (计费/资产)
    ASSET_INVENTORY = "asset_inventory"           # 资产台账
    LICENSE_MANAGEMENT = "license_management"     # 许可证管理
    USAGE_TRACKING = "usage_tracking"             # 使用量追踪

    # Audit (审计)
    COMPLIANCE_CHECK = "compliance_check"         # 合规检查
    EVENT_FORWARDING = "event_forwarding"         # 事件转发
    INCIDENT_RESPONSE = "incident_response"       # 事件响应
    LOG_COLLECTION = "log_collection"             # 日志采集

    # Deployment (部署 — 扩展能力)
    AGENT_DEPLOYMENT = "agent_deployment"         # Agent 部署
    AGENT_UPGRADE = "agent_upgrade"               # Agent 升级
    AGENT_ROLLBACK = "agent_rollback"             # Agent 回滚
    SOFTWARE_DISTRIBUTION = "software_dist"       # 软件分发


# ─── Data Contracts ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DeviceRecord:
    """Standard device record exchanged between Aegis and 4A platforms."""
    device_id: str
    hostname: str = ""
    os_type: str = ""          # "windows" | "macos" | "linux"
    os_version: str = ""
    owner: str = ""
    department: str = ""
    ip_address: str = ""
    mac_address: str = ""
    serial_number: str = ""
    compliance_status: str = "unknown"  # "compliant" | "non_compliant" | "unknown"
    last_checkin: int = 0
    tags: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ComplianceResult:
    """Standard compliance check result."""
    device_id: str
    policy_id: str
    compliant: bool
    risk_level: str = "normal"   # "critical" | "high" | "medium" | "low" | "normal"
    reason: str = ""
    checked_at: int = field(default_factory=lambda: int(time.time()))
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DeploymentTask:
    """Standard agent deployment task."""
    task_id: str
    device_id: str
    action: str              # "install" | "upgrade" | "rollback" | "uninstall"
    package_url: str = ""
    package_sha256: str = ""
    target_version: str = ""
    status: str = "pending"  # "pending" | "in_progress" | "success" | "failed" | "cancelled"
    created_at: int = field(default_factory=lambda: int(time.time()))
    completed_at: int | None = None
    error: str = ""


@dataclass(frozen=True)
class SecurityEvent:
    """Standard security event forwarded to 4A platforms."""
    event_id: str
    event_type: str          # "ai_agent_security_finding" | "compliance_violation" | "policy_change"
    severity: str            # "critical" | "high" | "medium" | "low" | "info"
    device_id: str
    source: str = "aegis"
    occurred_at: int = field(default_factory=lambda: int(time.time()))
    recommended_action: str = "observe"  # "observe" | "alert" | "isolate_pending" | "block_pending"
    finding_count: int = 0
    policy_version: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


# ─── Interface Protocol ─────────────────────────────────────────────────────

@runtime_checkable
class FourAInterface(Protocol):
    """
    Vendor-neutral 4A integration interface.

    Any enterprise platform adapter (Intune, Sangfor EDR, Leagsoft,
    CrowdStrike, Jamf, SCCM, or custom) implements this protocol.
    Aegis core never imports vendor-specific modules directly.
    """

    @property
    def vendor_name(self) -> str:
        """Human-readable vendor/platform name."""
        ...

    @property
    def vendor_version(self) -> str:
        """Detected or configured vendor platform version."""
        ...

    def capabilities(self) -> set[FourACapability]:
        """Declare which 4A capabilities this adapter provides."""
        ...

    def health_check(self) -> dict[str, Any]:
        """
        Non-destructive connectivity and auth check.
        Returns: {"ok": bool, "latency_ms": int, "error": str | None, "version": str}
        """
        ...

    # ── Device Management ──

    def list_devices(self, query: str = "", limit: int = 100, offset: int = 0) -> list[DeviceRecord]:
        """Query device inventory from the 4A platform."""
        ...

    def get_device(self, device_id: str) -> DeviceRecord | None:
        """Get single device record."""
        ...

    # ── Compliance ──

    def check_compliance(self, device_id: str, policy_id: str) -> ComplianceResult:
        """Run compliance check for a device against a policy."""
        ...

    def report_compliance(self, result: ComplianceResult) -> bool:
        """Push compliance result to the 4A platform. Returns accepted."""
        ...

    # ── Event Forwarding ──

    def forward_event(self, event: SecurityEvent) -> dict[str, Any]:
        """
        Forward a security event to the 4A platform.
        Returns: {"accepted": bool, "event_id": str, "action_taken": str}
        """
        ...

    # ── Deployment ──

    def deploy_agent(self, task: DeploymentTask) -> DeploymentTask:
        """Submit an agent deployment task. Returns updated task with status."""
        ...

    def get_deployment_status(self, task_id: str) -> DeploymentTask | None:
        """Poll deployment task status."""
        ...

    # ── Policy Distribution ──

    def push_policy(self, device_ids: list[str], policy_json: str) -> dict[str, Any]:
        """
        Distribute security policy to devices.
        Returns: {"accepted": int, "rejected": int, "task_id": str}
        """
        ...


# ─── Null Adapter (default when no vendor configured) ───────────────────────

class NullFourAAdapter:
    """
    No-op adapter used when no enterprise 4A platform is configured.
    All operations return safe defaults. Never raises.
    """

    vendor_name = "null"
    vendor_version = "0.0.0"

    def capabilities(self) -> set[FourACapability]:
        return set()

    def health_check(self) -> dict[str, Any]:
        return {"ok": False, "latency_ms": 0, "error": "no_vendor_configured", "version": ""}

    def list_devices(self, query="", limit=100, offset=0) -> list[DeviceRecord]:
        return []

    def get_device(self, device_id: str) -> DeviceRecord | None:
        return None

    def check_compliance(self, device_id: str, policy_id: str) -> ComplianceResult:
        return ComplianceResult(device_id=device_id, policy_id=policy_id, compliant=True, reason="no_vendor")

    def report_compliance(self, result: ComplianceResult) -> bool:
        return False

    def forward_event(self, event: SecurityEvent) -> dict[str, Any]:
        return {"accepted": False, "event_id": "", "action_taken": "none"}

    def deploy_agent(self, task: DeploymentTask) -> DeploymentTask:
        return DeploymentTask(**{**task.__dict__, "status": "failed", "error": "no_vendor_configured"})

    def get_deployment_status(self, task_id: str) -> DeploymentTask | None:
        return None

    def push_policy(self, device_ids: list[str], policy_json: str) -> dict[str, Any]:
        return {"accepted": 0, "rejected": len(device_ids), "task_id": ""}


# ─── Adapter Registry ───────────────────────────────────────────────────────

_REGISTRY: dict[str, FourAInterface] = {}


def register_adapter(name: str, adapter: FourAInterface) -> None:
    """Register a 4A adapter instance by name."""
    if not isinstance(adapter, FourAInterface):
        raise TypeError(f"adapter '{name}' does not implement FourAInterface")
    _REGISTRY[name] = adapter


def get_adapter(name: str) -> FourAInterface:
    """Get registered adapter by name, or NullFourAAdapter if not found."""
    return _REGISTRY.get(name, NullFourAAdapter())


def list_adapters() -> dict[str, set[FourACapability]]:
    """List all registered adapters and their capabilities."""
    return {name: adapter.capabilities() for name, adapter in _REGISTRY.items()}


def find_by_capability(cap: FourACapability) -> list[FourAInterface]:
    """Find all adapters that provide a specific capability."""
    return [a for a in _REGISTRY.values() if cap in a.capabilities()]
