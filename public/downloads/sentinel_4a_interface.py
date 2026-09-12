#!/usr/bin/env python3
"""Vendor-neutral capability contract for identity, 4A, NAC, EDR and device platforms."""
from __future__ import annotations
import enum, re
from typing import Any, NamedTuple, Protocol, runtime_checkable

class Capability(str,enum.Enum):
    IDENTITY_AUTHENTICATION="identity.authentication"
    IDENTITY_RESOLUTION="identity.resolution"
    AUTHORIZATION_DECISION="authorization.decision"
    ACCESS_REVIEW="authorization.access_review"
    AUDIT_ACCOUNTING="audit.accounting"
    DEVICE_POSTURE="device.posture"
    POLICY_DISTRIBUTION="device.policy_distribution"
    SOFTWARE_DISTRIBUTION="device.software_distribution"
    INCIDENT_NOTIFICATION="security.incident_notification"
    CONTAINMENT_REQUEST="security.containment_request"

CORE_EVENT_CAPABILITIES=frozenset({Capability.DEVICE_POSTURE,Capability.AUDIT_ACCOUNTING})
PRIVILEGED_CAPABILITIES=frozenset({Capability.AUTHORIZATION_DECISION,Capability.ACCESS_REVIEW,Capability.CONTAINMENT_REQUEST})

class ProviderDescriptor(NamedTuple):
    provider_id: str
    capabilities: frozenset[Capability]
    protocol_version: str="sentinel.integration/v1"
    approval_enforced: bool=True

def validate_descriptor(value:ProviderDescriptor)->ProviderDescriptor:
    if not isinstance(value,ProviderDescriptor) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,63}",value.provider_id): raise ValueError("invalid_provider_id")
    if value.protocol_version!="sentinel.integration/v1" or not isinstance(value.capabilities,frozenset) or not value.capabilities or any(not isinstance(item,Capability) for item in value.capabilities): raise ValueError("invalid_provider_contract")
    if value.capabilities&PRIVILEGED_CAPABILITIES and value.approval_enforced is not True: raise ValueError("privileged_capability_requires_approval")
    return value

@runtime_checkable
class EnterpriseIntegration(Protocol):
    """Adapters implement only declared capabilities; Sentinel core never imports vendor SDKs."""
    def descriptor(self)->ProviderDescriptor: ...
    def health(self)->dict[str,Any]: ...
    def publish_posture(self,event:dict[str,Any])->str: ...

def supports(provider:EnterpriseIntegration,required:set[Capability]|frozenset[Capability])->bool:
    descriptor=validate_descriptor(provider.descriptor())
    return set(required).issubset(descriptor.capabilities)

def require_capabilities(provider:EnterpriseIntegration,required:set[Capability]|frozenset[Capability])->ProviderDescriptor:
    descriptor=validate_descriptor(provider.descriptor()); missing=set(required)-set(descriptor.capabilities)
    if missing: raise ValueError("missing_capabilities:"+",".join(sorted(item.value for item in missing)))
    return descriptor
