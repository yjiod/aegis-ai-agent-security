#!/usr/bin/env python3
"""Pure decision engine for Sentinel binary and signed-content delivery."""
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

SEMVER=re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
MAX_BYTES=262_144

def version(value):
    if not isinstance(value,str) or not SEMVER.fullmatch(value): raise ValueError("invalid_version")
    return tuple(int(part) for part in value.split("."))

def validate_policy(policy):
    if not isinstance(policy,dict) or set(policy)!={"schema","binary_delivery","content_delivery","rollout","rollback"} or policy.get("schema")!="sentinel.client-control/v1": raise ValueError("invalid_control_policy")
    binary=policy["binary_delivery"]; self_update=binary.get("self_update",{})
    if binary.get("mode") not in {"external_managed","controlled_self_update"}: raise ValueError("invalid_binary_delivery_mode")
    if not isinstance(binary.get("allowed_external_platforms"),list) or not binary["allowed_external_platforms"]: raise ValueError("invalid_external_platforms")
    required={"enabled","require_unmanaged_device","require_platform_signature","require_release_signature","require_dual_slot_rollback","require_maintenance_window","failure_circuit_breaker"}
    if set(self_update)!=required or any(type(self_update[name]) is not bool for name in required-{"failure_circuit_breaker"}) or type(self_update["failure_circuit_breaker"]) is not int or not 1<=self_update["failure_circuit_breaker"]<=10: raise ValueError("invalid_self_update_policy")
    content=policy["content_delivery"]
    if content!={"mode":"collector_pull","transport":"https","require_digest":True,"require_signature":True,"reject_downgrade":True,"keep_last_known_good":True,"channels":["policy","baseline","rules","skill_mcp_intelligence"]}: raise ValueError("unsafe_content_delivery")
    rollout=policy["rollout"]; rings=rollout.get("rings")
    if rings!=["lab","pilot","broad","production"] or set(rollout.get("minimum_observation_hours",{}))!=set(rings): raise ValueError("invalid_rollout")
    window=rollout.get("maintenance_window_utc",{})
    if type(window.get("start_hour")) is not int or not 0<=window["start_hour"]<=23 or type(window.get("duration_minutes")) is not int or not 15<=window["duration_minutes"]<=720: raise ValueError("invalid_maintenance_window")
    rollback=policy["rollback"]
    if rollback!={"binary_slots":["active","previous"],"separate_content_lkg":True,"health_timeout_seconds":300,"automatic_on_health_failure":True}: raise ValueError("unsafe_rollback_policy")
    return policy

def in_window(policy,now):
    window=policy["rollout"]["maintenance_window_utc"]; minute=now.hour*60+now.minute; start=window["start_hour"]*60; end=start+window["duration_minutes"]
    return start<=minute<end if end<=1440 else minute>=start or minute<end-1440

def plan(policy,device,offer,now=None):
    validate_policy(policy); now=now or datetime.now(timezone.utc)
    if not isinstance(device,dict) or not isinstance(offer,dict): raise ValueError("invalid_update_input")
    current=version(device.get("agent_version")); target=version(offer.get("agent_version"))
    if target<=current: return {"action":"none","reason":"current_or_downgrade","target":offer.get("agent_version")}
    binary=policy["binary_delivery"]; managed=device.get("management_platform") in binary["allowed_external_platforms"]
    if binary["mode"]=="external_managed": return {"action":"external_deployment_required","reason":"software_lifecycle_owner","target":offer["agent_version"]}
    controls=binary["self_update"]
    gates={
      "explicitly_enabled":controls["enabled"] is True,
      "unmanaged_device":not managed if controls["require_unmanaged_device"] else True,
      "platform_signature":offer.get("platform_signature_verified") is True if controls["require_platform_signature"] else True,
      "release_signature":offer.get("release_signature_verified") is True if controls["require_release_signature"] else True,
      "dual_slot":device.get("dual_slot_ready") is True if controls["require_dual_slot_rollback"] else True,
      "maintenance_window":in_window(policy,now) if controls["require_maintenance_window"] else True,
      "circuit_breaker":int(device.get("consecutive_update_failures",99))<controls["failure_circuit_breaker"],
      "ring_authorized":device.get("rollout_ring") in offer.get("authorized_rings",[]),
    }
    failed=[name for name,passed in gates.items() if not passed]
    return {"action":"self_update_ready" if not failed else "wait","reason":"all_gates_passed" if not failed else "gates_failed","target":offer["agent_version"],"failed_gates":failed}

def content_plan(policy,current,offer):
    validate_policy(policy); current_version=version(current.get("version")); target=version(offer.get("version"))
    gates={"digest":offer.get("digest_verified") is True,"signature":offer.get("signature_verified") is True,"schema":offer.get("schema_verified") is True,"regression":offer.get("regression_passed") is True}
    if target<=current_version: return {"action":"keep_lkg","reason":"current_or_downgrade"}
    failed=[name for name,value in gates.items() if not value]
    return {"action":"apply_content_atomically" if not failed else "keep_lkg","reason":"all_gates_passed" if not failed else "verification_failed","failed_gates":failed}

def read_json(path):
    raw=Path(path).read_bytes()
    if len(raw)>MAX_BYTES: raise ValueError("oversized_input")
    return json.loads(raw.decode("utf-8"))

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--policy",required=True); parser.add_argument("--device",required=True); parser.add_argument("--offer",required=True); parser.add_argument("--kind",choices=("binary","content"),default="binary"); args=parser.parse_args()
    try:
        policy=read_json(args.policy); device=read_json(args.device); offer=read_json(args.offer); result=plan(policy,device,offer) if args.kind=="binary" else content_plan(policy,device,offer)
    except (OSError,UnicodeError,ValueError,TypeError,json.JSONDecodeError) as exc: result={"action":"deny","reason":"invalid_input","error":type(exc).__name__}
    print(json.dumps(result,ensure_ascii=False,separators=(",",":"))); return 0 if result["action"] in {"none","external_deployment_required","self_update_ready","apply_content_atomically","keep_lkg","wait"} else 1

if __name__=="__main__": sys.exit(main())
