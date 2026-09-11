#!/usr/bin/env python3
"""Normalize privacy-minimized Microsoft Graph Intune snapshots for Aegis evidence."""
import argparse, json, re, sys
from pathlib import Path
import aegis_intune_preflight as preflight

MAX_GRAPH_EXPORT_BYTES=2_000_000
GRAPH_ID=re.compile(r"[A-Za-z0-9._-]{8,128}")
AEGIS_ID=re.compile(r"[A-Za-z0-9._-]{8,128}")
COMPLIANCE_STATES={"unknown","compliant","noncompliant","conflict","error","inGracePeriod","configManager"}
INSTALL_STATES={"notApplicable","installed","failed","notInstalled","uninstallFailed","unknown","pendingInstall"}
FAILURE_STATES={"failed","uninstallFailed"}

def identifier(value,pattern=GRAPH_ID):
    if not isinstance(value,str) or not pattern.fullmatch(value): raise ValueError("invalid_device_identifier")
    return value

def normalize(snapshot):
    expected={"schema","generated_at","current_ring","managed_devices","assigned_device_ids","install_states","bindings"}
    if not isinstance(snapshot,dict) or set(snapshot)!=expected or snapshot.get("schema")!="aegis.intune-graph-export/v1": raise ValueError("invalid_graph_export")
    generated=snapshot.get("generated_at")
    if isinstance(generated,bool) or not isinstance(generated,int) or generated<1: raise ValueError("invalid_graph_export_time")
    if snapshot.get("current_ring") not in preflight.RINGS: raise ValueError("invalid_graph_ring")
    managed=snapshot.get("managed_devices"); assigned_raw=snapshot.get("assigned_device_ids"); states=snapshot.get("install_states"); bindings=snapshot.get("bindings")
    if any(not isinstance(items,list) or len(items)>10000 for items in (managed,assigned_raw,states,bindings)): raise ValueError("invalid_graph_collection")
    compliance={}
    for item in managed:
        if not isinstance(item,dict) or set(item)!={"id","complianceState"}: raise ValueError("invalid_managed_device")
        graph_id=identifier(item.get("id")); state=item.get("complianceState")
        if graph_id in compliance or state not in COMPLIANCE_STATES: raise ValueError("invalid_managed_device")
        compliance[graph_id]=state
    assigned=[identifier(value) for value in assigned_raw]
    if len(set(assigned))!=len(assigned) or not set(assigned).issubset(compliance): raise ValueError("invalid_assignment_set")
    install={}
    for item in states:
        if not isinstance(item,dict) or set(item)!={"deviceId","installState"}: raise ValueError("invalid_install_state")
        graph_id=identifier(item.get("deviceId")); state=item.get("installState")
        if graph_id in install or graph_id not in compliance or state not in INSTALL_STATES: raise ValueError("invalid_install_state")
        install[graph_id]=state
    mapping={}; aegis_ids=set()
    for item in bindings:
        if not isinstance(item,dict) or set(item)!={"intune_device_id","aegis_device_id"}: raise ValueError("invalid_device_binding")
        graph_id=identifier(item.get("intune_device_id")); aegis_id=identifier(item.get("aegis_device_id"),AEGIS_ID)
        if graph_id in mapping or aegis_id in aegis_ids: raise ValueError("invalid_device_binding")
        mapping[graph_id]=aegis_id; aegis_ids.add(aegis_id)
    if set(mapping)!=set(assigned) or not set(assigned).issubset(install): raise ValueError("incomplete_assigned_device_evidence")
    assigned_aegis=[mapping[value] for value in assigned]
    return {"schema":"aegis.intune-export/v2","generated_at":generated,"current_ring":snapshot["current_ring"],"fleet_total_devices":len(compliance),"assigned_device_ids":assigned_aegis,"compliant_device_ids":[mapping[value] for value in assigned if compliance[value]=="compliant"],"installation_failed_device_ids":[mapping[value] for value in assigned if install[value] in FAILURE_STATES]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--graph-export",required=True); args=ap.parse_args()
    try:
        snapshot=preflight.read_json_bounded(args.graph_export,MAX_GRAPH_EXPORT_BYTES)
        print(json.dumps(normalize(snapshot),separators=(",",":"),sort_keys=True)); return 0
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
