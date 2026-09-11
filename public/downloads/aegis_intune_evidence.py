#!/usr/bin/env python3
"""Generate privacy-minimized Intune v3 promotion evidence from exported snapshots."""
import argparse, hashlib, json, re, sys, time
from pathlib import Path
import aegis_intune_preflight as preflight

MAX_SNAPSHOT_BYTES=2_000_000
DEVICE_ID=re.compile(r"[A-Za-z0-9._-]{8,128}")

def ids(value,limit=10000):
    if not isinstance(value,list) or len(value)>limit or any(not isinstance(item,str) or not DEVICE_ID.fullmatch(item) for item in value) or len(set(value))!=len(value): raise ValueError("invalid_device_id_set")
    return set(value)

def build(downloads,base,intune,collector,now=None):
    now=int(time.time() if now is None else now)
    v1={"schema","generated_at","current_ring","fleet_device_ids","assigned_device_ids","compliant_device_ids","installation_failed_device_ids"}; v2={"schema","generated_at","current_ring","fleet_total_devices","assigned_device_ids","compliant_device_ids","installation_failed_device_ids"}
    if not isinstance(intune,dict) or not ((intune.get("schema")=="aegis.intune-export/v1" and set(intune)==v1) or (intune.get("schema")=="aegis.intune-export/v2" and set(intune)==v2)): raise ValueError("invalid_intune_export")
    if not isinstance(collector,dict) or set(collector)!={"generated_at","complete","devices"} or collector.get("complete") is not True or not isinstance(collector.get("devices"),list) or len(collector["devices"])>10000: raise ValueError("invalid_collector_export")
    for stamp in (intune.get("generated_at"),collector.get("generated_at")):
        if isinstance(stamp,bool) or not isinstance(stamp,int) or stamp>now+60 or now-stamp>900: raise ValueError("snapshot_not_current")
    assigned=ids(intune["assigned_device_ids"]); compliant=ids(intune["compliant_device_ids"]); failed=ids(intune["installation_failed_device_ids"])
    if intune["schema"]=="aegis.intune-export/v1":
        fleet=ids(intune["fleet_device_ids"]); fleet_total=len(fleet)
        if not assigned.issubset(fleet): raise ValueError("invalid_intune_device_relationship")
    else:
        fleet_total=intune.get("fleet_total_devices")
        if isinstance(fleet_total,bool) or not isinstance(fleet_total,int) or fleet_total<1 or len(assigned)>fleet_total: raise ValueError("invalid_intune_device_relationship")
    if not compliant.issubset(assigned) or not failed.issubset(assigned) or compliant&failed: raise ValueError("invalid_intune_device_relationship")
    reporting=set(); collector_ids=set()
    for item in collector["devices"]:
        if not isinstance(item,dict) or set(item)!={"device_id","last_seen","report_count","credential_generation"}: raise ValueError("invalid_collector_device")
        device_id=item.get("device_id"); last_seen=item.get("last_seen"); report_count=item.get("report_count")
        if not isinstance(device_id,str) or not DEVICE_ID.fullmatch(device_id) or device_id in collector_ids or isinstance(last_seen,bool) or not isinstance(last_seen,int) or last_seen>now+60 or isinstance(report_count,bool) or not isinstance(report_count,int) or report_count<1 or item.get("credential_generation") not in {"legacy","current","previous"}: raise ValueError("invalid_collector_device")
        collector_ids.add(device_id)
        if device_id in assigned and now-last_seen<=86400: reporting.add(device_id)
    downloads=Path(downloads); release=preflight.read_json_bounded(downloads/"release.json",preflight.MAX_INTUNE_RELEASE_BYTES); manifest=preflight.read_bytes_bounded(downloads/"intune-deployment-manifest.json",preflight.MAX_INTUNE_MANIFEST_BYTES)
    if not isinstance(base,dict) or set(base)!=preflight.EVIDENCE_FIELDS: raise ValueError("invalid_evidence_base")
    result=dict(base); result.update(schema="aegis.intune-evidence/v3",release_version=release["release"],manifest_sha256=hashlib.sha256(manifest).hexdigest(),generated_at=now,current_ring=intune["current_ring"],fleet_total_devices=fleet_total,ring_assigned_devices=len(assigned),reporting_devices=len(reporting),compliant_devices=len(compliant),installation_failures=len(failed))
    return result

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--downloads",default=str(Path(__file__).parent)); ap.add_argument("--base-evidence",required=True); ap.add_argument("--intune-export",required=True); ap.add_argument("--collector-devices",required=True); args=ap.parse_args()
    try:
        base=preflight.read_json_bounded(args.base_evidence,preflight.MAX_INTUNE_EVIDENCE_BYTES); intune=preflight.read_json_bounded(args.intune_export,MAX_SNAPSHOT_BYTES); collector=preflight.read_json_bounded(args.collector_devices,MAX_SNAPSHOT_BYTES)
        print(json.dumps(build(args.downloads,base,intune,collector),separators=(",",":"),sort_keys=True)); return 0
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,json.JSONDecodeError) as exc:
        print(json.dumps({"ok":False,"error":type(exc).__name__},separators=(",",":")),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
