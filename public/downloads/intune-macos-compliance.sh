#!/bin/bash
set -u
INSTALL_DIR="/Library/Application Support/SentinelAgent"
REPORT="$INSTALL_DIR/reports/latest.json"
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
AGENT_SHA="ffbc1f1a10a4a39a9e9e1b857b76de2aabf22006059cddbef9773b18099dbc39"
POLICY_SHA="0f87d2ecdc801505d825c647ef8eced290bc9ba9e0bd17b4abe9b6a7a4d14423"
BASELINE_SHA="e6d87dba8756aa270a70f423368bf68a44f108a5a299ab2a62c4488ed74a962e"
installed=false; integrity=false; runtime=false
if [[ -f "$INSTALL_DIR/sentinel_agent.py" && -f "$INSTALL_DIR/sentinel-policy.json" && -f "$INSTALL_DIR/sentinel-security-baseline.md" ]]; then installed=true; fi
if [[ "$installed" == true ]] && \
  [[ "$(/usr/bin/shasum -a 256 "$INSTALL_DIR/sentinel_agent.py" | /usr/bin/awk '{print $1}')" == "$AGENT_SHA" ]] && \
  [[ "$(/usr/bin/shasum -a 256 "$INSTALL_DIR/sentinel-policy.json" | /usr/bin/awk '{print $1}')" == "$POLICY_SHA" ]] && \
  [[ "$(/usr/bin/shasum -a 256 "$INSTALL_DIR/sentinel-security-baseline.md" | /usr/bin/awk '{print $1}')" == "$BASELINE_SHA" ]]; then integrity=true; fi
if [[ -f "$PLIST" ]] && /bin/launchctl print system/com.company.sentinel-agent >/dev/null 2>&1; then runtime=true; fi
python_bin="$(command -v python3 2>/dev/null || true)"
if [[ -z "$python_bin" ]]; then
  /usr/bin/printf '%s\n' "{\"SentinelInstalled\":$installed,\"SentinelIntegrityValid\":$integrity,\"SentinelLaunchDaemonHealthy\":$runtime,\"SentinelPolicyVersion\":\"missing\",\"SentinelReportValid\":false,\"SentinelScanRecent\":false,\"SentinelCriticalFindings\":0,\"SentinelHighFindings\":0}"
  exit 0
fi
"$python_bin" - "$INSTALL_DIR/sentinel-policy.json" "$REPORT" "$installed" "$integrity" "$runtime" <<'PY'
import json, pathlib, sys, time
policy_path,report_path=map(pathlib.Path,sys.argv[1:3])
installed,integrity,runtime=(value=="true" for value in sys.argv[3:6])
policy="missing"; recent=False; report_valid=False; critical=0; high=0
try:
    value=json.loads(policy_path.read_text()); policy=str(value.get("version","missing"))
except (OSError,ValueError,TypeError): pass
try:
    report=json.loads(report_path.read_text()); scanned=int(report.get("scanned_at",0)); age=int(time.time())-scanned
    findings=report.get("findings",[]); summary=report.get("summary",{}); severities=("critical","high","medium","low")
    actual={severity:sum(isinstance(item,dict) and item.get("severity")==severity for item in findings) for severity in severities} if isinstance(findings,list) else {}
    valid_findings=isinstance(findings,list) and len(findings)<=10000 and all(isinstance(item,dict) and item.get("severity") in severities and all(isinstance(item.get(key),str) for key in ("kind","path","message")) for item in findings)
    report_valid=report.get("schema")=="sentinel.report/v1" and report.get("agent_version")=="0.25.0" and report.get("policy_version")==policy and isinstance(report.get("device_id"),str) and len(report["device_id"])==12 and all(char in "0123456789abcdef" for char in report["device_id"]) and type(report.get("scanned_at")) is int and valid_findings and isinstance(summary,dict) and all(type(summary.get(severity)) is int and summary[severity]==actual.get(severity) for severity in severities)
    if report_valid: recent=0<=age<86400; critical=actual["critical"]; high=actual["high"]
except (OSError,ValueError,TypeError): pass
print(json.dumps({"SentinelInstalled":installed,"SentinelIntegrityValid":integrity,"SentinelLaunchDaemonHealthy":runtime,"SentinelPolicyVersion":policy,"SentinelReportValid":report_valid,"SentinelScanRecent":recent,"SentinelCriticalFindings":critical,"SentinelHighFindings":high},separators=(",",":")))
PY
