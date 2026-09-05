#!/bin/bash
set -u
INSTALL_DIR="/Library/Application Support/SentinelAgent"
REPORT="$INSTALL_DIR/reports/latest.json"
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
AGENT_SHA="301e6da7af010b4c84c8b4f1a1cd38f29d931f31dbfe67450237aa5f656d1516"
POLICY_SHA="8f6183f1796b8f70064e1023c801843158a03da5b12c30c92f420972c8b34317"
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
  /usr/bin/printf '%s\n' "{\"SentinelInstalled\":$installed,\"SentinelIntegrityValid\":$integrity,\"SentinelLaunchDaemonHealthy\":$runtime,\"SentinelPolicyVersion\":\"missing\",\"SentinelScanRecent\":false,\"SentinelCriticalFindings\":0,\"SentinelHighFindings\":0}"
  exit 0
fi
"$python_bin" - "$INSTALL_DIR/sentinel-policy.json" "$REPORT" "$installed" "$integrity" "$runtime" <<'PY'
import json, pathlib, sys, time
policy_path,report_path=map(pathlib.Path,sys.argv[1:3])
installed,integrity,runtime=(value=="true" for value in sys.argv[3:6])
policy="missing"; recent=False; critical=0; high=0
try:
    value=json.loads(policy_path.read_text()); policy=str(value.get("version","missing"))
except (OSError,ValueError,TypeError): pass
try:
    report=json.loads(report_path.read_text()); scanned=int(report.get("scanned_at",0)); age=int(time.time())-scanned
    if report.get("schema")=="sentinel.report/v1":
        recent=0<=age<86400; summary=report.get("summary",{}); critical=max(int(summary.get("critical",0)),0); high=max(int(summary.get("high",0)),0)
except (OSError,ValueError,TypeError): pass
print(json.dumps({"SentinelInstalled":installed,"SentinelIntegrityValid":integrity,"SentinelLaunchDaemonHealthy":runtime,"SentinelPolicyVersion":policy,"SentinelScanRecent":recent,"SentinelCriticalFindings":critical,"SentinelHighFindings":high},separators=(",",":")))
PY
