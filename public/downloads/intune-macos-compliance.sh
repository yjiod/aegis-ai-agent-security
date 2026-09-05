#!/bin/bash
set -u
INSTALL_DIR="/Library/Application Support/SentinelAgent"
REPORT="$INSTALL_DIR/reports/latest.json"
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
AGENT_SHA="e8e87e570d71279e1128c390de17bbde757e653e99b988e46a171e08adc5b317"
POLICY_SHA="431a156f48208bcbc2c44dd92f8b2383be6a04df9294631f6386a9a6d48ac64d"
BASELINE_SHA="0c0b6ac7e4bee2859f0d0e70b80a3865fd5fb4c68cf531fe555188a1b9e6d19c"
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
