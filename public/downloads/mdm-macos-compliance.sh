#!/bin/bash
set -u
INSTALL_DIR="/Library/Application Support/AegisAgent"
REPORT="$INSTALL_DIR/reports/latest.json"
REPORTING="$INSTALL_DIR/reporting.json"
UPLOAD_STATUS="$INSTALL_DIR/reports/upload-status.json"
PLIST="/Library/LaunchDaemons/com.company.aegis-agent.plist"
AGENT_SHA="8df281794182ebae26624ab84fbcf52de7c510a6d078546c9b77fadb03d72b11"
POLICY_SHA="a8935b03ae59c08002a428d524b46ee69bde6042a5173c510d184f62d6737740"
BASELINE_SHA="5dafeaafdea7f04427148c905ad9697d4a4711820d6f80436c78b18a50835806"
installed=false; integrity=false; runtime=false
if [[ -f "$INSTALL_DIR/aegis_agent.py" && -f "$INSTALL_DIR/aegis-policy.json" && -f "$INSTALL_DIR/aegis-security-baseline.md" ]]; then installed=true; fi
if [[ "$installed" == true ]] && \
  [[ "$(/usr/bin/shasum -a 256 "$INSTALL_DIR/aegis_agent.py" | /usr/bin/awk '{print $1}')" == "$AGENT_SHA" ]] && \
  [[ "$(/usr/bin/shasum -a 256 "$INSTALL_DIR/aegis-policy.json" | /usr/bin/awk '{print $1}')" == "$POLICY_SHA" ]] && \
  [[ "$(/usr/bin/shasum -a 256 "$INSTALL_DIR/aegis-security-baseline.md" | /usr/bin/awk '{print $1}')" == "$BASELINE_SHA" ]]; then integrity=true; fi
if [[ -f "$PLIST" ]] && /bin/launchctl print system/com.company.aegis-agent >/dev/null 2>&1; then runtime=true; fi
python_bin="$(command -v python3 2>/dev/null || true)"
if [[ -z "$python_bin" ]]; then
  /usr/bin/printf '%s\n' "{\"AegisInstalled\":$installed,\"AegisIntegrityValid\":$integrity,\"AegisLaunchDaemonHealthy\":$runtime,\"AegisReportingConfigured\":false,\"AegisReportingHealthy\":false,\"AegisPolicyVersion\":\"missing\",\"AegisReportValid\":false,\"AegisScanRecent\":false,\"AegisCriticalFindings\":0,\"AegisHighFindings\":0}"
  exit 0
fi
"$python_bin" - "$INSTALL_DIR/aegis-policy.json" "$REPORT" "$REPORTING" "$UPLOAD_STATUS" "$installed" "$integrity" "$runtime" <<'PY'
import hmac, json, pathlib, stat, sys, time
from urllib.parse import urlsplit
policy_path,report_path,reporting_path,upload_status_path=map(pathlib.Path,sys.argv[1:5])
installed,integrity,runtime=(value=="true" for value in sys.argv[5:8])
policy="missing"; recent=False; report_valid=False; reporting_configured=False; reporting_healthy=False; configured_host=""; critical=0; high=0
try:
    info=reporting_path.stat(); value=json.loads(reporting_path.read_text()); parsed=urlsplit(value.get("report_url","")); token=value.get("report_token",""); secret=value.get("signing_secret","")
    reporting_configured=not reporting_path.is_symlink() and stat.S_ISREG(info.st_mode) and not info.st_mode&0o077 and info.st_uid==0 and set(value)=={"schema","report_url","report_token","signing_secret"} and value.get("schema")=="aegis.reporting/v1" and parsed.scheme=="https" and bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and 32<=len(token)<=4096 and 32<=len(secret)<=4096 and not hmac.compare_digest(token,secret)
    if reporting_configured: configured_host=parsed.hostname.lower().rstrip(".")
except (OSError,ValueError,TypeError): pass
try:
    status=json.loads(upload_status_path.read_text()); age=int(time.time())-status.get("last_success",0)
    reporting_healthy=reporting_configured and set(status)=={"schema","status","last_success","collector_host"} and status.get("schema")=="aegis.upload-status/v1" and status.get("status")=="accepted" and status.get("collector_host")==configured_host and type(status.get("last_success")) is int and 0<=age<86400
except (OSError,ValueError,TypeError): pass
try:
    value=json.loads(policy_path.read_text()); policy=str(value.get("version","missing"))
except (OSError,ValueError,TypeError): pass
try:
    report=json.loads(report_path.read_text()); scanned=int(report.get("scanned_at",0)); age=int(time.time())-scanned
    findings=report.get("findings",[]); summary=report.get("summary",{}); severities=("critical","high","medium","low")
    actual={severity:sum(isinstance(item,dict) and item.get("severity")==severity for item in findings) for severity in severities} if isinstance(findings,list) else {}
    valid_findings=isinstance(findings,list) and len(findings)<=10000 and all(isinstance(item,dict) and item.get("severity") in severities and all(isinstance(item.get(key),str) for key in ("kind","path","message")) for item in findings)
    report_valid=report.get("schema")=="aegis.report/v1" and report.get("agent_version")=="0.30.0" and report.get("policy_version")==policy and isinstance(report.get("device_id"),str) and len(report["device_id"])==12 and all(char in "0123456789abcdef" for char in report["device_id"]) and type(report.get("scanned_at")) is int and valid_findings and isinstance(summary,dict) and all(type(summary.get(severity)) is int and summary[severity]==actual.get(severity) for severity in severities)
    if report_valid: recent=0<=age<86400; critical=actual["critical"]; high=actual["high"]
except (OSError,ValueError,TypeError): pass
print(json.dumps({"AegisInstalled":installed,"AegisIntegrityValid":integrity,"AegisLaunchDaemonHealthy":runtime,"AegisReportingConfigured":reporting_configured,"AegisReportingHealthy":reporting_healthy,"AegisPolicyVersion":policy,"AegisReportValid":report_valid,"AegisScanRecent":recent,"AegisCriticalFindings":critical,"AegisHighFindings":high},separators=(",",":")))
PY
