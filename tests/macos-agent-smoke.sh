#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/public/downloads"
SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/sentinel-macos-smoke.XXXXXX")
trap 'find "$SANDBOX" -depth -delete 2>/dev/null || true' EXIT HUP INT TERM
INSTALL="$SANDBOX/install"
PROJECT="$SANDBOX/project"
REPORT="$SANDBOX/report.json"
TEST_HOME="$SANDBOX/home"
mkdir -p "$PROJECT" "$TEST_HOME"

SENTINEL_BASE_URL="file://$SOURCE" SENTINEL_INSTALL_DIR="$INSTALL" /bin/sh "$SOURCE/install-sentinel.sh"
HOME="$TEST_HOME" python3 "$INSTALL/sentinel_agent.py" "$PROJECT" --policy "$INSTALL/sentinel-policy.json" --output "$REPORT" >/dev/null
python3 -c 'import json,os,stat,sys; p=sys.argv[1]; r=json.load(open(p)); assert r["schema"]=="sentinel.report/v1" and r["agent_version"]=="0.34.0" and r["policy_version"]=="4.9.0"; assert r["summary"]["critical"]==0 and r["summary"]["high"]==0; assert stat.S_IMODE(os.stat(p).st_mode)==0o600' "$REPORT"

SECRET='sk-abcdefghijklmnopqrstuvwxyz123456'
printf '%s\n' "token=\"$SECRET\"" > "$PROJECT/app.py"
set +e
HOME="$TEST_HOME" python3 "$INSTALL/sentinel_agent.py" "$PROJECT" --policy "$INSTALL/sentinel-policy.json" --output "$REPORT" >/dev/null
CODE=$?
set -e
[ "$CODE" -eq 2 ]
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); secret=sys.argv[2]; matches=[f for f in r["findings"] if f["kind"]=="hardcoded_secret"]; assert r["summary"]["critical"]==1 and len(matches)==1; assert secret not in matches[0].get("evidence","") and secret not in open(sys.argv[1]).read()' "$REPORT" "$SECRET"
