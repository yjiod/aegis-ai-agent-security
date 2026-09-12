#!/bin/sh
set -eu
BASE="/Library/Application Support/AegisAgent"
PYTHON=""
for candidate in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
  if [ -x "$candidate" ]; then PYTHON="$candidate"; break; fi
done
if [ -z "$PYTHON" ]; then
  logger -t aegis-agent "Python 3 is required; scan skipped"
  exit 1
fi
install -d -m 0700 -o root -g wheel "$BASE/reports" "$BASE/spool"
"$PYTHON" "$BASE/aegis_agent.py" /Users \
  --policy "$BASE/aegis-policy.json" \
  --output "$BASE/reports/latest.json" \
  --report-config "$BASE/reporting.json" \
  --spool-dir "$BASE/spool" \
  --auto-enroll
