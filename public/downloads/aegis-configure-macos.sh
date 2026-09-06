#!/bin/sh
set -eu
OUTPUT_PATH="${AEGIS_REPORT_CONFIG:-/Library/Application Support/AegisAgent/reporting.json}"
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then echo "python3 is required" >&2; exit 1; fi
umask 077
"$PYTHON_BIN" - "$OUTPUT_PATH" <<'PY'
import hmac,json,os,sys,tempfile
from pathlib import Path
from urllib.parse import urlsplit
path=Path(sys.argv[1]); url=os.getenv("AEGIS_REPORT_URL",""); token=os.getenv("AEGIS_REPORT_TOKEN",""); secret=os.getenv("AEGIS_REPORT_SIGNING_SECRET",""); parsed=urlsplit(url)
if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or len(url)>2048: raise SystemExit("report URL must be an absolute credential-free HTTPS URL")
if not 32<=len(token)<=4096 or not 32<=len(secret)<=4096 or hmac.compare_digest(token,secret): raise SystemExit("report token and signing secret must be independent 32-4096 character values")
path.parent.mkdir(parents=True,exist_ok=True); os.chmod(path.parent,0o700)
fd,temp=tempfile.mkstemp(prefix="."+path.name+".",suffix=".tmp",dir=path.parent)
try:
    with os.fdopen(fd,"w",encoding="utf-8") as handle: json.dump({"schema":"aegis.reporting/v1","report_url":url,"report_token":token,"signing_secret":secret},handle,separators=(",",":")); handle.flush(); os.fsync(handle.fileno())
    os.chmod(temp,0o600); os.replace(temp,path)
except Exception:
    try: os.close(fd)
    except OSError: pass
    Path(temp).unlink(missing_ok=True); raise
PY
chmod 600 "$OUTPUT_PATH"
echo "Aegis reporting configuration installed with root-only permissions."
