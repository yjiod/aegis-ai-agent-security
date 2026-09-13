#!/bin/sh
set -eu
OUTPUT_PATH="${SENTINEL_REPORT_CONFIG:-/Library/Application Support/SentinelAgent/reporting.json}"
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then echo "python3 is required" >&2; exit 1; fi
umask 077
"$PYTHON_BIN" - "$OUTPUT_PATH" <<'PY'
import hmac,json,os,sys,tempfile
from pathlib import Path
from urllib.parse import urlsplit
path=Path(sys.argv[1]); url=os.getenv("SENTINEL_REPORT_URL",""); token=os.getenv("SENTINEL_REPORT_TOKEN",""); secret=os.getenv("SENTINEL_REPORT_SIGNING_SECRET",""); parsed=urlsplit(url)
try: policy_keys=json.loads(os.getenv("SENTINEL_POLICY_VERIFICATION_KEYS","[]"))
except (TypeError,ValueError): raise SystemExit("policy verification keys must be a JSON array")
if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or len(url)>2048: raise SystemExit("report URL must be an absolute credential-free HTTPS URL")
if not 32<=len(token)<=4096 or not 32<=len(secret)<=4096 or hmac.compare_digest(token,secret): raise SystemExit("report token and signing secret must be independent 32-4096 character values")
if not isinstance(policy_keys,list) or not 1<=len(policy_keys)<=5 or any(not isinstance(key,str) or not 32<=len(key)<=4096 for key in policy_keys) or len(policy_keys)!=len(set(policy_keys)) or token in policy_keys or secret in policy_keys: raise SystemExit("policy verification keys must contain 1-5 unique independent values")
path.parent.mkdir(parents=True,exist_ok=True); os.chmod(path.parent,0o700)
fd,temp=tempfile.mkstemp(prefix="."+path.name+".",suffix=".tmp",dir=path.parent)
try:
    with os.fdopen(fd,"w",encoding="utf-8") as handle: json.dump({"schema":"sentinel.reporting/v2","report_url":url,"report_token":token,"signing_secret":secret,"policy_verification_keys":policy_keys},handle,separators=(",",":")); handle.flush(); os.fsync(handle.fileno())
    os.chmod(temp,0o600); os.replace(temp,path)
except Exception:
    try: os.close(fd)
    except OSError: pass
    Path(temp).unlink(missing_ok=True); raise
PY
chmod 600 "$OUTPUT_PATH"
echo "Sentinel reporting configuration installed with root-only permissions."
