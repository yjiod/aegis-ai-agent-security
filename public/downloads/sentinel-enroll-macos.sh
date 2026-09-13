#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "root is required" >&2; exit 77; fi
if [ "$#" -ne 1 ]; then echo "usage: sentinel-enroll-macos.sh <private-enrollment.json>" >&2; exit 64; fi
ENROLLMENT=$1
OUTPUT="${SENTINEL_REPORT_CONFIG:-/Library/Application Support/SentinelAgent/reporting.json}"
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then echo "python3 is required" >&2; exit 1; fi
umask 077
"$PYTHON_BIN" - "$ENROLLMENT" "$OUTPUT" <<'PY'
import hashlib,hmac,json,os,stat,sys,tempfile,time
from pathlib import Path
from urllib.parse import urlsplit
source=Path(sys.argv[1]); output=Path(sys.argv[2])
info=source.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>32768: raise SystemExit("unsafe enrollment file ownership, mode, type, or size")
value=json.loads(source.read_text(encoding="utf-8")); expected={"schema","device_id","report_url","report_token","signing_secret","policy_verification_keys","issued_at","expires_at","consume_once"}
if not isinstance(value,dict) or set(value)!=expected or value.get("schema")!="sentinel.device-enrollment/v3" or value.get("consume_once") is not True: raise SystemExit("invalid enrollment contract")
now=int(time.time())
if type(value.get("issued_at")) is not int or type(value.get("expires_at")) is not int or not -300<=now-value["issued_at"]<=86400 or not 0<=value["expires_at"]-now<=86400: raise SystemExit("expired or future enrollment")
actual=hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:12]
if not hmac.compare_digest(value.get("device_id","").encode(),actual.encode()): raise SystemExit("enrollment device identity mismatch")
url=value.get("report_url",""); parsed=urlsplit(url); token=value.get("report_token",""); secret=value.get("signing_secret",""); policy_keys=value.get("policy_verification_keys")
if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or len(url)>2048: raise SystemExit("invalid report URL")
if not isinstance(token,str) or not isinstance(secret,str) or not 32<=len(token)<=4096 or not 32<=len(secret)<=4096 or hmac.compare_digest(token,secret): raise SystemExit("invalid reporting credentials")
if not isinstance(policy_keys,list) or not 1<=len(policy_keys)<=5 or any(not isinstance(key,str) or not 32<=len(key)<=4096 for key in policy_keys) or len(policy_keys)!=len(set(policy_keys)) or token in policy_keys or secret in policy_keys: raise SystemExit("invalid policy verification keys")
output.parent.mkdir(parents=True,exist_ok=True); os.chmod(output.parent,0o700)
fd,temp=tempfile.mkstemp(prefix="."+output.name+".",suffix=".tmp",dir=output.parent)
try:
    with os.fdopen(fd,"w",encoding="utf-8") as handle:
        json.dump({"schema":"sentinel.reporting/v2","report_url":url,"report_token":token,"signing_secret":secret,"policy_verification_keys":policy_keys},handle,separators=(",",":")); handle.flush(); os.fsync(handle.fileno())
    os.chmod(temp,0o600); os.replace(temp,output); source.unlink()
except Exception:
    try: os.close(fd)
    except OSError: pass
    Path(temp).unlink(missing_ok=True); raise
PY
echo "Sentinel enrollment consumed for this macOS device."
