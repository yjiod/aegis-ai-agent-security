#!/bin/sh
set -eu
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-user-session.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
HOME_ROOT="$WORK/home"
PUBLISH="$WORK/publish"
mkdir -p "$HOME_ROOT/.codex" "$PUBLISH"
dotnet publish deploy/clients/host/SentinelServiceHost.csproj -c Release -r osx-arm64 --self-contained true -p:PublishSingleFile=true -p:DebugType=None -o "$PUBLISH"
cp public/downloads/sentinel-security-baseline.md "$PUBLISH/"

HOME="$HOME_ROOT" "$PUBLISH/SentinelServiceHost" --user-session
HOME="$HOME_ROOT" "$PUBLISH/SentinelServiceHost" --user-session
test "$(grep -Fxc '<!-- sentinel-managed-user-baseline:start -->' "$HOME_ROOT/.codex/AGENTS.md")" -eq 1
test "$(grep -Fxc '<!-- sentinel-managed-user-baseline:end -->' "$HOME_ROOT/.codex/AGENTS.md")" -eq 1
python3 - "$HOME_ROOT/Library/Application Support/SentinelAgent/session-attestation.json" <<'PY'
import json,os,stat,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
assert set(value)=={"schema","host_version","updated_at","platform","agents","baseline_targets","baseline_writes","baseline_failures","arbitrary_command_enabled"}
assert value["schema"]=="sentinel.user-session/v1" and value["host_version"]=="0.3.0" and value["platform"]=="macos"
assert value["agents"]==["codex"] and value["baseline_targets"]==1 and value["baseline_writes"]==1 and value["baseline_failures"]==0
assert value["arbitrary_command_enabled"] is False and stat.S_IMODE(os.stat(sys.argv[1]).st_mode)==0o600
PY

printf '%s\n' '<!-- sentinel-managed-user-baseline:start -->' >> "$HOME_ROOT/.codex/AGENTS.md"
cp "$HOME_ROOT/.codex/AGENTS.md" "$WORK/malformed-before"
set +e
HOME="$HOME_ROOT" "$PUBLISH/SentinelServiceHost" --user-session
status=$?
set -e
test "$status" -eq 2
cmp "$WORK/malformed-before" "$HOME_ROOT/.codex/AGENTS.md"
python3 - "$HOME_ROOT/Library/Application Support/SentinelAgent/session-attestation.json" <<'PY'
import json,sys
value=json.load(open(sys.argv[1],encoding="utf-8"))
assert value["baseline_targets"]==1 and value["baseline_writes"]==0 and value["baseline_failures"]==1
PY

ESCAPE_HOME="$WORK/escape-home"
ESCAPE_TARGET="$WORK/escape-target"
mkdir -p "$ESCAPE_HOME/.codex" "$ESCAPE_TARGET"
ln -s "$ESCAPE_TARGET" "$ESCAPE_HOME/Library"
set +e
HOME="$ESCAPE_HOME" "$PUBLISH/SentinelServiceHost" --user-session
status=$?
set -e
test "$status" -eq 78
test ! -e "$ESCAPE_HOME/.codex/AGENTS.md"
test ! -e "$ESCAPE_TARGET/Application Support/SentinelAgent/session-attestation.json"
