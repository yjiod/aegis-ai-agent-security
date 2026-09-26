#!/bin/sh
# Retain the historical filename as a maintenance-only launcher, without payload.
# Native installations (online or cached/offline package) use build-macos-pkg.sh.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HEADER="$ROOT/public/downloads/retire-aegis-user-macos.sh"
OUT="$ROOT/public/downloads/aegis-agent-macos-standalone.run"
[ -f "$HEADER" ] && [ ! -L "$HEADER" ] || { echo 'Maintenance launcher source unavailable' >&2; exit 1; }
[ ! -L "$OUT" ] || { echo 'Refusing linked maintenance output' >&2; exit 1; }
TEMP=$(mktemp "$ROOT/public/downloads/.aegis-legacy-launcher.XXXXXXXX")
trap 'rm -f "$TEMP"' EXIT INT TERM
cp "$HEADER" "$TEMP"
chmod 755 "$TEMP"
/bin/sh -n "$TEMP"
mv -f "$TEMP" "$OUT"
echo 'Built maintenance-only aegis-agent-macos-standalone.run; no runtime payload or installer fallback.'
