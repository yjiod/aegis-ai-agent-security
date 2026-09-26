#!/bin/sh
# Developer/CI builder. None of the build tools ship as endpoint prerequisites.
set -eu
[ "$#" -eq 1 ] || { echo 'Usage: build-app.sh NEW_OUTPUT_DIRECTORY' >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
case "$1" in /*) OUT=$1 ;; *) OUT="$PWD/$1" ;; esac
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo 'Output already exists' >&2; exit 2; }
VERSION=$(grep -m1 'AGENT_VERSION =' "$ROOT/public/downloads/aegis_agent.py" | sed 's/[^"]*"\([^"]*\)".*/\1/')
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo 'Invalid bundle version' >&2; exit 2; }
mkdir -p "$OUT"
swift build --package-path "$ROOT/clients/macos" --scratch-path "$OUT/build" -c release
BIN_DIR=$(swift build --package-path "$ROOT/clients/macos" --scratch-path "$OUT/build" -c release --show-bin-path)
APP="$OUT/Aegis.app"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN_DIR/AegisAgent" "$APP/Contents/MacOS/AegisAgent"
chmod 755 "$APP/Contents/MacOS/AegisAgent"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>AegisAgent</string>
<key>CFBundleIdentifier</key><string>com.aegis.desktop</string>
<key>CFBundleName</key><string>Aegis</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
plutil -lint "$APP/Contents/Info.plist"
if otool -L "$APP/Contents/MacOS/AegisAgent" | grep -Eqi 'libpython|Python.framework|/opt/homebrew|/usr/local'; then
  echo 'External runtime linkage is prohibited' >&2
  exit 1
fi
ditto -c -k --keepParent "$APP" "$OUT/Aegis.app.zip"
echo "Unsigned review candidate: $APP"
