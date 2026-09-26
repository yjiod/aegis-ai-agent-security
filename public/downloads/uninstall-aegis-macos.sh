#!/bin/sh
set -eu
# Maintenance is embedded in the client; never search for external Python.
INSTALL_DIR='/Library/Application Support/AegisAgent'
if [ "$#" -ne 0 ]; then
  echo 'The Aegis uninstaller accepts no arguments.' >&2
  exit 2
fi
if [ "$(/usr/bin/id -u)" != 0 ]; then
  echo 'Run the Aegis uninstaller with administrator privileges.' >&2
  exit 2
fi
trusted_path() {
  [ ! -L "$1" ] || return 1
  [ "$(/usr/bin/stat -f '%u' "$1")" = 0 ] || return 1
  mode=$(/usr/bin/stat -f '%Lp' "$1")
  [ "$((0$mode & 022))" -eq 0 ]
}
for directory in /Library '/Library/Application Support' "$INSTALL_DIR"; do
  if ! trusted_path "$directory"; then
    echo 'Aegis installation ownership or permissions are invalid; uninstall refused.' >&2
    exit 1
  fi
done
AGENT="$INSTALL_DIR/aegis-agent"
if [ -f "$AGENT" ] && [ -x "$AGENT" ] && [ ! -L "$AGENT" ]; then
  trusted_path "$AGENT" || exit 1
  # Old clients may not expose maintenance. Test that exact capability before
  # stopping services; do not fall back to a loose script or another runtime.
  "$AGENT" --maintenance-selftest >/dev/null 2>&1 || {
    echo 'Aegis maintenance self-test failed. Repair the installation before uninstalling.' >&2
    exit 1
  }
  exec "$AGENT" --uninstall-system
fi
echo 'Aegis maintenance runtime is missing. Repair the installation before uninstalling; no files were removed.' >&2
exit 1
