#!/bin/sh
set -eu
# Service coordination and managed block cleanup live in the installed helper.
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
if [ -x "$INSTALL_DIR/aegis-maintenance" ] && [ ! -L "$INSTALL_DIR/aegis-maintenance" ]; then
  trusted_path "$INSTALL_DIR/aegis-maintenance" || exit 1
  exec "$INSTALL_DIR/aegis-maintenance"
fi
if [ -x /usr/bin/python3 ] && [ -f "$INSTALL_DIR/aegis_macos_maintenance.py" ] && [ ! -L "$INSTALL_DIR/aegis_macos_maintenance.py" ]; then
  trusted_path "$INSTALL_DIR/aegis_macos_maintenance.py" || exit 1
  exec /usr/bin/python3 -I -B "$INSTALL_DIR/aegis_macos_maintenance.py"
fi
echo 'Aegis maintenance runtime is missing. Repair the installation before uninstalling; no files were removed.' >&2
exit 1
