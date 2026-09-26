#!/bin/sh
# Historical .run filename: current-user legacy service retirement only.
# New installations use the trusted system .pkg workflow in MACOS-INSTALL.md.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
umask 077
fail() {
  printf '{"schema":"aegis.user-retirement-result/v1","scope":"current_user","status":"%s","runtime_retained":true,"baselines_retained":true,"health_verified":false}\n' "$1"
  exit "$2"
}
if [ "$#" -eq 1 ] && [ "$1" = --help ]; then
  printf '%s\n' 'Legacy current-user service retirement: /bin/sh aegis-agent-macos-standalone.run --uninstall' 'Run as that user, without sudo. Requires an installed trusted native maintenance runtime.' 'New installation: use the approved system package and MACOS-INSTALL.md.'
  exit 0
fi
[ "$#" -eq 1 ] && [ "$1" = --uninstall ] || fail native_package_installation_required 2
# Custom service names or directories cannot silently widen the operation.
[ "${AEGIS_INSTALL_DIR+x}${AEGIS_PLIST+x}${AEGIS_LABEL+x}" = '' ] || fail custom_user_retirement_not_supported 2
[ "$(/usr/bin/uname -s)" = Darwin ] || fail macos_required 2
[ "$(/usr/bin/id -u)" != 0 ] || fail unprivileged_macos_user_required 2
INSTALL_DIR='/Library/Application Support/AegisAgent'
trusted_path() {
  [ ! -L "$1" ] || return 1
  [ "$(/usr/bin/stat -f '%u' "$1")" = 0 ] || return 1
  mode=$(/usr/bin/stat -f '%Lp' "$1")
  [ "$((0$mode & 022))" -eq 0 ] || return 1
  # ACL grants can permit writes despite restrictive POSIX mode bits.
  metadata=$(/bin/ls -lde "$1" 2>/dev/null) || return 1
  case "$metadata" in *'
'*) return 1 ;; esac
  return 0
}
for directory in /Library '/Library/Application Support' "$INSTALL_DIR"; do
  trusted_path "$directory" || fail trusted_runtime_required 1
done
AGENT="$INSTALL_DIR/aegis-agent"
[ -f "$AGENT" ] && [ -x "$AGENT" ] && [ ! -L "$AGENT" ] || fail trusted_runtime_required 1
trusted_path "$AGENT" || fail trusted_runtime_required 1
[ "$(/usr/bin/stat -f '%l' "$AGENT")" = 1 ] || fail trusted_runtime_required 1
"$AGENT" --user-retirement-selftest >/dev/null 2>&1 || fail native_retirement_capability_required 1
exec "$AGENT" --retire-legacy-user
