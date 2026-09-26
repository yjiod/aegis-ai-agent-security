#!/bin/sh
# This MDM entry point only invokes the installed self-contained client.
set -eu
INSTALL_DIR='/Library/Application Support/AegisAgent'
fail() {
  printf '%s\n' '{"schema":"aegis.macos-health/v1","AegisInstalled":false,"AegisIntegrityValid":false,"AegisIntegrityScope":"local-package-checksums","AegisLaunchDaemonRegistered":false,"AegisLaunchDaemonHealthy":false,"AegisLegacyServicePresent":false,"AegisReportingConfigured":false,"AegisReportingHealthy":false,"AegisPolicyVersion":"missing","AegisReportValid":false,"AegisScanRecent":false,"AegisFindingsKnown":false,"AegisCriticalFindings":0,"AegisHighFindings":0,"AegisFreshnessSeconds":7200,"AegisDiagnosticIssues":["runtime_unavailable"]}'
  exit "$1"
}
[ "$#" -eq 0 ] || fail 2
[ "$(/usr/bin/id -u)" = 0 ] || fail 2
trusted_path() {
  [ ! -L "$1" ] || return 1
  [ "$(/usr/bin/stat -f '%u' "$1")" = 0 ] || return 1
  mode=$(/usr/bin/stat -f '%Lp' "$1")
  [ "$((0$mode & 022))" -eq 0 ]
}
for directory in /Library '/Library/Application Support' "$INSTALL_DIR"; do
  trusted_path "$directory" || fail 1
done
AGENT="$INSTALL_DIR/aegis-agent"
[ -f "$AGENT" ] && [ -x "$AGENT" ] && [ ! -L "$AGENT" ] || fail 1
trusted_path "$AGENT" || fail 1
"$AGENT" --diagnostics-selftest >/dev/null 2>&1 || fail 1
exec "$AGENT" --diagnostics
