#!/bin/sh
# Bootstrap a self-contained system package. No interpreter install/fallback.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
umask 077
STAGE=''
DIGEST=''
ATTEMPTED=false
SUCCEEDED=false
finish() {
  printf '{"schema":"aegis.mdm-install-result/v1","status":"%s","installation_attempted":%s,"installer_succeeded":%s,"health_verified":false,"artifact_sha256":"%s"}\n' "$1" "$ATTEMPTED" "$SUCCEEDED" "$DIGEST"
  exit "$2"
}
cleanup() {
  if [ -n "$STAGE" ]; then
    /bin/rm -f "$STAGE/candidate.pkg" "$STAGE/download.log" "$STAGE/signature.log" "$STAGE/assessment.plist" "$STAGE/assessment.log" "$STAGE/status.log" "$STAGE/installer.log"
    /bin/rmdir "$STAGE" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'finish interrupted 130' INT
trap 'finish interrupted 143' TERM
[ "$#" -eq 0 ] || finish unexpected_arguments 2
[ "$(/usr/bin/id -u)" = 0 ] || finish administrator_required 2
[ "$(/usr/bin/uname -s)" = Darwin ] || finish macos_required 2

EXPECTED="${AEGIS_MACOS_PKG_SHA256:-}"
TEAM="${AEGIS_MACOS_TEAM_ID:-}"
case "$EXPECTED" in ''|*[!0-9a-fA-F]*) finish trusted_digest_required 2 ;; esac
[ "${#EXPECTED}" -eq 64 ] || finish trusted_digest_required 2
DIGEST=$(printf '%s' "$EXPECTED" | /usr/bin/tr 'A-F' 'a-f')
case "$TEAM" in ''|*[!A-Z0-9]*) finish publisher_required 2 ;; esac
[ "${#TEAM}" -eq 10 ] || finish publisher_required 2

LOCAL="${AEGIS_MACOS_PKG_PATH:-}"
URL="${AEGIS_MACOS_PKG_URL:-}"
[ -z "$LOCAL" ] || [ -z "$URL" ] || finish ambiguous_package_source 2
if [ -n "$LOCAL" ]; then
  case "$LOCAL" in /*.pkg) ;; *) finish invalid_local_package 2 ;; esac
  [ -f "$LOCAL" ] && [ ! -L "$LOCAL" ] || finish invalid_local_package 2
  [ "$(/usr/bin/stat -f '%u' "$LOCAL" 2>/dev/null)" = 0 ] || finish unsafe_local_package 2
  [ "$(/usr/bin/stat -f '%l' "$LOCAL" 2>/dev/null)" = 1 ] || finish unsafe_local_package 2
  mode=$(/usr/bin/stat -f '%Lp' "$LOCAL" 2>/dev/null) || finish unsafe_local_package 2
  [ "$((0$mode & 022))" -eq 0 ] || finish unsafe_local_package 2
  size=$(/usr/bin/stat -f '%z' "$LOCAL" 2>/dev/null) || finish unsafe_local_package 2
  [ "$size" -gt 0 ] && [ "$size" -le 134217728 ] || finish package_size_refused 2
else
  [ -n "$URL" ] || URL="${AEGIS_BASE_URL:-https://aegis.example.com/downloads}/aegis-agent-macos.pkg"
  # No credentials, queries, redirects, whitespace or shell-interpreted input.
  [ "${#URL}" -le 2048 ] || finish invalid_package_url 2
  printf '%s\n' "$URL" | /usr/bin/grep -Eq '^https://([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?/[A-Za-z0-9._~%/-]+$' || finish invalid_package_url 2
  case "$URL" in *'
'*) finish invalid_package_url 2 ;; esac
fi

# A fresh package must not silently run alongside a legacy scanner or overwrite
# an installation whose previous child-process cleanup is still unconfirmed.
if [ -e '/Library/Application Support/AegisAgent/watch-cleanup-pending.json' ] || [ -L '/Library/Application Support/AegisAgent/watch-cleanup-pending.json' ]; then
  finish prior_cleanup_requires_verification 1
fi
if /bin/launchctl print system/com.company.aegis-agent >/dev/null 2>&1; then
  finish legacy_service_migration_required 1
else
  legacy_result=$?
  [ "$legacy_result" -eq 113 ] || finish legacy_service_state_unavailable 1
fi
for legacy in /Library/LaunchDaemons/com.company.aegis-agent.plist /Users/*/Library/LaunchAgents/com.aegis.agent.plist /Users/*/Library/LaunchAgents/com.company.aegis-agent.plist; do
  if [ -e "$legacy" ] || [ -L "$legacy" ]; then finish legacy_service_migration_required 1; fi
done

for parent in /private /private/var /private/var/tmp; do
  [ -d "$parent" ] && [ ! -L "$parent" ] || finish staging_unavailable 1
done
STAGE=$(/usr/bin/mktemp -d /private/var/tmp/aegis-mdm.XXXXXXXX) || finish staging_unavailable 1
/bin/chmod -N "$STAGE" && /bin/chmod 700 "$STAGE" || finish staging_unavailable 1
PKG="$STAGE/candidate.pkg"
if [ -n "$LOCAL" ]; then
  (ulimit -f 131072; /bin/cp -P -X "$LOCAL" "$PKG") 2>"$STAGE/download.log" || finish package_copy_failed 1
else
  (ulimit -f 131072; /usr/bin/curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --silent --show-error --connect-timeout 15 --max-time 120 --max-filesize 134217728 \
    "$URL" -o "$PKG") >"$STAGE/download.log" 2>&1 || finish package_download_failed 1
fi
[ -f "$PKG" ] && [ ! -L "$PKG" ] || finish invalid_staged_package 1
/bin/chmod -N "$PKG" && /bin/chmod 600 "$PKG" || finish staging_unavailable 1
size=$(/usr/bin/stat -f '%z' "$PKG")
[ "$size" -gt 0 ] && [ "$size" -le 134217728 ] || finish package_size_refused 1
verify_digest() {
  printf '%s  %s\n' "$DIGEST" "$PKG" | /usr/bin/shasum -a 256 -c - >/dev/null 2>&1
}
verify_digest || finish package_digest_mismatch 1
/usr/sbin/pkgutil --check-signature "$PKG" >"$STAGE/signature.log" 2>&1 || finish package_signature_rejected 1
/usr/bin/grep -Eq "^[[:space:]]*1[.] Developer ID Installer: .+ [(]$TEAM[)][[:space:]]*$" "$STAGE/signature.log" || finish package_publisher_mismatch 1
if ! /usr/sbin/spctl --status >"$STAGE/status.log" 2>&1; then
  /usr/bin/grep -Fxq 'assessments disabled' "$STAGE/status.log" && finish platform_assessment_disabled 1
  finish platform_assessment_unavailable 1
fi
/usr/bin/grep -Fxq 'assessments enabled' "$STAGE/status.log" || finish platform_assessment_disabled 1
/usr/sbin/spctl --assess --type install --raw --ignore-cache --no-cache "$PKG" >"$STAGE/assessment.plist" 2>"$STAGE/assessment.log" || finish package_assessment_rejected 1
verdict=$(/usr/bin/plutil -extract 'assessment:verdict' raw -expect bool -o - "$STAGE/assessment.plist" 2>/dev/null) || finish invalid_package_assessment 1
[ "$verdict" = true ] || finish package_assessment_rejected 1
source=$(/usr/bin/plutil -extract 'assessment:authority.assessment:authority:source' raw -expect string -o - "$STAGE/assessment.plist" 2>/dev/null) || finish invalid_package_assessment 1
[ "$source" = 'Notarized Developer ID' ] || finish package_notarization_unconfirmed 1
# Older plutil versions can print a missing-key error to stdout despite -o.
if /usr/bin/plutil -extract 'assessment:authority.assessment:authority:override' raw -o /dev/null "$STAGE/assessment.plist" >/dev/null 2>&1; then
  finish package_assessment_override_refused 1
fi
if /usr/bin/plutil -type 'assessment:authority.assessment:authority:verdict' "$STAGE/assessment.plist" >/dev/null 2>&1; then
  authority=$(/usr/bin/plutil -extract 'assessment:authority.assessment:authority:verdict' raw -expect bool -o - "$STAGE/assessment.plist" 2>/dev/null) || finish invalid_package_assessment 1
  [ "$authority" = true ] || finish package_assessment_rejected 1
fi
# Recheck bytes after all assessors, immediately before Installer gets the package.
verify_digest || finish package_changed_after_assessment 1
ATTEMPTED=true
/usr/sbin/installer -pkg "$PKG" -target / >"$STAGE/installer.log" 2>&1 || finish installer_failed_state_requires_verification 1
SUCCEEDED=true
finish installed_health_pending 0
