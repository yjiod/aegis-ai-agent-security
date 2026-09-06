#!/bin/sh
set -eu
PLIST="/Library/LaunchDaemons/com.company.sentinel-agent.plist"
INSTALL_DIR="/Library/Application Support/SentinelAgent"
if [ -L "$INSTALL_DIR" ]; then echo "Sentinel installation directory is a symlink; refusing recursive removal" >&2; exit 1; fi
if [ -e "$INSTALL_DIR" ] && [ "$(/usr/bin/stat -f '%u' "$INSTALL_DIR" 2>/dev/null || echo -1)" -ne 0 ]; then echo "Sentinel installation directory is not owned by root; refusing recursive removal" >&2; exit 1; fi
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
START='<!-- sentinel-managed-user-baseline:start -->'
END='<!-- sentinel-managed-user-baseline:end -->'
for home in /Users/*; do
  [ -d "$home" ] && [ ! -L "$home" ] || continue
  for relative in '.codex/AGENTS.md' '.claude/CLAUDE.md' '.gemini/GEMINI.md' '.copilot/copilot-instructions.md'; do
    file="$home/$relative"
    [ -f "$file" ] && [ ! -L "$file" ] && [ ! -L "$(/usr/bin/dirname "$file")" ] || continue
    start_count="$(/usr/bin/grep -Fxc "$START" "$file" || true)"; end_count="$(/usr/bin/grep -Fxc "$END" "$file" || true)"
    start_line="$(/usr/bin/grep -Fn "$START" "$file" | /usr/bin/cut -d: -f1 || true)"; end_line="$(/usr/bin/grep -Fn "$END" "$file" | /usr/bin/cut -d: -f1 || true)"
    if [ "$start_count" -eq 1 ] && [ "$end_count" -eq 1 ] && [ "$start_line" -lt "$end_line" ]; then
      temp="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/sentinel-uninstall.XXXXXX")"
      /usr/bin/awk -v start="$START" -v end="$END" '$0==start{managed=1;next}$0==end{managed=0;next}!managed{print}' "$file" > "$temp"
      /bin/cat "$temp" > "$file"; /bin/rm -f "$temp"
    fi
  done
done
rm -f "$PLIST"
rm -rf "$INSTALL_DIR"
echo "Sentinel runtime and managed user baseline blocks removed. Repository rule files remain under source control."
