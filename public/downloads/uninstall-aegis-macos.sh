#!/bin/sh
set -eu
PLIST="/Library/LaunchDaemons/com.company.aegis-agent.plist"
launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
START='<!-- aegis-managed-user-baseline:start -->'
END='<!-- aegis-managed-user-baseline:end -->'
for home in /Users/*; do
  [ -d "$home" ] || continue
  for relative in '.codex/AGENTS.md' '.claude/CLAUDE.md'; do
    file="$home/$relative"
    [ -f "$file" ] && [ ! -L "$file" ] || continue
    if /usr/bin/grep -Fq "$START" "$file" && /usr/bin/grep -Fq "$END" "$file"; then
      temp="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/aegis-uninstall.XXXXXX")"
      /usr/bin/awk -v start="$START" -v end="$END" '$0==start{managed=1;next}$0==end{managed=0;next}!managed{print}' "$file" > "$temp"
      /bin/cat "$temp" > "$file"; /bin/rm -f "$temp"
    fi
  done
done
rm -f "$PLIST"
rm -rf "/Library/Application Support/AegisAgent"
echo "Aegis runtime and managed user baseline blocks removed. Repository rule files remain under source control."
