#!/usr/bin/env bash
set -euo pipefail

echo "[diagnose] df -h"
df -h || true
echo
echo "[diagnose] df -i"
df -i || true

for target in / /var /var/log; do
  if [[ -d "$target" ]]; then
    echo
    echo "[diagnose] top directories in $target"
    du -x -h --max-depth=2 "$target" 2>/dev/null | sort -hr | head -n 20 || true
  fi
done
