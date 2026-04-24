#!/usr/bin/env bash
set -euo pipefail

ARGS_JSON="${MONITORING_KB_ARGS_JSON:-{}}"
DRY_RUN_ENV="${MONITORING_KB_DRY_RUN:-true}"

readarray -t PARSED < <(python3 - <<'PY'
import json, os
raw = os.getenv("MONITORING_KB_ARGS_JSON", "{}")
obj = json.loads(raw) if raw else {}
if not isinstance(obj, dict):
    obj = {}
path = str(obj.get("path", "/var/log"))
older = int(obj.get("older_than_days", 14))
dry = bool(obj.get("dry_run", True))
print(path)
print(older)
print("true" if dry else "false")
PY
)

TARGET_PATH="${PARSED[0]:-/var/log}"
OLDER_DAYS="${PARSED[1]:-14}"
ARG_DRY_RUN="${PARSED[2]:-true}"

if [[ "${DRY_RUN_ENV,,}" == "true" ]]; then
  DRY_RUN="true"
else
  DRY_RUN="$ARG_DRY_RUN"
fi

case "$TARGET_PATH" in
  /var/log|/tmp|/var/tmp) ;;
  *)
    echo "Refusing unsafe path: $TARGET_PATH" >&2
    exit 2
    ;;
esac

if [[ -z "$TARGET_PATH" || "$TARGET_PATH" == "/" || "$TARGET_PATH" == "/home" || "$TARGET_PATH" == "/etc" || "$TARGET_PATH" == "/usr" ]]; then
  echo "Refusing disallowed path: $TARGET_PATH" >&2
  exit 2
fi

echo "Target path: $TARGET_PATH"
echo "Older than days: $OLDER_DAYS"
echo "Dry run: $DRY_RUN"

FIND_EXPR=( -type f -mtime +"$OLDER_DAYS" \( -name '*.gz' -o -name '*.xz' -o -name '*.old' -o -name '*.log.*' \) )

if [[ "$DRY_RUN" == "true" ]]; then
  find "$TARGET_PATH" "${FIND_EXPR[@]}" -print
else
  while IFS= read -r file; do
    rm -f -- "$file"
    echo "deleted: $file"
  done < <(find "$TARGET_PATH" "${FIND_EXPR[@]}" -print)
fi
