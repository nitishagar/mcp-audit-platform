#!/usr/bin/env bash
# Copy-guard (I9): fail on banned assurance words outside the phrase allowlist.
# Scope: tracked content files only; excludes itself, the allowlist, fixtures,
# vendored oracles, and build output. Whole-word matching; an allowlisted phrase
# containing a banned word passes, anywhere else fails.
set -euo pipefail
cd "$(dirname "$0")/.."

ALLOW="scripts/copy-guard-allowlist.txt"
BANNED=('penetration test' 'pentest' 'exploit' 'guarantee secure' 'certified')

mapfile -t FILES < <(git ls-files '*.ts' '*.js' '*.mjs' '*.html' '*.css' '*.json' '*.md' \
  | grep -v -e '^scripts/copy-guard\.sh$' -e '^scripts/copy-guard-allowlist\.txt$' \
             -e '/fixtures/' -e '/vendor/' -e '/dist/' || true)

fail=0
for f in "${FILES[@]:-}"; do
  [ -n "${f:-}" ] || continue
  # Strip allowlisted phrases first (phrase granularity), then scan.
  content=$(cat "$f")
  while IFS= read -r phrase || [ -n "$phrase" ]; do
    [ -n "$phrase" ] || continue
    content=${content//"$phrase"/}
  done < "$ALLOW"
  for word in "${BANNED[@]}"; do
    if printf '%s' "$content" | grep -i -w -q -e "$word"; then
      echo "copy-guard: banned phrase '$word' in $f" >&2
      fail=1
    fi
  done
done

if [ "$fail" -ne 0 ]; then
  echo "copy-guard: FAIL" >&2
  exit 1
fi
echo "copy-guard: OK (${#FILES[@]} files scanned)"
