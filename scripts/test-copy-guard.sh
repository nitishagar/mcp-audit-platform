#!/usr/bin/env bash
# Exercises copy-guard both ways without touching the tree (P1L-copyguard):
# green on a clean clone, red after injecting a banned phrase.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

git clone -q . "$TMP/clone" 2>/dev/null
if ! (cd "$TMP/clone" && bash scripts/copy-guard.sh >/dev/null); then
  echo "copy-guard self-test: FAIL (clean clone is red)" >&2
  exit 1
fi
echo "guarantee secure outcomes" >> "$TMP/clone/README.md"
if (cd "$TMP/clone" && bash scripts/copy-guard.sh >/dev/null 2>&1); then
  echo "copy-guard self-test: FAIL (injected phrase stayed green)" >&2
  exit 1
fi
echo "copy-guard self-test: OK"
