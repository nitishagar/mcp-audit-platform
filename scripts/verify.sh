#!/usr/bin/env bash
# `pnpm verify`: typecheck + lint + build + test + copy-guard, in order.
# Build always precedes test so dist-reading suites pass on fresh checkouts.
# Prints "VERIFY OK" on success; any failure aborts non-zero with no OK line.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== static =="
pnpm typecheck
pnpm lint
pnpm format:check

echo "== build =="
pnpm build

echo "== tests =="
pnpm test

echo "== copy-guard =="
pnpm copy-guard
bash scripts/test-copy-guard.sh

echo "VERIFY OK"
