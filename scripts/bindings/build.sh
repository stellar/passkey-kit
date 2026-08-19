#!/usr/bin/env bash
#
# Regenerate the passkey-kit-sdk bindings from the canonical smart-wallet WASM.
#
# The canonical hash is THE source of truth (docs/deployments-testnet-*.md). The
# WASM is fetched by hash from testnet, bindings are generated to a temp dir with
# the pinned Stellar CLI, and only the generated `src/index.ts` is copied into
# the package. The curated README and the B1 packaging are preserved. NEVER
# hand-edit the generated bindings; add post-gen steps here.
#
# Usage: bash scripts/bindings/build.sh
set -euo pipefail

# Canonical smart-wallet WASM hash — keep in sync with the deployments manifest
# (docs/deployments-2026-08-19.md). Pinned Stellar CLI: 27.1.0.
CANONICAL_HASH="502ea4e7bdb3ea99880941f1d35ceb67fb598692c0bb40f842ef9c9f17d58b58"
NETWORK="testnet"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_SRC="$ROOT/packages/passkey-kit-sdk/src/index.ts"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Fetching canonical WASM ${CANONICAL_HASH} from ${NETWORK}…"
stellar contract fetch --wasm-hash "$CANONICAL_HASH" --network "$NETWORK" \
  --out-file "$TMP/smart-wallet.wasm"

ACTUAL="$(shasum -a 256 "$TMP/smart-wallet.wasm" | awk '{print $1}')"
if [ "$ACTUAL" != "$CANONICAL_HASH" ]; then
  echo "✗ Fetched WASM hash ($ACTUAL) != canonical ($CANONICAL_HASH)" >&2
  exit 1
fi

echo "Generating TypeScript bindings…"
stellar contract bindings typescript --wasm "$TMP/smart-wallet.wasm" \
  --overwrite --output-dir "$TMP/pks-gen" >/dev/null

echo "Applying post-gen patches (copy generated spec, preserve docs and packaging)…"
cp "$TMP/pks-gen/src/index.ts" "$PKG_SRC"

echo "✓ Regenerated passkey-kit-sdk from canonical WASM ${CANONICAL_HASH}"
echo "  Run 'pnpm --filter passkey-kit-sdk run build' to rebuild dist."
