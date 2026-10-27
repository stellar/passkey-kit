# Legacy code inventory

Last reviewed: 2026-10-27 (against `main` at `74210a4`, `passkey-kit@0.19.1`).

This repo is forward-only: every line must earn its keep. This document lists
the code that looks like legacy, says why it is still here, and says what
removing it would break. Update it when you remove or add legacy code.

Code is grouped by what to do with it:

1. [Kept on purpose](#1-kept-on-purpose): legacy code that protects funds in
   deployed wallets. Keep it until its exit condition is met.
2. [Not legacy](#2-not-legacy-misleading-names): current code with "legacy" in
   its name or comments, or kept for API compatibility. Rename or reword it;
   do not remove it.
3. [Removal candidates](#3-removal-candidates): code with no strong reason to
   stay.

## 1. Kept on purpose

Exit conditions differ by item; each item states its own. The upgrade items
depend on the `update_signer` advisory and the upgrade window for the affected
mainnet wallets. See [SECURITY.md](../SECURITY.md) and
[legacy-wallet-upgrade.md](./legacy-wallet-upgrade.md). When an item exits,
move it to a tag or branch instead of deleting its history.

### `contracts-legacy/`

- **What:** the pre-1.0 wallet source, the committed artifact
  `contracts-legacy/out/smart_wallet.wasm`, and the `contracts-legacy` CI job
  that checks its hash and runs its tests.
- **Why:** it builds `c079d3a4…` (`LEGACY_UPGRADE_TARGET_WASM_HASH`), the
  in-place upgrade target for mainnet wallets on known-vulnerable WASM. It is
  the only build that reads both pre-1.0 storage layouts. The other patched
  builds brick `0c0a264d…` and `19868df3…` wallets.
- **If removed:** operators cannot rebuild or verify the upgrade target.
  `SECURITY.md`, `README.md` (repository layout), and
  `docs/legacy-wallet-upgrade.md` point to it. The CI hash check is lost.
- **Exit:** affected wallets no longer need the upgrade path.

### Legacy upgrade helpers and code identities

- **What:** `src/kit/legacy-ops.ts` (`inspectLegacyWallet`,
  `buildLegacyUpgradeTx`, `signLegacyUpgradeTx`, `buildLegacyMigrateTx`), the
  `PasskeyKit` methods that wrap them, `LegacyWalletError`
  (`src/errors.ts`), and the hash lists in `src/constants.ts`
  (`KNOWN_VULNERABLE_WALLET_WASM_HASHES`, `LEGACY_WALLET_WASM_HASHES`,
  `LEGACY_UPGRADE_TARGET_WASM_HASH`, `LEGACY_WALLET_UPGRADE_GUIDE_URL`).
- **Why:** they are the in-kit upgrade path for affected wallets (shipped in
  0.19.x). The `PasskeyKit` constructor also uses the vulnerable-hash list to
  refuse a vulnerable hash in `walletWasmHash`, `acceptedWasmHashes`, or
  `acceptedBirthWasmHashes`.
- **If removed:** a breaking public API change. `connectWallet` on an old
  wallet fails with a generic birth-verification error instead of naming the
  vulnerable code and the upgrade path. The guard against deploying from or
  accepting a vulnerable build is lost.
- **Exit:** the upgrade helpers can go when affected wallets no longer need
  them. Keep `KNOWN_VULNERABLE_WALLET_WASM_HASHES` and the constructor guard
  while a vulnerable build can still be deployed from or accepted; they are
  cheap.

### Legacy contract error codes 1-9

- **What:** the `SmartWalletLegacy` entries in `src/contract-errors.ts`.
- **Why:** errors from pre-1.0 wallets still decode to a name and message.
- **If removed:** old wallets show raw codes. The saving is about 10 lines.
- **Exit:** with the upgrade helpers, not before.

### Mercury indexer: two signer generations

- **What:** `generation: "legacy" | "v1"` and the `expiration_unit: "ledger"`
  handling in `src/indexer/mercury.ts`.
- **Why:** the hosted passkey-indexer returns history across both signer
  generations (legacy `("sw_v1", …)` tuple events and v1 typed events).
- **If removed:** legacy rows parse wrong, and a ledger sequence can be read
  as a UNIX timestamp.
- **Exit:** the indexer filters legacy rows out on its side. This does not
  depend on the upgrade window.

## 2. Not legacy (misleading names)

These are current code. Do not remove them. Fix the names and comments.

- **"Legacy V1 address credentials"** (`src/kit/auth-payload.ts`,
  `src/kit/tx-ops.ts`, `relayer-proxy/src/index.ts`). "V1" is the protocol
  name for the `sorobanCredentialsAddress` XDR arm (CAP-0071). The V1 → V2
  coercion (`toAddressBoundCredentials`) is a security control: it binds the
  wallet address into the signed preimage. The relayer deploy check requires
  V1 because the shared deployer signs its `CreateContractV2` entry with V1
  credentials (`SubmissionManager.signDeploy`). Removing either breaks
  signature binding or deploys.
- **`parseLegacyLookupResponse`** (`src/indexer/mercury.ts`). This is the live
  parser for Ed25519 and policy keys (`/api/lookup/address/…`). Rename it, for
  example to `parseAddressLookupResponse`. It accepts three body shapes
  (`wallets`, `candidates`, `schema: 2`). If the live indexer now sends only
  one shape, the others can go. This was not checked against the live
  indexer.
- **`deriveContractAddress`** (`src/utils.ts`). Its doc comment says
  "legacy account-deployer", but `salt = sha256(keyId)` with the canonical
  deployer is the current derivation. Fix the comment.
- **`CreateWalletResult.signedTx`** (`src/types.ts`). The name stays for API
  compatibility ([migration-v1.md](./migration-v1.md), 0.15.0 section). For
  the shared deployer it is an authorized carrier with no envelope signature.
  For a custom deployer it is a signed envelope. Removing or renaming it
  breaks callers, including the demo (`demo/src/lib/actions.ts`).
- **Counter "legacy caveat" comments** (`ADMIN_COUNT` and `DURABLE_COUNT` in
  `contracts/smart-wallet/src/lib.rs`). `admin_count` and `durable_count`
  return zero when their instance entries are absent. Keep these defaults:
  they keep the signer guards fail-safe. The comments name a pre-1.0 → v1
  upgrade, but that upgrade bricks the wallet (see the 0.13.0 correction in
  [CHANGELOG.md](../CHANGELOG.md)). Reword the caveats to name only cases that
  can happen.

## 3. Removal candidates

### Custom `deploySource` envelope path

- **What:** the non-default-deployer branch at the end of
  `SubmissionManager.signDeploy` (`src/managers/submission-manager.ts`), which
  keeps the old self-source envelope path, and the `restoreKeypair` fallback
  to a custom deployer in the `PasskeyKit` constructor (`src/kit.ts`). The
  code calls it "the pre-existing behaviour".
- **Why it is a candidate:** it runs only when an integrator sets
  `deploySource`. The demo and the relayer do not set it. A custom deployer
  changes every deterministic address relative to the canonical deployer.
  Discovery does not depend on derivation: it uses stored birth records and
  complete indexed candidates (see `README.md`, "Deterministic derivation").
- **If removed:** breaking for any integrator that sets `deploySource`.
- **Options:**
  - Remove `deploySource` completely (largest saving, breaking).
  - Keep `deploySource` but require `restoreSource` with it, and drop the
    fallback (smaller, still breaking for that combination).

### `RelayerClientConfig.adminSecret`

- **What:** a public option in `src/relayer.ts`. `RelayerClient` passes it to
  `ChannelsClient`, which ignores it.
- **If removed:** no runtime change. TypeScript callers that pass it in an
  object literal get a compile error.
- **Also:** the module comment in `src/relayer.ts` names `PluginClientError`.
  The class is `ChannelsClientError`.

### Stale pointers to the July 2026 testnet manifest

- `contracts/Makefile` points to `docs/deployments-testnet-2026-07-11.md` for
  canonical hashes. That file is superseded. Point it to
  [`deployments-2026-09-01.md`](./deployments-2026-09-01.md).
- `.cursorrules` points to the same July file for the derivation tuple. The
  description there is still correct, but a current reference is better:
  `README.md`, "Deterministic derivation".

## Reviewed and kept

- **Dated deployment manifests** (`docs/deployments-*.md`). All three have
  links from `CHANGELOG.md`, and the current one from `README.md`,
  `SECURITY.md`, `docs/releasing.md`, scripts, and the demo env files. The two
  older ones already carry "superseded" banners. Keep them as the record of
  past canonical hashes.
- **CHANGELOG entries for removed code** (Stellar Indexer, `zephyr/`). These
  are history, not code.
