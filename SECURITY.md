# Security Policy

## Security status

The smart-wallet contract, SDKs, and repository relayer proxy have not received an independent third-party security audit.

Tests and reviews reduce risk. They do not prove that the software has no defects.

Do not store or control assets you cannot afford to lose. Limit balances and permissions. Monitor wallets and maintain recovery and authorized upgrade paths.

## Supported versions

Only the latest npm releases and the canonical smart-wallet WASM receive security fixes.

The current [`deployment manifest`](./docs/deployments-2026-09-01.md) identifies the canonical WASM. Existing wallet instances do not upgrade automatically.

## Known-vulnerable wallet WASM hashes

Wallets deployed from the following mainnet WASM hashes run code in which `update_signer` has no authorization check. Anyone who knows a signer key can overwrite that signer. The defect was fixed in source in commit [`dcc6e3dc9c`](https://github.com/kalepail/passkey-kit/commit/dcc6e3dc9cfd32e64b98f23541cd2d96812b64c4) on 2025-03-27. Deployed wallets keep the old code until their owner upgrades them.

| WASM hash | Storage layout |
|---|---|
| `0c0a264d4cc0b3e79b8533e2a2e1f0ed21501a5a3f9f2455d2f18c232940b865` | bare (pre-`6a27d48`) |
| `19868df3653d427cafa1c30bdb6cec1ca5c8c815eeabab8a8bae6d83efb1fedd` | bare (pre-`6a27d48`) |
| `b62f62217ff256d557513793e9e44317b25b14401a8a6b6149a04d38d72d6c7c` | wrapped |
| `c5509dfa5f022deb8ae621f073adac5fd788feca0b24d15b5f392ab22c2ff222` | wrapped (not built from this repo) |

Do not deploy new wallets from these hashes, or from any Makefile or `.env` pin older than commit `da472f9`.

Upgrade affected wallets in place to the legacy-line build `c079d3a4136eb6ca68eb724acd3d8af11b0be4a0ed82605925a6dfd4dd83a97c`, built from [`contracts-legacy/`](./contracts-legacy). It reads both storage layouts. The earlier post-fix builds `ecd990f0…` and `e45c42b9…` and the v1 build read only the wrapped layout and brick a bare-layout wallet. See [`docs/legacy-wallet-upgrade.md`](./docs/legacy-wallet-upgrade.md) for the procedure.

Move funds out of any affected wallet you do not intend to upgrade.

The current SDK refuses to deploy from these hashes and throws `LegacyWalletError` with the upgrade guidance when `connectWallet` meets a wallet running one of them.

## Cargo advisory status

The lockfile retains `serde_with@3.14.0` and its inactive `time@0.3.41` optional dependency.

The `serde_with` advisory affects `KeyValueMap` serialization. The repository does not use that adapter.

The `time` package is not in the active dependency graph for any target. `cargo tree --target all -i time@0.3.41` returns no path.

Updating either lock entry also updates compile-time serialization packages. That change produces a different smart-wallet WASM hash without a contract source change.

The canonical hash remains `97ce047884106b1c6c3bb40b8973cc48db1c4dad95c9e20462bf2c701daa764e`. A future contract release must update these packages and publish a reviewed replacement hash together.

`cargo audit` also reports the unmaintained `paste@1.0.15` package and the yanked `spin@0.9.8` package.

Both packages enter through native Soroban host testing dependencies. Neither package is in the `wasm32v1-none` contract dependency graph.

## Secret scanning

The secret scanner recognizes only public contract identifiers, published hashes, generated bundles, and test placeholders.

Exact fingerprints isolate removed demo credentials from 2024. Their tokens are expired, and their public accounts do not exist on current public networks.

Treat every credential in repository history as compromised. Do not reuse it.

## Report a vulnerability privately

Do not open a public issue, pull request, discussion, or chat message for a suspected vulnerability.

Email `tyler@stellar.org` with the subject `passkey-kit security report`. If email is unsuitable, request a private channel without including sensitive details.

Include the affected version or commit, impact, reproduction steps, and a minimal proof of concept. Do not include secrets or personal data.

Use local tests or isolated test accounts. Do not test against public user wallets or move assets that you do not own.

The maintainers will confirm receipt, investigate the report, prepare a fix, and coordinate disclosure with the reporter.
