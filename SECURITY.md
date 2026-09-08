# Security Policy

## Security status

The smart-wallet contract, SDKs, and repository relayer proxy have not received an independent third-party security audit.

Tests and reviews reduce risk. They do not prove that the software has no defects.

Do not store or control assets you cannot afford to lose. Limit balances and permissions. Monitor wallets and maintain recovery and authorized upgrade paths.

## Supported versions

Only the latest npm releases and the canonical smart-wallet WASM receive security fixes.

The current [`deployment manifest`](./docs/deployments-2026-09-01.md) identifies the canonical WASM. Existing wallet instances do not upgrade automatically.

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
