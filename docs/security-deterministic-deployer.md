# Deterministic deployer security model

The shared deterministic deployer is intentional.
Its published seed makes a wallet address reproducible.
The network, deployer address, and credential-derived salt determine that address.

The deployer is never a wallet signer.
It cannot authorize wallet operations or move wallet funds.

## Sign-only deployment

The shared deployer can sign a `CreateContractV2` Soroban authorization entry.
It never supplies a transaction source, sequence number, or fee.
It never signs the transaction envelope.

`createWallet()` returns an authorized carrier in `signedTx`.
`PasskeyServer.send()` extracts its `{ func, auth }` data.
A relayer supplies the envelope source, sequence number, and fee.

A custom `deploySource` keeps the separate self-sourced path.
Changing `deploySource` changes every derived wallet address.

`restoreFootprint` uses a separate funded `restoreSource`.
It never uses the shared deployer as a transaction source.

The shared sign-only path has these testnet validation transactions:

- passkey-kit: `60e51c9c14c9c3f664c0f69c56179e9a677cd3e9137e74fb6a4ed1a176c63869`
- smart-account-kit: `1de0c40e61504ecfcb630e2ef5ac033c18df157da781a6d4c6a16a7c6fc33f08`

In each transaction, another funded account supplied the envelope source and fee.
The shared deployer signed only the address authorization.
The deployed contract matched the derived address.

## Sequence and balance limits

The project will not set the shared deployer sequence to `INT64_MAX`.
Older clients still use that account sequence.
This change would break those clients.

`INT64_MAX` prevents the account from supplying a valid next transaction sequence.
It does not stop Soroban address authorization.
Soroban authorization uses address credentials and an authorization nonce.

The public key can still authorize classic operations that meet its threshold.
Never fund the shared deployer.

The current mainnet deployers use `auth_immutable` and thresholds `1/2/3`.
Each deployer has one signer with weight `2`.
This blocks high-threshold signer changes and account merge.
It does not protect the balance from medium-threshold payments.

## Address occupancy

The contract address does not bind the WASM hash or constructor arguments.
Anyone can use the public deployer to occupy an unused derived address.

A normal registration does not publish a new credential id before deployment.
However, a deployment publishes that credential id.
The same credential can then expose unused addresses on other networks.

A secondary credential creates a permanent same-network case.
Only the first credential salts the real wallet deployment.
`derive(keyId_2)` is not the real wallet address.

Do not use `derive(keyId)` alone as a deposit address.
It is a candidate address, not an ownership proof.

## Constructor-only signer provenance

The product deploys wallets through direct `CreateContractV2` and `__constructor`.
It does not use a factory contract.
The salt stays `sha256(keyId)`.
All existing address vectors stay valid.

`__constructor` requires a WebAuthn GENESIS proof for a Secp256r1 first signer.
The proof commits to the network, the wallet address, the purpose, and the full original Signer.
The full original Signer covers key id, public key, limits, expiration, and storage.
The constructor verifies the proof before it writes the signer entry.
It stores the original Signer, the purpose, and the proof as a `Secp256r1BindingRecord`.
The constructor also requires at least one durable admin.

`add_secp256r1` requires wallet authorization and an ADD proof.
The two domains never interchange.
`add_signer` rejects Secp256r1 signers.

`connectWallet` treats verified storage and indexer results as candidates.
Indexer fields are claims.
The SDK verifies every untrusted candidate in this order:

1. Birth verification through the creation transaction.
2. The current WASM hash is in `acceptedWasmHashes`.
3. The credential id identifies a live Secp256r1 signer.
4. The binding record matches the live signer by identity.
5. The purpose-specific stored proof verifies for the candidate address.
6. A fresh assertion verifies under the live public key.
7. Exactly one candidate passes every check.

Birth verification is load-bearing.
Evil birth code can copy a pending constructor proof, add an attacker, and then upgrade.
The copied proof, signer, and fresh assertion then all agree.
The SDK fetches the creation transaction through Stellar RPC.
It recomputes the transaction hash from the envelope.
It confirms the birth WASM hash is in `acceptedBirthWasmHashes`.
It also confirms success, ledger, candidate address, and direct `CreateContractV2`.
It uses configured Horizon history after RPC retention expires.
The SDK stores birth data locally only after this verification.
The SDK captures the latest RPC ledger before an indexer lookup.
The response must cover that ledger without gaps.
A complete but stale response fails closed.

The stored proof rejects forged state from custom birth code.
The birth check rejects a copied constructor proof at custom birth code.
The fresh proof rejects an attacker key under a copied credential id.
The SDK connects only when exactly one candidate passes every check.

Code identity alone does not prove signer provenance.
A signer getter alone does not prove signer provenance.
A binding record alone does not prove signer provenance.
The birth check and the two WebAuthn proofs supply the missing evidence.

This design closes the reported SDK wallet-binding and fund-redirection path.
Pre-release wallets are unsupported in this release.
No `allowUnverifiedLegacy` flag exists.
No `bind_secp256r1` migration exists.
No derivation-only connection exists.
A candidate without verified birth data cannot connect.

See [`security-signer-provenance-v2.md`](./security-signer-provenance-v2.md) for the complete design.

Operational verification uses [`mainnet-hardening.md`](./mainnet-hardening.md).
The `scripts/check-mainnet-deployer.mjs` command fails when the geometry changes.

## Deployer inventory

| Generation | Derivation | Address | State / action |
|---|---|---|---|
| Current smart-account-kit | `sha256("openzeppelin-smart-account-kit")` seed | `GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N` | Shared sign-only identity; do not fund or rotate. |
| Current passkey-kit | `sha256("kalepail")` seed | `GC2C7AWLS2FMFTQAHW3IBUB4ZXVP4E37XNLEF2IK7IVXBB6CMEPCSXFO` | Shared sign-only identity; do not fund or rotate. |
| Legacy passkey-kit mainnet, before `23597d8` | `sha256(mainnet network passphrase)` seed | `GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7` | Locked: master weight `0`; cannot sign. |
| Legacy passkey-kit testnet, before `23597d8` | `sha256(testnet network passphrase)` seed | *(withheld; see the internal operations tracker)* | Superseded and testnet only. Track it for retirement. |

Changing a deployer changes every wallet address in that namespace.
Keep legacy identities in discovery and migration logic.
Use `restoreSource` for footprint fees.

## Operational follow-ups

These tasks are not SDK defects.
They reduce testnet operational risk.

- Harden the testnet deployers after every network reset.
- Make provisioning fail when a deployer account has unsafe thresholds.
- Do not let the relayer fund a shared deployer.
- Sweep or retire every superseded testnet deployer.
