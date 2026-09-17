# Upgrading pre-fix legacy wallets

This document is for operators of applications that deployed passkey-kit
smart wallets on mainnet from one of the WASM hashes listed below (the last
such deployment was on 2025-06-29). It explains which deployed wallets
still run vulnerable code, why a naive upgrade bricks some of them, and the
exact in-place upgrade that closes the hole without moving funds or changing
the wallet address.

## The defect

Before commit [`dcc6e3dc9c`](https://github.com/kalepail/passkey-kit/commit/dcc6e3dc9cfd32e64b98f23541cd2d96812b64c4)
(2025-03-27), `update_signer` had no `require_auth`. Anyone who knows a
wallet's signer key (a passkey credential id, an Ed25519 public key, or a
policy address) can overwrite that signer's stored value. For a passkey that
means replacing the public key and taking the wallet over. Signer keys are
public: they appear in the `sw_v1` events and in the passkey indexer.

Wallet instances do not upgrade themselves. A wallet deployed from a pre-fix
WASM keeps that code until its owner calls `update_contract_code`.

## Affected mainnet WASM hashes

| WASM hash | Repo pin | Storage layout | Wallets (2026-09-17) |
|---|---|---|---|
| `0c0a264d4cc0b3e79b8533e2a2e1f0ed21501a5a3f9f2455d2f18c232940b865` | `contracts/Makefile` @ `48bda61` | **bare** | ~829 |
| `19868df3653d427cafa1c30bdb6cec1ca5c8c815eeabab8a8bae6d83efb1fedd` | `contracts/Makefile` @ `42f2b52` | **bare** | 1 |
| `b62f62217ff256d557513793e9e44317b25b14401a8a6b6149a04d38d72d6c7c` | `contracts/Makefile` @ `df5efb8` | wrapped | ~812 |
| `c5509dfa5f022deb8ae621f073adac5fd788feca0b24d15b5f392ab22c2ff222` | not in repo (integrator build) | wrapped | 66 |

Seven other pre-fix hashes appear in repository history but were never
uploaded to mainnet. Do not deploy from any Makefile or `.env` pin older than
commit `da472f9`.

## Two storage layouts

Commit `6a27d48` (2024-12-13) changed how a signer's value is stored:

- **bare**: expiration is a plain `Option<u32>` (`void` or `u32`).
- **wrapped**: expiration is `SignerExpiration(Option<u32>)`, a one-element
  vector.

The signer *key* is identical in both. Every build after `6a27d48`, including
the post-fix legacy builds `ecd990f0…` and `e45c42b9…` and the v1 build
`97ce0478…`, decodes only the wrapped layout. A bare-layout wallet upgraded to
any of them succeeds as a transaction and then fails to decode its own signers
on every subsequent call. The wallet is bricked and its funds are locked.

## The upgrade target

`contracts-legacy/` builds a legacy-line wallet from the last pre-1.0 source
(`e45c42b9…`, commit `aeb04d7`) with two additions:

1. Signer reads accept both layouts. Nothing else about storage, events,
   error codes, or expiration semantics changes.
2. `migrate_signers(keys)` re-encodes listed entries into the wrapped layout,
   and `get_signer(key)` returns a stored entry for verification.

`update_signer` requires authorization, as in every post-fix build.

| Artifact | Value |
|---|---|
| WASM sha256 (`out/smart_wallet.wasm`) | `c079d3a4136eb6ca68eb724acd3d8af11b0be4a0ed82605925a6dfd4dd83a97c` |
| Source | `contracts-legacy/` (soroban-sdk 23.0.2, Rust 1.89, `wasm32v1-none`) |
| Canonical artifact | `contracts-legacy/out/smart_wallet.wasm`, committed. CI asserts its hash and runs the tests against it. Built with Rust 1.89 and stellar CLI 27.1.0 on macOS aarch64. `stellar contract build` remaps source paths, but rustc's wasm codegen differs across host platforms, so a rebuild on another host is functionally equivalent with a different hash. Doc comments on exported functions are embedded in the contract spec, so editing them also changes the hash. |
| Testnet upload | tx `ae5e9439ad044b6c6d3cb491ff6f0e5bd60cfcc1eefbc8a56cc6f1f89b93acaf` |
| Mainnet upload | not yet uploaded |
| Verify / test | `cd contracts-legacy && make verify` / `make test` |

The tests load the real mainnet `0c0a264d…`, `b62f6221…`, and `c5509dfa…`
WASM, create a wallet on each, upgrade it to this build with a real signed authorization,
and check that the hole is closed, the wallet still authorizes, and
`migrate_signers` re-encodes bare entries.

This target is safe for **all four** affected hashes. The v1 WASM is not a
drop-in target for any legacy wallet: it expects UNIX-second expirations,
treats an empty limits map as no permissions, and the v1 SDK does not connect
to wallets born without a constructor.

## Upgrade procedure

Each step is one contract invocation on the wallet, authorized by a signer
that is still valid on that wallet. The wallet address does not change and no
funds move. Because the hole is a race, upgrade funded wallets first.

1. **Restore archived entries.** Three of the four vulnerable code entries are
   archived on mainnet, and many wallet instances and signer entries are too.
   Submit a `RestoreFootprint` operation for the wallet's **current** code
   entry (archived for `0c0a264d…`, `19868df3…`, and `c5509dfa…`; nothing on
   the wallet can run until it is live), the wallet instance, its signer
   entries, and the code entry of the target hash if needed. Restore is
   permissionless and any funded account can pay for it. The legacy SDK line
   has no restore helper; build the operation with `@stellar/stellar-sdk`
   (`Operation.restoreFootprint` plus a simulated footprint).
2. **Upgrade.** Invoke `update_contract_code(c079d3a4…)` on the wallet,
   authorized by an existing signer. The wallet's current code checks the
   authorization, so the signature format is the one that code expects.
3. **Normalize (bare cohort).** Invoke `migrate_signers([keys…])` with every
   signer key the wallet holds. The call needs no authorization; it is a
   value-preserving re-encoding whose only side effect is a TTL extension.
   It returns the number of entries rewritten. It emits no event.
   Signer keys come from the `sw_v1` `add`/`update` events or from the
   hosted passkey indexer.
4. **Verify.** Invoke `get_signer(key)` for each key and confirm the value,
   or check the wallet's code hash on an explorer.

Step 3 is optional for the wrapped cohort (`migrate_signers` returns 0) and
recommended for the bare cohort, so that the wallet can later move to a
strict build if its operator chooses to.

### With the stellar CLI

```bash
# once per network: upload the code. As of 2026-09-17 it is on testnet only.
stellar contract upload --wasm contracts-legacy/out/smart_wallet.wasm \
  --source <funded-key> --network mainnet

# per wallet: update_contract_code needs the WALLET's own authorization, which
# is a Signatures map inside a Soroban auth entry checked by the wallet's
# __check_auth. The CLI cannot produce that map: --source is only the
# fee-paying envelope source. Build and sign the update_contract_code call
# from an application (see "From an application" below). The two calls
# below need no wallet authorization and work from the CLI:
stellar contract invoke --id <WALLET> --source <any-funded-key> --network mainnet \
  -- migrate_signers --signer_keys '[{"Secp256r1":"<credential-id-hex>"}]'

stellar contract invoke --id <WALLET> --source <any-funded-key> --network mainnet \
  -- get_signer --signer_key '{"Secp256r1":"<credential-id-hex>"}'
```

### From an application

Wallet authorizations are produced by the client. For a passkey signer that
means the browser. Use the last legacy SDK line (`passkey-kit` `0.10.20`
through `0.12.x`) to connect to the wallet, build a transaction that invokes
`update_contract_code` with the hash above, sign it with the passkey (or
with an Ed25519 signer key the wallet holds), and submit it through your
relayer or a funded source. The current SDK (`0.17.0` and later) does not
connect to these wallets and cannot be used for this step.

## What the current kit does with a legacy wallet

`passkey-kit` `0.19.0` and later cannot operate a pre-1.0 wallet, but it
recognizes one. `connectWallet` throws `LegacyWalletError` (code `2006`)
before birth verification when a candidate's current code is one of the
four vulnerable hashes or a patched legacy build. The error's `vulnerable`
flag, `upgradeTarget`, and `guideUrl` fields carry this document's guidance,
and its message says what to do. The constructor also refuses a
known-vulnerable `walletWasmHash`, so no new wallet can be deployed from one.
Perform the upgrade itself with the 0.10.20–0.12.x kit line.

## Client compatibility after the upgrade

- Applications on the wrapped-era SDK (`0.10.20` through `0.12.x`) keep
  working unchanged on both cohorts after the upgrade.
- Applications still on a bare-era SDK (`passkey-kit` releases before `0.10.7`, 2024-12-13) keep
  signing transactions after the upgrade, because a signature map entry
  encodes the same way in both eras. Their `add_signer` and `update_signer`
  calls send the bare argument shape, which the upgraded wallet rejects.
  Move those applications to a wrapped-era SDK for signer management.
- A bare-era client that signs with a policy signer sends `void` where the
  upgraded wallet expects `Signature::Policy`. Such calls fail after the
  upgrade. Move that client to a wrapped-era SDK.
- The reverse holds before the upgrade: a bare-layout wallet whose only
  usable signer is a policy must authorize the upgrade with a bare-era
  signature map (`void` for the policy entry), because the old code has no
  `Signature::Policy` variant. Passkey and Ed25519 signatures encode the
  same way in both eras and need no special handling.

## Boundaries

- A wallet whose only signers have expired, or whose only signers were
  temporary entries that the network has since evicted, cannot authorize the
  upgrade. Nothing can be done for it now; an expired-but-present entry stays
  writable through the old bug until the wallet is upgraded, so such a wallet
  should have been drained while a signer was still valid.
- A constructor-less wallet that was created but never received its first
  `add_signer` has no signers and is not exploitable through `update_signer`.
  Its first `add_signer` needs no authorization on every legacy build,
  including this one. Do not fund such a wallet.

## What was not done

- The v1 line is unchanged. Moving a legacy wallet to v1 is a separate,
  future migration that needs SDK support for constructor-less births.
- No wallet was upgraded by the maintainers. Owners and application operators
  authorize upgrades; the shared deterministic deployer cannot.
