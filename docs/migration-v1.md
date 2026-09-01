# Migrating to `passkey-kit` v1

v1 is a ground-up overhaul of the contract, SDK, and services. It has **no backwards-compatibility layer** — every change below is a clean cut from the `0.12.x` line. If you only ever call `connectWallet()` and submit through `PasskeyServer`, the two changes that will touch your code are the **signing API** (a `Signer` instance instead of an options object) and the **`TransactionResult`** discriminated union.

> [!IMPORTANT]
> **Contract compatibility.** `0.17.0` requires wallets created by the new
> provenance contract. Pre-`0.17.0` wallets remain on-chain, but this SDK does
> not connect to them. This alpha release has no migration or legacy bypass.

## 0.17.0: verified wallet birth and signer provenance

`createWallet` now returns deployment data without storing a wallet record.
Submit the deployment, then call `confirmWalletCreation(created, transactionHash)`.
That call verifies the direct `CreateContractV2` transaction and stores its birth data.

Fresh-device connection now needs `getWalletCandidates` from a schema-2 indexer.
The SDK rejects derivation-only discovery.
It also rejects incomplete, stale, or ambiguous indexer results.

The SDK requires `birthWasmHash`, `creationTransactionHash`, and `creationLedger`.
Hosted Mercury lookup does not return these fields yet.
Fresh-device `connectWallet` fails closed until Mercury deploys schema 2.
Verified local records still connect.
The SDK verifies these claims through RPC or Horizon history.

## 0.15.0: shared deploy and restore sources

Shared-default-deployer wallet creation is now sign-only. `createWallet()` still
returns `signedTx` for API compatibility, but for the shared deployer that value
is an authorized carrier with no usable source or envelope signature.
`PasskeyServer.send(signedTx)` extracts and relays `{ func, auth }`; the relayer
supplies the envelope source, sequence, and fees. Submitting *through
`PasskeyServer.send()`* therefore requires a configured relayer — building does
not. `PasskeyKit` never touches a relayer, so you may extract the carrier's
`{ func, auth }` and submit it through any funded source you control. A custom
`deploySource` keeps the self-sourced signed envelope path.

The sibling smart-account-kit exposes this split as
`relayerPayload: { func, auth }` for shared deployments and an optional
`signedTransaction` for custom deployers only. passkey-kit retains its existing
`signedTx` field; its meaning is the carrier described above, not a guarantee
that the shared deployer signed an envelope.

Footprint restoration now uses a separate funded source:

```ts
const kit = new PasskeyKit({
  rpcUrl,
  networkPassphrase,
  walletWasmHash,
  deploySource,  // address identity; changing it changes derived wallets
  restoreSource, // funded S… key used only for restoreFootprint
});
```

`restoreSource` has no fallback to `deploySource`, and the shared default
deployer is always rejected. Do not rotate `deploySource` to solve restore
funding: the deployer address is part of every wallet's deterministic address
preimage, so rotation changes every derived address and breaks discovery of
existing wallets.

## Contents

- [Signing pipeline](#signing-pipeline)
- [Results & error handling](#results--error-handling)
- [Errors](#errors)
- [Configuration](#configuration)
- [Signer model & expiration](#signer-model--expiration)
- [Storage adapters](#storage-adapters)
- [Indexer & discovery](#indexer--discovery)
- [Packaging & imports](#packaging--imports)
- [Removed exports](#removed-exports)
- [Gap analysis](#gap-analysis)
- [Contract-side changes](#contract-side-changes)
- [Behavior changes](#behavior-changes)

---

## Signing pipeline

**`sign` / `signAuthEntry` now take a typed `Signer` instance** instead of a mutually-exclusive `{ keyId | keypair | policy }` options object.

```ts
// Before (0.12.x)
await kit.sign(txn, { keyId });                    // passkey
await kit.sign(txn, { keypair });                  // Ed25519
await kit.sign(txn, { policy });                   // policy
await kit.sign(txn, { keyId: "any", expiration }); // any passkey + explicit expiration

// After (v1)
import { PasskeySigner, Ed25519Signer, PolicySigner } from "passkey-kit";

await kit.sign(txn);                               // connected passkey (default)
await kit.sign(txn, new PasskeySigner(keyId));     // specific passkey
await kit.sign(txn, new Ed25519Signer(keypair));   // Ed25519
await kit.sign(txn, new PolicySigner(policy));     // policy
await kit.sign(txn, new PasskeySigner("any"), { expiration }); // any passkey + expiration
```

Notes:

- The per-call options object is now just `{ expiration?: number }`. Per-call `rpId` is gone — `rpId` moved to the `PasskeyKit` constructor (a single source of truth).
- `Ed25519Signer.fromSecret("S…")` builds a signer from a secret key (throws `ValidationError` on an invalid key).
- Multi-sign by calling `sign` once per signer; each merges into the flat `Signatures` map, now sorted in Soroban **host order** (was a `localeCompare` approximation that could produce a map the host rejected).

**`sign` takes a single `AssembledTransaction`.** The old `AssembledTransaction | Tx | string` tri-input silently dropped memo/fee/operations on its fallback path. If you hold XDR, rebuild first:

```ts
// Before: await kit.sign(xdrString)
// After:
import { AssembledTransaction } from "@stellar/stellar-sdk/contract";
const txn = AssembledTransaction.fromXDR(options, xdrString, spec);
await kit.sign(txn);
```

## Results & error handling

**`TransactionResult` is now a discriminated union on `success`.** Narrow on `result.success` before reading `.error` or `.hash`.

```ts
// Before (0.12.x): an untyped { success, hash, error? } object; error was a string.
const result = await server.send(txn);
if (result.success) {
  console.log(result.hash);
} else {
  console.error(result.error); // string
}

// After (v1)
const result = await server.send(txn);
if (result.success) {
  // TransactionSuccess: { success: true; hash: string; ledger?; transactionId? }
  console.log(result.hash);
} else {
  // TransactionFailure: { success: false; error: PasskeyKitError; hash? }
  console.error(`[${result.error.code}] ${result.error.message}`);
}
```

- `error` is now a **typed `PasskeyKitError`** (a `ContractError` when an on-chain code was decoded), not a string. Branch on `result.error.code`.
- Success results have **no** `error` field; failure results have an **optional** `hash`.
- New type exports: `TransactionSuccess`, `TransactionFailure`, `SubmissionMethod`.

**Which methods return this vs. throw.** Only submission methods (`server.send`, `server.getTransaction`) return a `TransactionResult`. **Everything else throws** a typed `PasskeyKitError` subclass. A pending (non-terminal) relayer status is surfaced as a failure carrying `RELAYER_PENDING` — keep polling `getTransaction`; do not treat it as success.

## Errors

- All thrown errors are now `PasskeyKitError` subclasses with a numeric `code`: `ConfigurationError`, `WalletNotConnectedError`, `WalletOwnershipError`, `WebAuthnError`, `SigningError`, `SignerNotFoundError`, `SimulationError`, `SubmissionError`, `ValidationError`, `IndexerError`, `RelayerError`, `ContractError`. Codes are grouped by concern (`1xxx`–`9xxx`, `10000` for contract-level).
- **New decoding API:** `decodeContractError(diagnostic)`, `contractErrorFromCode(code)`, `CONTRACT_ERROR_REGISTRY`, and types `ContractErrorFamily` / `ContractErrorInfo`.
- **Contract error codes were renumbered to 100–133** (see [README → Contract error decoding](../README.md#contract-error-decoding)). The legacy 1–9 codes still decode for diagnostics.

```ts
if (!result.success && result.error instanceof ContractError) {
  switch (result.error.contractErrorName) {
    case "SignerExpired": /* 102 */ break;
    case "MissingContext": /* 110 */ break;
  }
}
```

## Configuration

**`PasskeyKit` config** gains `rpId`, `deploySource`, and `storage`:

```ts
// Before
new PasskeyKit({ rpcUrl, networkPassphrase, walletWasmHash, timeoutInSeconds, WebAuthn });

// After
new PasskeyKit({
  rpcUrl, networkPassphrase, walletWasmHash,
  rpId,            // NEW: WebAuthn RP id (was read per sign()/connect() call)
  deploySource,    // NEW: S… secret for the fee payer (default = canonical deployer)
  storage,         // NEW: StorageAdapter for passkey records
  timeoutInSeconds, WebAuthn,
});
```

**`PasskeyServer` config is now nested** (was a flat bag of `relayer*`/`mercury*` keys):

```ts
// Before
new PasskeyServer({
  rpcUrl, relayerUrl, relayerApiKey,
  mercuryProjectName, mercuryUrl, mercuryJwt, mercuryKey,
});

// After
new PasskeyServer({
  networkPassphrase,                                  // NEW: now required
  rpcUrl,
  relayer: { baseUrl, apiKey, adminSecret?, timeout? },
  mercury: { url? },                                  // keyless; url defaults to the network's hosted endpoint
});
```

`networkPassphrase` is required. `relayer.baseUrl`/`apiKey` replace `relayerUrl`/`relayerApiKey`. The old `mercury*` keys (`mercuryProjectName`/`mercuryJwt`/`mercuryKey`) are **gone** — Mercury's hosted passkey-indexer is keyless, so `mercury` is now just an optional `{ url? }` that defaults to the network's hosted endpoint (omit it entirely to use the default).

## Signer model & expiration

- **Expiration is a UNIX timestamp in seconds** (inclusive), not a ledger sequence number. Update any code that computed `latestLedger + N`; use `nowSeconds + N`.
- **`SignerLimits::Some(empty map)` now means fail-closed (no permissions).** Pre-1.0 an empty map meant *unlimited*. If you passed an empty map to mean "unlimited", pass `undefined` instead.
- **Deploy permission is decoupled from limits.** A limits entry for the wallet's own address no longer grants deploy permission; `CreateContract*` contexts require an unlimited (`undefined`-limits) signer. Granting a signer a limits entry for the wallet's own address grants it the full admin surface (it can add an unlimited signer) — treat that as full control.
- **New `upgrade(newWasmHash)` wrapper** (contract `upgrade`, renamed from `update_contract_code`) and **new `getSigner(signerKey)`** read (contract `get_signer`).

## Storage adapters

The kit no longer expects apps to hand-roll `localStorage`. Import an adapter from the new `passkey-kit/storage` subpath and pass it as `storage`:

```ts
import { IndexedDBStorage } from "passkey-kit/storage";
const kit = new PasskeyKit({ /* … */, storage: new IndexedDBStorage() });
```

`confirmWalletCreation` stores a verified passkey and wallet birth record.
`connectWallet` uses that record before it requests indexer candidates.

## Indexer & discovery

- `PasskeyServer.getSigners` returns **`WalletSigner[]`**.
- `PasskeyServer.getWalletCandidates` replaces `getContractId` and `getContractIds`.
- The new method returns a complete lookup with immutable birth claims.
- A `SignerIndexer` abstraction resolved by the keyless `MercuryIndexer` — exported from the main `passkey-kit` entry (browser-safe; no token), alongside the browser-safe types + `lookupWithRetry`.
- Mercury signer enumeration is live through its hosted, **keyless** passkey-indexer.
- As of 2026-09-01, schema-2 reverse lookup is not deployed.
- Fresh-device connection fails closed until the hosted lookup returns complete birth claims.
- `MercuryConfig` is an optional `{ url? }`. Resolve it with `MercuryIndexer.forNetwork(...)`.

## Packaging & imports

- The package now ships **compiled `dist/`** (ESM + `.d.ts`) with an `exports` map. Remove any `transpilePackages: ["passkey-kit", "passkey-factory-sdk", …]` / bundler workaround you added for the old raw-TypeScript shipping.
- `@stellar/stellar-sdk` is a **peer dependency** (`>=16.0.0`) — install it in your app.
- Server-only code moved behind the `passkey-kit/server` subpath. Import `PasskeyServer` from `passkey-kit/server`, not `passkey-kit`, and never from browser code.

```ts
// Before
import { PasskeyKit, PasskeyServer } from "passkey-kit";

// After
import { PasskeyKit } from "passkey-kit";
import { PasskeyServer } from "passkey-kit/server"; // server-only
```

## Removed exports

- **`passkey-factory-sdk`** — never a real package; the factory design it referenced was abandoned before v1. Remove it from imports and bundler config.
- **`PasskeyServer` from the package root** — moved to `passkey-kit/server`.
- **The old indexer row type** (`Signer` / `IndexedSigner`) — **removed**. `PasskeyServer.getSigners` and the `MercuryIndexer` return the richer `WalletSigner` shape (`SignerIndexer` abstraction). The name `Signer` now refers only to the signing-pipeline interface.
- **`StellarIndexerBackend` / `StellarIndexerConfig` / `indexerForConfig`** — removed; `MercuryIndexer` (keyless, both networks) is the one backend. `MercuryIndexer` moved from `passkey-kit/server` to the main `passkey-kit` entry.

## Gap analysis

An explicit accounting of capabilities the pre-1.0 version had that v1 changes or drops — and what to use instead.

| Old capability | v1 status | What to do instead |
|---|---|---|
| `connectWallet({ walletPublicKey })` — resolve/connect a wallet by an Ed25519 `G…` key | **Removed.** `connectWallet` is passkey-ownership-based by design. | Use `server.getWalletCandidates({ publicKey })` for candidate data. Verify each address independently before use. |
| `sign(xdrString \| Tx)` — sign a raw XDR string or `Tx` | **Removed** (lossy fallback). | `AssembledTransaction.fromXDR(...)` first, then `sign(txn)`. |
| Per-call `rpId` on `sign` / `connectWallet` | **Moved to the constructor.** | Set `rpId` once on `new PasskeyKit({ rpId })`. |
| **Signer discovery via Mercury** (`getSigners` / `getWalletCandidates`) | Signer enumeration is live. Schema-2 birth claims are pending. | Use `server.getSigners(contractId)`. Treat an incomplete candidate lookup as unavailable. |
| Legacy `("sw_v1", …)` tuple events | **Replaced** by typed `#[contractevent]` events. | Consume the new `signer_added`/`signer_updated`/`signer_removed`/`upgraded` schema; Mercury's hosted passkey-indexer already does (and still indexes the legacy tuples for older wallets). |
| Raw-TypeScript package (import internal source files) | **Removed** — ships compiled `dist/`. | Use the public entry points (`.`, `./storage`, `./server`). |

The v1 contract and SDK intentionally remove unsupported legacy paths.
Mercury supplies hosted signer enumeration on both networks.
Schema-2 reverse lookup remains pending.

## Contract-side changes

If you build against the contract directly (not just the SDK):

- `__constructor(signer, proof)` is the only init path. Secp256r1 requires `Some(proof)` with the GENESIS purpose.
- Ed25519 and Policy require `None` for `proof`. Every first signer must be a durable admin.
- `update_contract_code` → `upgrade(new_wasm_hash)`; new `get_signer(signer_key) -> Option<SignerVal>` view.
- `SignerExpiration(Option<u64>)` is a UNIX timestamp; `SignerLimits::Some(empty)` is fail-closed; errors use 100–133 with gaps; events are `#[contractevent]` structs; policies gain `install`/`uninstall`.

See the [CHANGELOG](../CHANGELOG.md#contract-smart-wallet-soroban-sdk-27) for the full list and [`contracts/smart-wallet-interface/src/`](../contracts/smart-wallet-interface/src) for the canonical interface.

## Behavior changes

| Situation | Before | After |
|---|---|---|
| Submission failure | `{ success: false, error: string }` | `{ success: false, error: PasskeyKitError }` |
| Any non-submission failure | plain `Error` / failure object | typed `PasskeyKitError` subclass (thrown) |
| `connectWallet` with a keyId not on the wallet | trusted the derived/looked-up address | throws `WalletOwnershipError` unless every birth, code, signer, record, and assertion check succeeds. |
| Empty `SignerLimits` map | unlimited | no permissions (fail-closed) |
| Signer/signature expiration unit | ledger sequence | UNIX timestamp (seconds) |
| WebAuthn challenge | fixed string | random 32 bytes |
| `Signatures` map order | `localeCompare` | Soroban host ScVal order |
| Address auth credentials | V1 | V2 (CAP-0071-02; the wallet address is part of the signed payload). The kit refuses to sign non-address-bound entries. |
| `updateSecp256r1` | `updateSecp256r1(keyId, publicKey, …)` | `updateSecp256r1(keyId, …)` — the public key is re-read from the ledger, never caller-supplied |
