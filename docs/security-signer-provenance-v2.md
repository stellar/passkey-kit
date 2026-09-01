# Constructor-only Secp256r1 signer provenance

Status: implemented in `passkey-kit@0.17.0` and smart-wallet `binver = 1.1.0`.
The hosted Mercury schema-2 response remains pending on 2026-09-01.
This design supersedes the factory design and all migration designs.
It does not replace deployer hardening in `mainnet-hardening.md`.

## Security goal

An untrusted wallet candidate must not become the connected wallet.
The check must survive arbitrary birth code and a later upgrade to accepted code.
The check must also separate a copied credential id from the real passkey.
The design must prevent unverified wallet binding and fund redirection.

## Threat facts

The shared deployer secret is public.
Anyone can deploy any WASM at an unused derived address.
The address preimage is the network, the deployer address, and `sha256(keyId)`.
A credential id is opaque and does not bind a public key.
Pending deployment data is public.
Current wallet code can differ from wallet birth code.
Signer state alone does not prove wallet birth.
A third party cannot produce a signature from the user's passkey.

## Design overview

The product uses direct `CreateContractV2` and `__constructor`.
It does not use a factory contract.
The salt stays `sha256(keyId)`.
All existing address vectors stay valid.
Pre-release wallets are unsupported in this release.
No existing-wallet migration exists.

## Proof domains

The wallet uses two separate proof domains.
`GENESIS` covers the constructor signer.
`ADD` covers each later Secp256r1 signer.
The domain is a field inside the signed payload.
A proof from one domain never verifies in the other.

Each proof commits to four inputs.
The inputs are the network, the wallet address, the purpose domain, and the full original Signer.
The full original Signer covers the key id, public key, limits, expiration, and storage.
This commitment stops a relayer or a front-runner from altering the signer policy.
The challenge is `sha256(XDR(payload))`.
The WebAuthn assertion carries the base64url challenge.

## Constructor requirements

`__constructor(signer, proof)` is the only init path.
A Secp256r1 signer requires `Some(proof)` with the GENESIS purpose.
An Ed25519 or Policy signer requires `None` for `proof`.
A failed constructor aborts the deployment transaction.
The failed deployment does not occupy the contract address.
The first signer must be a durable admin.

## add_secp256r1

`add_secp256r1(signer, proof)` requires wallet authorization and an ADD proof.
The ADD proof commits to the full added Signer.
`add_signer` rejects Secp256r1 signers.
It still accepts Ed25519 and Policy signers.

## Binding record

The constructor and `add_secp256r1` store a `Secp256r1BindingRecord`.
The record keeps the original Signer, the purpose, and the proof bytes.
The record uses the same durability as its signer.
`update_signer` moves the record with a durability change.
`remove_signer` deletes the record.
The SDK never trusts the record because the contract wrote it.
The SDK re-verifies the proof bytes itself.

The SDK compares the record against the live signer by identity only.
Identity means the key id and the public key.
Limits, expiration, and storage may change after consent.
The SDK recomputes the challenge from the record's original Signer, not the live entry.
This rule keeps the record valid across authorized administration.

## Candidate verification

The SDK treats verified storage and the indexer as candidate sources.
Indexer fields are claims.
The SDK never accepts a claim without verification.
The SDK captures the RPC latest ledger before the lookup.
The response `indexedThroughLedger` must be at or above that floor.
A complete but stale response fails closed.
The SDK applies these checks to every untrusted candidate:

1. Birth verification. See the next section.
2. The current wallet WASM hash is in `acceptedWasmHashes`.
3. The credential id identifies a live Secp256r1 signer.
4. The binding record matches the live signer by identity.
5. The purpose-specific stored proof verifies for the candidate address and network.
6. A fresh targeted assertion verifies under the live signer public key.
7. Exactly one candidate passes every check.

Zero passing candidates fail closed.
Two or more passing candidates raise `WalletAmbiguousError`.

## Birth verification

Birth verification is required.
Current code does not prove which code created a wallet.
The creation transaction supplies the immutable birth evidence.

The indexer returns `birthWasmHash`, `creationTransactionHash`, and `creationLedger` per candidate.
These fields are claims.
The SDK verifies them through Stellar RPC:

1. Fetch `creationTransactionHash` with `getTransaction`.
2. Recompute the transaction hash from the returned envelope.
3. Compare the recomputed hash with `creationTransactionHash`.
4. Confirm the transaction succeeded at `creationLedger`.
5. Confirm the transaction created the candidate address.
6. Confirm the operation is a direct `CreateContractV2`.
7. Confirm the birth WASM hash is in `acceptedBirthWasmHashes`.

A valid wallet can upgrade after birth.
Therefore, `acceptedBirthWasmHashes` and `acceptedWasmHashes` stay separate.

RPC retention can expire a transaction.
The SDK then fetches the same transaction through configured Horizon history.
It recomputes and verifies the hash the same way.
A transaction that fails any check disqualifies the candidate.
A transaction the SDK cannot fetch disqualifies the candidate.

The birth check runs before the stored-proof check.
A candidate with accepted birth code still needs every later check.

## Local storage

Local storage contains only birth data that the SDK already verified.
The adapter stores `birthWasmHash`, `creationTransactionHash`, and `creationLedger` after verification.
A stored row without verified birth data is not trusted.
A stored candidate passes through the same verification pipeline.
Local trust never skips a check.

## What this design does not do

No derivation-only connection exists.
Derivation supplies a candidate address, never proof of birth.
A candidate without verified birth data cannot connect.
Local storage counts only after `confirmWalletCreation` or a prior verified connection.
No `allowUnverifiedLegacy` flag exists.
No `bind_secp256r1` path exists.
No existing-wallet migration exists for this release.
Pre-release wallets cannot pass the accepted-birth check.

## Residual risks

Address occupancy remains a denial-of-service risk.
Anyone can occupy an unused derived address with the public deployer.
The victim's own deployment then fails visibly.
The victim can recover with a new credential.
Blind sends to `derive(keyId)` remain unsafe.
A sender must use a verified wallet address.
Same-`rpId` phishing remains possible when the origin policy is wide.
Consent for the wrong wallet remains valid consent.

## Component status

1. The contract changes are complete.
2. The canonical WASM and TypeScript bindings are published.
3. `passkey-kit@0.17.0` includes the security checks.
4. `passkey-kit@0.17.1` supports the additive dual-field indexer rollout.
5. The demo and relayer use the canonical WASM.
6. The hosted indexer still needs the schema-2 response.

Fresh-device recovery works only after step 6.
The indexer must deploy the new response before that recovery works.

## Required tests

Contract tests cover:

- a correct GENESIS proof succeeds and stores a record;
- a missing, foreign-domain, foreign-address, foreign-network, or foreign-key proof fails;
- an altered initial Signer fails the proof;
- a non-durable genesis admin fails;
- `add_secp256r1` requires an ADD proof for the full added Signer;
- `add_signer` rejects Secp256r1;
- updates move the record and never change the key or public key;
- removal deletes the record;
- re-add requires a fresh ADD proof.

Client tests cover:

- one real candidate passes all checks and connects;
- an unaccepted birth address fails the birth check;
- a post-birth code change does not replace the birth check;
- a mismatched public key fails the fresh assertion;
- altered initial limits fail the constructor proof;
- incomplete indexer data fails closed;
- two valid candidates raise `WALLET_AMBIGUOUS`;
- a stored row without verified birth data is rejected;
- an old response shape fails closed.
- a complete but stale response fails closed.

The WASM integration test must deploy through `deploy_v2`.
It must not mock the constructor path.

## Failure behavior

Missing fields fail closed.
Incomplete scans fail closed.
Old response shapes fail closed.
Stale responses fail closed.
Unverifiable creation transactions fail closed.
Transport errors fail closed.
Every failure leaves the kit disconnected.

## Indexer response contract

The indexer response must include `complete`, `indexedThroughLedger`, and candidates.
Each candidate must include `contractId`, `birthWasmHash`, `creationTransactionHash`, and `creationLedger`.
See `indexer-signer-provenance-response.md` for the full contract and tests.

Compact example:

```json
{
  "schema": 2,
  "complete": true,
  "indexedThroughLedger": 5440001,
  "candidates": [
    {
      "contractId": "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ",
      "birthWasmHash": "ab3f…64-hex…9c",
      "creationTransactionHash": "e4d1…64-hex…07",
      "creationLedger": 5432100
    }
  ]
}
```

The `schema` field marks the response version.
A response without it is an old shape and fails closed.

## getWalletCandidates callback

The SDK replaces the `getContractId` callback with `getWalletCandidates`.
The exact shape:

```ts
interface WalletCandidate {
  contractId: string;
  birthWasmHash: string;
  creationTransactionHash: string;
  creationLedger: number;
}

type IncompleteWalletCandidate = Partial<WalletCandidate> & {
  contractId: string;
};

type WalletCandidateLookup =
  | {
      schema: 2;
      complete: true;
      indexedThroughLedger: number;
      candidates: WalletCandidate[];
    }
  | {
      schema?: number;
      complete: false;
      indexedThroughLedger?: number;
      candidates: IncompleteWalletCandidate[];
    };

type GetWalletCandidates = (
  keyId: string
) => Promise<WalletCandidateLookup>;
```

An application omits the callback when the network has no indexer.
The SDK validates the response shape before use.
The SDK rejects the incomplete variant before candidate verification.
The SDK treats every field as a claim and verifies it.

The SDK captures the latest RPC ledger before it starts the lookup.
The response must cover that ledger without gaps.
A complete but stale response fails closed.
