# Security coordination: passkey wallet candidate ambiguity and signer provenance

## Distribution

Please treat this document as private security coordination.

Do not publish the vulnerability details before the coordinated release.

## Requested action

We need the indexer to return every wallet candidate for one Secp256r1 credential ID.

The indexer must not select a candidate.

The indexer must confirm current signer state through Stellar RPC.

The indexer must return birth data for each candidate.

The indexer must mark incomplete scans.

The SDK performs the final cryptographic verification.

This change supports an urgent SDK and smart-wallet security update.

## Executive summary

The current wallet lookup can return more than one wallet for one credential ID.

One wallet can be the real wallet.

Another wallet can be an attacker-controlled squat.

The squat can run the accepted smart-wallet WASM.

The squat can also contain a live signer with the victim credential ID.

Therefore, a WASM check and a signer lookup cannot prove wallet ownership.

The old constructor creates this gap.

The old constructor writes the first signer without proof from that signer.

An attacker can create genuine signer state under accepted code.

An indexer can report that state accurately and still return an unsafe candidate.

The problem does not require false indexer data.

The problem comes from incomplete ownership evidence.

## Affected user path

The strongest attack path uses a secondary passkey.

A user first creates a wallet with a primary passkey.

The user later adds a secondary passkey to the same wallet.

The secondary credential ID becomes public through contract state and events.

The real wallet address does not derive from the secondary credential ID.

Therefore, `derive(secondaryKeyId)` remains unused by the real wallet.

An attacker can deploy a contract at that unused address.

The public shared deployer permits this deployment.

The attacker can deploy the accepted wallet WASM.

The old constructor lets the attacker select the first signer without signer authorization.

The attacker can retain an unlimited signer on the squat.

The attacker can also install the victim credential data on the squat.

Both wallets can then contain the same credential ID.

Both wallets can pass a current WASM hash check and a live signer lookup.

A fresh device has no trusted local wallet mapping.

The device can then receive the squat from the indexer.

The SDK can display the squat as the user wallet.

Funds sent to that address enter the attacker-controlled wallet.

## Why indexer ordering cannot prove ownership

The lookup response has an order.

That order does not have a security meaning.

The first row is not necessarily the real wallet.

Creation time also does not prove ownership.

The derived address does not prove ownership.

The public deployer lets an attacker occupy that address.

The accepted WASM hash does not prove ownership by itself.

Custom birth code can upgrade to the accepted WASM.

A live signer entry does not prove ownership either.

The indexer must therefore return candidates without choosing an owner.

## Immediate indexer containment

### 1. Return every candidate

Return one row per wallet that lists the credential ID.

Never return only the first match.

Never drop a candidate because another candidate exists.

Never drop a candidate because it matches the derived address.

### 2. Confirm current signer state

Check live signer state through Stellar RPC before you return a candidate.

Reject rows whose signer is removed, expired, or evicted.

Record the ledger you used for confirmation.

### 3. Report ambiguity explicitly

Set `complete = false` when a scan cannot finish.

Set `indexedThroughLedger` to the highest ledger your scan covered.

Serve a current `indexedThroughLedger` on every request.

Never replace an incomplete scan with an empty result.

### 4. Return birth data

Return `birthWasmHash`, `creationTransactionHash`, and `creationLedger` for each candidate.

Take these values from the transaction that created the contract.

Do not guess or reconstruct them from current state.

A candidate without complete birth data is still a candidate.

Return it. The SDK will fail it closed.

## Complete mitigation

The complete mitigation uses the contract, the SDK, and the indexer together.

The production design does not use a factory contract.

It keeps the existing shared account deployer.

It keeps `salt = sha256(keyId)`.

It uses `__constructor` directly.

### Proof domains

The wallet uses two proof domains.

`GENESIS` covers the constructor signer.

`ADD` covers each later Secp256r1 signer.

A proof from one domain never verifies in the other.

Each proof commits to the network, the wallet address, the purpose, and the full original Signer.

The full original Signer covers key id, public key, limits, expiration, and storage.

A relayer or a front-runner cannot alter the signer policy without breaking the proof.

### Constructor proof

The new constructor receives `signer` and `proof`.

The constructor verifies the GENESIS proof before it writes signer state.

A failed proof aborts the deployment transaction.

The failed deployment does not occupy the contract address.

The constructor also requires at least one durable admin.

A durable admin is a Persistent signer with no expiration.

### Later passkey additions

`add_secp256r1` requires wallet authorization and an ADD proof.

The generic `add_signer` rejects Secp256r1 signers.

No `bind_secp256r1` function exists.

No migration path exists in this release.

### SDK verification

The SDK treats every indexer field as a claim.

The SDK verifies birth data first:

1. Fetch `creationTransactionHash` through Stellar RPC.
2. Recompute the transaction hash from the envelope.
3. Confirm success, `creationLedger`, and the candidate address.
4. Confirm a direct `CreateContractV2` operation.
5. Confirm the birth WASM hash is in `acceptedBirthWasmHashes`.

RPC retention can expire a transaction.

The SDK then uses configured Horizon history.

It recomputes and verifies the hash the same way.

The SDK checks the current WASM hash against `acceptedWasmHashes`.
It then checks the live signer and the binding record.

The SDK re-verifies the purpose-specific stored proof itself.

The SDK also requests a fresh WebAuthn assertion.

The SDK connects only when exactly one candidate passes every check.

### Why the birth check is load-bearing

Evil birth code can copy a pending constructor proof.

It can add an attacker signer and then upgrade to accepted code.

The copied proof, the copied signer, and the fresh assertion then all agree.

Only the creation transaction distinguishes that wallet from the real wallet.

The birth data plus RPC verification supplies that distinction.

## Requested response shape

The endpoint must serve a versioned candidate response.

The response must include these fields:

- `schema`
- `complete`
- `indexedThroughLedger`
- `candidates[].contractId`
- `candidates[].birthWasmHash`
- `candidates[].creationTransactionHash`
- `candidates[].creationLedger`

This shape is the contract:

```json
{
  "schema": 2,
  "complete": true,
  "indexedThroughLedger": 5440001,
  "candidates": [
    {
      "contractId": "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ",
      "birthWasmHash": "64-character-lowercase-hex",
      "creationTransactionHash": "64-character-lowercase-hex",
      "creationLedger": 5432100
    }
  ]
}
```

Optional evidence fields may accompany each candidate.

Optional fields include the live signer public key, signer status, and the binding record bytes.

Optional fields are evidence only.

The SDK verifies every security-sensitive claim through RPC.

## Fail-closed rules

The SDK rejects the whole response when:

- `schema` is missing or not `2`;
- `complete` is missing or `false`;
- `indexedThroughLedger` is missing;
- `indexedThroughLedger` is below the SDK freshness floor;
- a candidate misses any required birth field;
- a birth field has a malformed value.

The SDK rejects a candidate when its creation transaction:

- cannot be fetched through RPC or Horizon history;
- does not match the recomputed transaction hash;
- did not succeed;
- did not create the candidate address;
- does not use a direct `CreateContractV2`;
- did not deploy a WASM hash in `acceptedBirthWasmHashes`.

A rejected response leaves the kit disconnected.

The application shows a discovery failure, never an unverified wallet.

## Freshness rule

The SDK captures the latest RPC ledger before it starts the lookup.
That ledger becomes the freshness floor for the response.
The response must cover that ledger without gaps.
The SDK rejects a response below that floor.
A complete but stale response fails closed.
This rule prevents a complete response from hiding a recently created candidate.

## API behavior requirements

The API must return deterministic JSON fields.

The API ordering must remain informational only.

The API must return a stable contract ID for each candidate.

The API must expose its indexed ledger position.

The API must serve a current indexed ledger position on every request.

The API must identify incomplete results.

The API must not replace an incomplete result with an empty result.

The API must not cache a live signer result beyond its safe freshness window.

The API must invalidate signer state after removal events.

The API must still confirm temporary signer state through RPC.

The API must serve the versioned response on the same lookup routes.

The old response shape must remain available for old clients during rollout.

The old shape must never satisfy the new SDK.

## Rollout ordering

### Phase 1: indexer release

Add the versioned response with birth fields and completeness.

Remove every first-result selection.

Confirm live signer state through RPC.

Keep the old response shape for old clients during the transition.

Fresh-device recovery starts working only when this phase deploys.

### Phase 2: contract release

Upload the new smart-wallet WASM.

Publish its canonical hash.

Regenerate the TypeScript bindings from that exact WASM.

Update `walletWasmHash` and `acceptedWasmHashes`.

Create new wallets with the GENESIS proof.

The constructor requires a durable admin.

### Phase 3: SDK release

Release the candidate-array lookup with birth verification.

Remove the `allowUnverifiedLegacy` flag.

Remove the `bind_secp256r1` path.

Reject every candidate that fails any check.

Pre-release wallets are unsupported in this release.

### Phase 4: application update

Update the demo and applications to `getWalletCandidates`.

Remove all legacy flags from application code.

## Required indexer tests

Test a credential with one real wallet.

Return one candidate with complete birth data.

Test a credential with one real wallet and one squat.

Return both candidates with their own birth data.

Test a removed signer event.

Do not return the removed signer as live.

Test an expired signer.

Do not return the expired signer as live.

Test an evicted temporary signer.

Confirm eviction through RPC.

Test an RPC timeout for one candidate.

Return an incomplete result or fail the request.

Do not return a complete empty result.

Test duplicate indexer rows for one contract.

Return one deduplicated candidate.

Test two valid wallets for one credential.

Return both candidates.

Test a partial scan.

Set `complete = false` and keep the candidates.

Test a stale scan with `indexedThroughLedger` below the RPC latest ledger.

The SDK rejects the response even when `complete = true`.

Serve a fresh ledger value on every request.

Test a candidate with an unknown creation transaction.

Return the candidate with `complete = false` for the response, or omit the scan section for that candidate and mark incompleteness.

Never invent birth data.

Test the old client shape.

Keep it byte-compatible during rollout.

Test the new shape against the fail-closed rules.

Every required field must appear.

## Monitoring requirements

Count credential IDs with more than one candidate.

Count candidates with missing birth data.

Count responses with `complete = false`.

Count responses rejected as stale by the SDK freshness floor.

Count RPC confirmation failures.

Count removed or evicted rows rejected during confirmation.

Count SDK ambiguity errors when application telemetry provides them.

Do not log private keys or authenticator secrets.

Credential IDs and public keys already exist on-chain.

Treat them as security-sensitive identifiers in operational logs.

## What the indexer cannot solve alone

The indexer cannot prove ownership from an event alone.

The indexer cannot prove ownership from the current WASM hash alone.

The indexer cannot prove ownership from signer presence alone.

The indexer cannot make response ordering secure.

The indexer cannot prevent address occupancy by the public deployer.

The indexer cannot protect SDK flows which bypass the indexer.

The indexer can preserve every candidate and expose birth evidence.

The SDK and contract must verify the cryptographic binding.

## Remaining risk after this mitigation

The public deployer still permits address occupancy.

An attacker can still occupy an unused derived address.

The victim's own deployment then fails visibly.

That outcome is a denial-of-service problem.

The SDK rejects occupied addresses without valid victim proofs and verified birth data.

Therefore, the reported fund-redirection path closes.

Blind sends to `derive(keyId)` also remain unsafe.

A sender must use a verified wallet address.

Only deployer control can prevent all occupancy in this namespace.

This mitigation does not add that control.

## Acceptance criteria

The indexer serves the versioned response with all required fields.

The indexer returns all confirmed candidates.

The indexer never selects an owner.

The indexer marks incomplete scans with `complete = false`.

The indexer serves a current `indexedThroughLedger` on every request.

The indexer supplies birth data from the creation transaction.

The indexer does not claim that birth data proves ownership.

The SDK verifies birth data, code, signer state, records, and fresh possession.

The SDK connects only to one fully verified candidate.

The constructor rejects a Secp256r1 signer without its domain-bound proof.

The constructor requires a durable admin.

The complete flow preserves the existing deployer and address formula.

No factory contract participates in this design.

No migration path exists for pre-release wallets.
