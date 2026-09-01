# Mercury schema-2 wallet candidate response

Status: required by `passkey-kit@0.17.0` and later, but not yet deployed.

This document defines the public response contract for fresh-device wallet discovery.
It contains no private report data.
It does not describe the closed security issue.

## Current hosted status

Mercury hosts public, keyless indexers on testnet and mainnet.
The signer enumeration routes are live.

As of 2026-09-01, the lookup routes return the old response shape.
That shape has `wallets` and `count` fields.
It does not contain wallet birth claims or a complete ledger position.

`passkey-kit@0.17.0` and later treat the old shape as incomplete.
Fresh-device discovery therefore fails closed.
Verified local wallet records continue to connect.

## Required route

Serve schema 2 on the existing credential lookup route:

```text
GET /api/lookup/:credentialId
```

Keep the route public and keyless.
Use the hexadecimal credential ID format that the current route accepts.

## Required response

Return this response when the scan is complete:

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

The response has these required fields:

- `schema` must equal `2`.
- `complete` must equal `true` only after a complete scan.
- `indexedThroughLedger` is the highest fully indexed ledger.
- `candidates` contains every matching wallet candidate.

Each candidate has these required fields:

- `contractId` is the wallet contract address.
- `birthWasmHash` is the WASM hash from the creation transaction.
- `creationTransactionHash` is the creating transaction hash.
- `creationLedger` is the ledger that created the contract.

Use lowercase hexadecimal strings for both hashes.
Each hash must contain 64 characters.
Use a safe positive integer for each ledger number.

The SDK accepts snake-case aliases for candidate and ledger fields.
These aliases include `contract_id`, `birth_wasm_hash`, and `creation_ledger`.
It also accepts `creation_transaction_hash`, `creation_tx`, and `indexed_through_ledger`.
`schema` must be the number `2`, not the string `"2"`.

## Candidate rules

Return every wallet that currently contains the requested live signer.
Do not select one wallet for the client.
Do not use response order as a trust signal.
Deduplicate candidates by `contractId`.

Confirm current signer state before you return a complete result.
Exclude removed, expired, or evicted signers from the live candidate set.
Use Stellar RPC when a temporary signer's state needs confirmation.

Take every birth field from the direct creation transaction.
Do not infer birth data from current contract state.
Do not use the current WASM hash as the birth WASM hash.
Do not create missing birth values.

## Completeness and freshness

Set `complete` to `true` only after an end-to-end scan.
The scan must include all indexed history through `indexedThroughLedger`.
The ledger position must have no known gaps.

Set `complete` to `false` when any required scan cannot finish.
Keep discovered candidates in the incomplete response for diagnostics.
Do not replace an incomplete result with an empty complete result.

Example incomplete response:

```json
{
  "schema": 2,
  "complete": false,
  "indexedThroughLedger": 5439000,
  "candidates": []
}
```

The SDK records the current RPC ledger before it requests candidates.
It rejects a response below that ledger.
Serve a current `indexedThroughLedger` on every request.

## SDK behavior

The SDK treats every indexer field as a claim.
It verifies each creation transaction through Stellar RPC or Horizon history.
It recomputes the transaction hash from the returned envelope.

The SDK verifies these creation facts:

- the transaction succeeded;
- the transaction created the candidate address;
- the operation used direct `CreateContractV2`;
- the transaction used the claimed creation ledger;
- the birth WASM hash is accepted.

The SDK then verifies current code and signer state.
It also verifies the stored signer proof and a fresh passkey assertion.
The SDK connects only when one candidate passes all checks.

The SDK rejects the complete response when any required field is missing.
It also rejects malformed fields and stale ledger positions.
Every rejection leaves the kit disconnected.

## Compatibility

Old clients can continue to read the existing `wallets` and `count` fields.
Add schema-2 fields without removing those fields during the transition.
Put complete birth rows in the new `candidates` field.
The new SDK prefers `candidates` when `schema` equals `2`.
It uses `wallets` for the old response shape.
When both arrays exist, their `contractId` sets must match.
A mismatch makes the complete response invalid.

An additive dual-field rollout requires `passkey-kit@0.17.1` or later.
Version `0.17.0` remains fail-closed on that rollout shape.

The deployed contract and `passkey-kit@0.17.1` support schema 2.
The indexer deployment is the remaining service step.
No contract, demo, or relayer change is required for that deployment.

## Required tests

Test a credential with no wallets.
Return a complete empty candidate list after a complete scan.

Test a credential with one live wallet.
Return one candidate with verified birth fields.

Test a credential with multiple live wallets.
Return every candidate with its own birth fields.

Test duplicate index rows.
Return one candidate for each `contractId`.

Test removed and expired signers.
Do not return them as live candidates.

Test an evicted temporary signer.
Confirm its state through RPC.

Test a missing creation transaction.
Return `complete: false` and never create birth data.

Test an RPC timeout or partial scan.
Return `complete: false` or fail the request.

Test a stale `indexedThroughLedger` value.
Confirm that the SDK rejects the response.

Test every missing required field.
Confirm that the SDK rejects each response.

Test the old fields during the transition.
Confirm that old clients remain compatible.

## Monitoring

Count complete and incomplete responses.
Count candidates with missing birth data.
Count signer confirmations that fail.
Count responses that the SDK rejects as stale.

Do not log private keys or authenticator secrets.
Treat credential IDs and public keys as sensitive operational identifiers.

## Deployment acceptance

The deployment is complete when both networks serve schema 2.
Each response must include a current indexed ledger position.
Each complete candidate must include verified birth fields.
Incomplete scans must remain incomplete.

After deployment, test a fresh-device connection on both networks.
Confirm that one valid candidate connects.
Confirm that incomplete, stale, and ambiguous results fail closed.
