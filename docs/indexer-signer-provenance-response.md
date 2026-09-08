# Mercury schema-2 wallet candidate response

Status: the SDK uses this route on supported networks.
Testnet fixtures verified the response contract on 2026-09-08.
This check did not independently verify mainnet v2 responses.

This document defines the public response contract for fresh-device wallet discovery.
It contains no private report data.
It does not describe the closed security issue.

## Current hosted status

Mercury hosts public, keyless indexers on testnet and mainnet.
The signer enumeration routes are live.

Verified testnet v2 responses return wallet birth claims and a complete ledger position.
The address route keeps its existing path and response behavior.
The SDK validates the v2 response before it confirms candidates on-chain.

## Required route

Serve schema 2 on the versioned credential lookup route:

```text
GET /api/v2/lookup/:credentialId
```

Keep the route public and keyless.
Use the hexadecimal credential ID format that the current route accepts.

## Required response

Return this response when the scan is complete:

```json
{
  "schema": 2,
  "credentialId": "lowercase-hexadecimal-credential-id",
  "network": "testnet",
  "complete": true,
  "indexedThroughLedger": 5440001,
  "rpcCheckedAtLedger": 5440001,
  "candidates": [
    {
      "contractId": "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ",
      "birthWasmHash": "64-character-lowercase-hex",
      "creationTransactionHash": "64-character-lowercase-hex",
      "creationLedger": 5432100,
      "currentWasmHash": "64-character-lowercase-hex",
      "generation": "legacy",
      "derivedAddress": false,
      "collision": false,
      "incomplete": false,
      "signer": {
        "publicKey": "130-character-lowercase-hex",
        "expiration": null,
        "expiration_unit": null,
        "storage": "persistent",
        "status": "live",
        "rpcConfirmed": true
      }
    }
  ],
  "count": 1,
  "ambiguous": false
}
```

The response has these required fields:

- `schema` must equal `2`.
- `credentialId` must match the requested hexadecimal credential ID.
- `network` must equal `testnet` or `mainnet`.
- `complete` must equal `true` only after a complete scan.
- `indexedThroughLedger` is the highest fully indexed ledger.
- `rpcCheckedAtLedger` is the ledger used for current signer checks.
- `candidates` contains every matching wallet candidate.
- `count` must equal the candidate count.
- `ambiguous` is true only when multiple distinct candidates exist.

Each candidate has these required fields:

- `contractId` is the wallet contract address.
- `birthWasmHash` is the WASM hash from the creation transaction.
- `creationTransactionHash` is the creating transaction hash.
- `creationLedger` is the ledger that created the contract.

Use lowercase hexadecimal strings for both hashes.
Each hash must contain 64 characters.
Use a safe positive integer for each ledger number.

Each complete candidate also carries the current WASM hash and event generation.
It identifies derived-address candidates and credential collisions.
It carries the RPC-confirmed current signer state.
The SDK does not use indexer signer key material as signing authority.

`collision` is true only when derived and non-derived candidates coexist.
It is false for ordinary multi-wallet ambiguity.
The SDK still verifies all candidates and rejects multiple verified candidates.

An incomplete candidate sets `incomplete` to true.
Only that candidate can contain `incompleteReasons`.
The closed candidate reason set is:

- `missing_birth`
- `rpc_unchecked`
- `signer_unconfirmed`
- `instance_missing`
- `wasm_unresolved`
- `inconsistent_creation_ledger`

A response can also contain response-level `incompleteReasons`.
The closed response reason set is `reducer_errors` and `index_behind`.
Do not add incomplete reasons to a complete response.

The v2 route uses the exact camel-case fields above.
The address lookup parser still accepts its existing aliases.
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
  "credentialId": "lowercase-hexadecimal-credential-id",
  "network": "testnet",
  "complete": false,
  "indexedThroughLedger": 5439000,
  "rpcCheckedAtLedger": 5440001,
  "candidates": [],
  "count": 0,
  "ambiguous": false,
  "incompleteReasons": ["index_behind"]
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

Secp256r1 lookup uses the versioned v2 route.
Ed25519 and policy lookup keeps `/api/lookup/address/:address`.
The contract, demo, and relayer need no change for the route update.

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

Test the existing Ed25519 and policy address route.
Confirm that its path and response behavior stay compatible.

## Monitoring

Count complete and incomplete responses.
Count candidates with missing birth data.
Count signer confirmations that fail.
Count responses that the SDK rejects as stale.

Do not log private keys or authenticator secrets.
Treat credential IDs and public keys as sensitive operational identifiers.

## Deployment acceptance

Do not claim complete deployment until each supported network serves schema 2.
Each response must include a current indexed ledger position.
Each complete candidate must include verified birth fields.
Incomplete scans must remain incomplete.

Test a fresh-device connection on each supported network after each indexer change.
Confirm that one valid candidate connects.
Confirm that incomplete, stale, and ambiguous results fail closed.
