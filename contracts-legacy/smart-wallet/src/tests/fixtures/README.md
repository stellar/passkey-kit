# Test fixtures

Byte-exact copies of the mainnet `ContractCode` entries for three of the four
pre-fix smart-wallet builds, fetched on 2026-09-17 through
`getLedgerEntries` and verified with `sha256(code) == hash` before saving.
The end-to-end tests deploy a wallet from each and upgrade it in place to the
WASM built from this crate.

| File | sha256 (= mainnet WASM hash) | Bytes |
|---|---|---|
| `0c0a264d.wasm` | `0c0a264d4cc0b3e79b8533e2a2e1f0ed21501a5a3f9f2455d2f18c232940b865` | 20524 |
| `b62f6221.wasm` | `b62f62217ff256d557513793e9e44317b25b14401a8a6b6149a04d38d72d6c7c` | 23193 |
| `c5509dfa.wasm` | `c5509dfa5f022deb8ae621f073adac5fd788feca0b24d15b5f392ab22c2ff222` | 21660 |

`19868df3…` (one wallet) has the same source shape as `0c0a264d…` and no
fixture. To re-fetch: build the ledger key as `base64(0x00000007 || hash)`
and call `getLedgerEntries` on any mainnet RPC; the code bytes follow the hash
inside the `ContractCode` entry XDR.
