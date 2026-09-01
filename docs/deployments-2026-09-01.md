# passkey-kit signer-provenance release — 2026-09-01

This manifest is the canonical source for the `0.17.0` smart-wallet WASM.
It supersedes the smart-wallet hash in `deployments-2026-08-19.md`.

## Canonical artifact

| Component | Cargo package | Bytes | SHA-256 / network WASM hash |
|---|---|---:|---|
| Smart wallet | `smart-wallet` | 42,108 | `97ce047884106b1c6c3bb40b8973cc48db1c4dad95c9e20462bf2c701daa764e` |

- Source tag: `v0.17.0`
- Rust/Cargo: `1.94.0`
- `soroban-sdk`: `27.0.0` (`e5cb4b52c3da8e56fc48adfd7b85d85976c1a059`)
- Stellar CLI: `27.1.0` (`8e402ea28202950b272fbabc34caad4d2f64fe87`)
- Contract metadata: `binver: 1.1.0`, `rsver: 1.94.0`, `rssdkver: 27.0.0`
- Build command: `stellar contract build --locked --package smart-wallet --out-dir out`

Repeated optimized builds produced the same hash and size.

## Security behavior

The release closes accepted-code wallet redirection.

- `__constructor` requires a GENESIS WebAuthn proof for a Secp256r1 signer.
- `add_secp256r1` requires a separate ADD proof.
- Each proof commits to the network, address, purpose, and complete signer.
- The constructor requires a durable admin signer.
- The wallet stores the original signer, purpose, and proof.
- The SDK verifies the immutable creation transaction before connection.
- The SDK also verifies current code, signer state, the stored proof, and fresh possession.
- The SDK rejects derivation-only, incomplete, stale, and ambiguous discovery.

The production design uses direct `CreateContractV2` and `__constructor`.
It does not use a factory contract.

## Verification results

- Rust wallet tests: 136 passed.
- Real-WASM constructor tests: 2 passed.
- TypeScript tests: 272 passed.
- Relayer-proxy tests: 54 passed.
- Rust formatting and clippy checks passed.
- SDK, bindings, ESM, and demo builds passed.

## Testnet upload

- Network passphrase: `Test SDF Network ; September 2015`
- Upload source: `GAJKIZRJDFYR343ENKRYCYLMWV7WWXUFCPLLKGRYN5SHQ2RE7Z45LVDW`
- Upload transaction: `a910da984328461d0c79a29ec3fb60a2f33d3c750a72fc7285234a51709625ba`
- Upload ledger: `4454440`
- Upload time: `2026-09-01T20:49:47Z`

## Mainnet upload

- Network passphrase: `Public Global Stellar Network ; September 2015`
- Upload source: `GBDVX4VELCDSQ54KQJYTNHXAHFLBCA77ZY2USQBM4CSHTTV7DME7KALE`
- Upload transaction: `441f3987eb386de1b8881f7fd9b800de515dfa61a23bc94dcf87d7aec47b6324`
- Upload ledger: `64229392`
- Upload time: `2026-09-01T20:50:24Z`

Each upload installs code only.
It does not deploy a singleton wallet.

## Byte verification

```sh
shasum -a 256 contracts/out/smart_wallet.wasm
stellar contract fetch \
  --wasm-hash 97ce047884106b1c6c3bb40b8973cc48db1c4dad95c9e20462bf2c701daa764e \
  --network testnet --out-file /tmp/passkey-wallet-testnet.wasm
stellar contract fetch \
  --wasm-hash 97ce047884106b1c6c3bb40b8973cc48db1c4dad95c9e20462bf2c701daa764e \
  --network mainnet --out-file /tmp/passkey-wallet-mainnet.wasm
shasum -a 256 /tmp/passkey-wallet-testnet.wasm /tmp/passkey-wallet-mainnet.wasm
```

Each file returned this hash:

```text
97ce047884106b1c6c3bb40b8973cc48db1c4dad95c9e20462bf2c701daa764e
```

## Compatibility

This alpha release has no pre-release wallet migration path.
Pre-`0.17.0` wallets remain on-chain, but this SDK does not connect to them.

Address occupancy remains possible with the public shared deployer.
That condition causes a visible deployment failure.
It does not give an attacker control of a wallet accepted by this release.
