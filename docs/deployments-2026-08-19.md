# passkey-kit smart-wallet security release — 2026-08-19

This manifest is the canonical source for the fixed smart-wallet WASM.
It supersedes the smart-wallet hash in `deployments-testnet-2026-07-11.md`.
The sample-policy and example-contract hashes remain unchanged.

## Fixed artifact

| Component | Cargo package | Bytes | SHA-256 / network WASM hash |
|---|---|---:|---|
| Smart wallet | `smart-wallet` | 33,242 | `b2e858176fab112cc9afbe54590e13d12192ba7fa32dd83cf565d21f2f13179a` |

- Source commit: `d2dd0888663894b0465207edd565da95fc7fd1df`
- Rust/Cargo: `1.94.0`
- `soroban-sdk`: `27.0.0` (`e5cb4b52c3da8e56fc48adfd7b85d85976c1a059`)
- Stellar CLI: `27.1.0` (`8e402ea28202950b272fbabc34caad4d2f64fe87`)
- Contract metadata: `binver: 1.0.1`, `rsver: 1.94.0`, `rssdkver: 27.0.0`
- Build command: `stellar contract build --locked --package smart-wallet --out-dir out`

Two clean optimized builds produced the same hash and size.

## Security behavior

The release fixes two authorization failures.

- Every `Signature::Policy` entry now calls `policy__`.
- A required policy must remain stored and unexpired.
- Removing a required policy now revokes every dependent signer.
- A missing required policy now fails closed with `MissingContext`.

The full Rust workspace suite passed with 104 tests.
The library clippy check and formatting check also passed.

## Testnet

- Network passphrase: `Test SDF Network ; September 2015`
- Upload source: `GD2GA2JF6OJURU36COZQWJLPEJ7XC3GB25TBD7U4ALCGKOG27262RICH`
- Upload transaction: `bfeb0cf0de6be52819a5047a4816636e4b45f02e9239bdb29cd53d5e42b478af`
- Upload ledger: `4225953`
- Upload time: `2026-08-19T15:06:11Z`

### Live smoke wallet

- Instance: `CBM2GPDT2VU5M62AANUEPKXJ67UKSBNJCXDGKRP4BAPYUVI7UBFCIXEU`
- Deploy transaction: `a5e4df6849422c46984d1d125a60c47ff94fa81f1e5b3a8a9016ece0126d6f7a`
- Constructor signer: `GD2GA2JF6OJURU36COZQWJLPEJ7XC3GB25TBD7U4ALCGKOG27262RICH`
- Storage: `Persistent`
- Expiration: none
- Limits: none

The live `get_signer` call returned `{"Ed25519":[[null],[null]]}`.
Mercury returned this wallet and its live constructor signer.

## Mainnet

- Network passphrase: `Public Global Stellar Network ; September 2015`
- Upload source: `GBDVX4VELCDSQ54KQJYTNHXAHFLBCA77ZY2USQBM4CSHTTV7DME7KALE`
- Upload transaction: `20a3b37dc7459ea9508975c3e490ed3d01c39720fad754883e46aab714917d1c`
- Upload ledger: `64027849`
- Upload time: `2026-08-19T15:11:10Z`

The upload installs code only.
It does not deploy a singleton or upgrade an existing wallet.

## Verification

The local, testnet, and mainnet bytes produced the same SHA-256 hash.

```sh
shasum -a 256 contracts/out/smart_wallet.wasm
stellar -q contract fetch \
  --wasm-hash b2e858176fab112cc9afbe54590e13d12192ba7fa32dd83cf565d21f2f13179a \
  --network testnet | shasum -a 256
stellar -q contract fetch \
  --wasm-hash b2e858176fab112cc9afbe54590e13d12192ba7fa32dd83cf565d21f2f13179a \
  --network mainnet | shasum -a 256
```

Each command returned this hash:

```text
b2e858176fab112cc9afbe54590e13d12192ba7fa32dd83cf565d21f2f13179a
```

## Existing wallets

Existing `binver = 1.0.0` wallets remain vulnerable until an authorized upgrade.
Each owner must call `upgrade` with the fixed hash.
The upgrade keeps the existing wallet address and signer storage.

The testnet relayer rejects the old vulnerable hash.
This stops sponsored use of every old-wallet administration function.
Users must submit an old-wallet upgrade through another fee source.

Required policies must be installed wallet signers after the upgrade.
An unstored required policy now revokes the dependent signer.
This behavior is an intentional fail-closed compatibility change.

## Superseded smart-wallet hash

Do not use this hash for new deployments:

```text
fdefad64b96837147e1c333e51f537b696eab925e9f147e63d597c04e3c903f0
```

The previous manifest remains available for historical verification.
