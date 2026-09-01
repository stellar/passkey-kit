# passkey-kit smart-wallet security release — 2026-08-19

> [!WARNING]
> This manifest is historical and superseded.
> Do not use this WASM with `passkey-kit@0.17.0` or later.
> Use [`deployments-2026-09-01.md`](./deployments-2026-09-01.md).

This manifest records the canonical smart-wallet WASM on 2026-08-19.
It superseded the smart-wallet hash in `deployments-testnet-2026-07-11.md`.
The sample-policy and example-contract hashes remain unchanged.

## Fixed artifact

| Component | Cargo package | Bytes | SHA-256 / network WASM hash |
|---|---|---:|---|
| Smart wallet | `smart-wallet` | 33,094 | `502ea4e7bdb3ea99880941f1d35ceb67fb598692c0bb40f842ef9c9f17d58b58` |

- Source commit: `1eafc888a2bdfb210277a19f51f654a397cb4c68`
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
- Upload transaction: `aa5a07778a72c9dde8cfbecfc51a76f9451ebcf563b2d75591d97aa2eb76c00a`
- Upload ledger: `4226258`
- Upload time: `2026-08-19T15:31:39Z`

### Live smoke wallet

- Instance: `CDIK3DUSSYAHV6H4PJPZOCBSB4QLGO22LKTHJDZLGIVOSZDWWV7ZHHXO`
- Deploy transaction: `54f00d6595b6089504309682b00b477de8aef1409289e224a82e7ca16ba726a9`
- Deploy ledger: `4226310`
- Deploy time: `2026-08-19T15:36:00Z`
- Constructor signer: `GD2GA2JF6OJURU36COZQWJLPEJ7XC3GB25TBD7U4ALCGKOG27262RICH`
- Storage: `Persistent`
- Expiration: none
- Limits: none

The live `get_signer` call returned `{"Ed25519":[[null],[null]]}`.
Mercury returned this wallet and its live constructor signer.

## Mainnet

- Network passphrase: `Public Global Stellar Network ; September 2015`
- Upload source: `GBDVX4VELCDSQ54KQJYTNHXAHFLBCA77ZY2USQBM4CSHTTV7DME7KALE`
- Upload transaction: `df21ca2177301118758fd3175ca1fcc96bd606f46f93a10405194f44a77b8de1`
- Upload ledger: `64028093`
- Upload time: `2026-08-19T15:34:20Z`

The upload installs code only.
It does not deploy a singleton or upgrade an existing wallet.

## Verification

The local, testnet, and mainnet bytes produced the same SHA-256 hash.

```sh
shasum -a 256 contracts/out/smart_wallet.wasm
stellar -q contract fetch \
  --wasm-hash 502ea4e7bdb3ea99880941f1d35ceb67fb598692c0bb40f842ef9c9f17d58b58 \
  --network testnet | shasum -a 256
stellar -q contract fetch \
  --wasm-hash 502ea4e7bdb3ea99880941f1d35ceb67fb598692c0bb40f842ef9c9f17d58b58 \
  --network mainnet | shasum -a 256
```

Each command returned this hash:

```text
502ea4e7bdb3ea99880941f1d35ceb67fb598692c0bb40f842ef9c9f17d58b58
```

## Existing wallets

This section records the upgrade guidance from 2026-08-19.
It does not apply to `passkey-kit@0.17.0` or later.
The current SDK does not connect to these pre-release wallets.

The testnet relayer rejects every superseded hash.
This stops sponsored use of every superseded-wallet administration function.
Users must submit an old-wallet upgrade through another fee source.

Required policies must be installed wallet signers after the upgrade.
An unstored required policy now revokes the dependent signer.
This behavior is an intentional fail-closed compatibility change.

## Superseded smart-wallet hash

Do not use these hashes for new deployments:

```text
fdefad64b96837147e1c333e51f537b696eab925e9f147e63d597c04e3c903f0  superseded build
b2e858176fab112cc9afbe54590e13d12192ba7fa32dd83cf565d21f2f13179a  pre-release build with truncated SignerLimits metadata
```

The previous manifest remains available for historical verification.
