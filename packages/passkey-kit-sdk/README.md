# passkey-kit-sdk

Generated TypeScript bindings for the passkey-kit smart-wallet contract.

> [!CAUTION]
> The smart-wallet contract and these bindings have not received an independent third-party security audit. Defects can cause unauthorized transactions, loss of access, or permanent asset loss. Do not store or control assets you cannot afford to lose. You use this software at your own risk. See the repository [security policy](https://github.com/stellar/passkey-kit/blob/main/SECURITY.md) and [caveats](https://github.com/stellar/passkey-kit#caveats).

Most applications should install [`passkey-kit`](https://www.npmjs.com/package/passkey-kit). Use this package when you need the generated contract client and contract types directly.

## Install

```sh
pnpm add passkey-kit-sdk @stellar/stellar-sdk
```

## Use

```ts
import { Client } from "passkey-kit-sdk";

const wallet = new Client({
  contractId: "C...",
  networkPassphrase: "Test SDF Network ; September 2015",
  rpcUrl: "https://soroban-testnet.stellar.org",
});

const signer = await wallet.get_signer({
  signer_key: { tag: "Policy", values: ["C..."] },
});
```

State-changing methods return an `AssembledTransaction`. Review the simulated transaction before signing and submitting it.

Use only the canonical hash in the current [deployment manifest](https://github.com/stellar/passkey-kit/blob/main/docs/deployments-2026-09-01.md).
Pre-`0.17.0` wallets cannot connect through `passkey-kit`, even after an upgrade.
Create new wallets with the canonical hash.

The generated TypeScript types and method documentation come from the contract specification. The repository preserves this README during binding regeneration.
