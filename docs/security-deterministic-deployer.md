# Deterministic deployer security model

The shared deterministic deployer is intentional. Its published seed makes a
wallet address reproducible from the network, deployer address, and
credential-derived salt. The deployer is never a signer on the resulting smart
wallet and cannot authorize wallet operations or move wallet funds.

## Status: sign-only is implemented

The current SDK enforces this invariant for the shared default deployer:

> The shared deployer may derive an address and sign the CreateContractV2
> Soroban authorization entry. It never supplies a transaction-envelope source,
> sequence, or fee and never signs the transaction envelope.

`createWallet()` returns an authorized carrier in `signedTx` for compatibility;
`PasskeyServer.send()` extracts its `{ func, auth }` and requires a relayer to
supply the envelope source, sequence, and fees. A custom `deploySource` remains
a separate, self-sourced envelope path.

`restoreFootprint` is also decoupled. It requires a separate funded
`restoreSource` and never falls back to the shared deployer. `deploySource` is
address identity, not a fee-source knob: rotating it changes every derived
wallet address.

The shared sign-only path is implemented and testnet-verified:

- passkey-kit transaction
  `60e51c9c14c9c3f664c0f69c56179e9a677cd3e9137e74fb6a4ed1a176c63869`
- smart-account-kit transaction
  `1de0c40e61504ecfcb630e2ef5ac033c18df157da781a6d4c6a16a7c6fc33f08`

In each validation, a separate funded account supplied the envelope source and
fee, the shared deployer signed only address authorization, and the deployed
contract matched the deterministically derived address.

## We deliberately do not self-brick

We will not set the current shared deployer's sequence to `INT64_MAX`. Published
SDK versions still read or source its account sequence, and self-bricking would
retroactively break those clients. The current SDK does not read that sequence
or use the account as an envelope source, so a third party setting it to
`INT64_MAX` is a non-event for new shared deployments. Deliberately doing the
same thing ourselves would add effectively no protection while breaking old
clients.

No on-chain self-brick is part of this remediation.

## What `INT64_MAX` does and does not mean

Setting an account's sequence to `INT64_MAX` prevents that account from being
the **transaction-envelope source**, because it cannot supply a valid next
sequence number. That is the complete protection supplied by the sequence
brick. It does **not**:

- protect the account's balance;
- stop another account's envelope from naming it as an operation source, with
  its normal signer and threshold checks; or
- affect Soroban address authorization, which uses address credentials,
  signer weight/policy, and an authorization nonce rather than the classic
  account sequence.

The publicly derivable key can therefore still authorize classic operations
whose threshold it meets, including a payment sourced from the deployer. Never
fund a shared deployer.

The current mainnet smart-account-kit and passkey-kit deployers use
`auth_immutable`, thresholds `1/2/3`, and a single signer of weight `2`. This
blocks high-threshold signer changes and account merge, but it does not protect
the balance from medium-threshold payments. These controls bound takeover; the
SDK's sign-only architecture removes the shared sequence and balance from its
deployment and restore paths.

## Accepted residual: address squatting

The contract address does not bind the wallet WASM hash or constructor signer
set. Anyone who learns a credential ID before its intended deployment can use
the public deployer key to place arbitrary code at the derived address first.

This is an accepted, documented residual:

- Stellar does not expose a public transaction mempool that reveals a pending
  credential ID.
- A normal WebAuthn registration does not publish its credential ID before the
  client deploys, and a new registration creates a fresh credential.
- **Across networks, that last point does not hold.** Deploying a wallet
  publishes its `keyId`, and the `keyId` is not network-scoped even though the
  network passphrase is part of the address preimage. A passkey that already has
  a wallet on one network therefore maps to an address on every other network
  that its owner does not hold.
  **Register a fresh credential per network; never reuse a passkey that already
  has a wallet deployed on another one.**
- **Same-network, the "before deployment" framing also fails for secondary
  credentials.** Only a wallet's FIRST credential salts its deploy, so
  `derive(keyId_1)` is the wallet itself. A later signer's `keyId` is also
  published, but `derive(keyId_2)` is a distinct address that is never
  legitimately deployed, so it does not have the narrow exposure window a first
  credential does. Treat any derivation from a secondary credential as
  unauthenticated.
- The impact is griefing or value sent to the wrong precomputed address, not
  control of a correctly deployed wallet — the deployer is never a wallet signer.
  The one SDK-level consequence was that `connectWallet` resolved a secondary
  `keyId` by derivation first, so a squat at `derive(keyId_2)` could win over the
  correct wallet; resolution is now trusted-state-first (storage → indexer →
  derivation) with a live-signer ownership check, so a squat no longer misbinds
  a returning user. A first connect on a fresh device with no local record still
  falls through to the indexer and then to derivation; since `0.16.0` both bind
  accepted code identity before any signer state is read. A derivation-resolved
  address remains unauthenticated by construction — see below.

A signer-presence check **alone is not a mitigation**. Arbitrary code at a
squatted address can implement `get_signer`, `list`, or an equivalent getter and
return whatever signer set the client expects, so a successful signer getter is
not proof of anything without an independent binding on the code that answered
it. Since `0.16.0` the SDK binds accepted code identity first — see below.

**Code identity and signer state together still do not authenticate a derived
address.** A code-identity check proves the contract runs expected code; it says
nothing about who the signers are, because the address preimage binds neither the
WASM hash nor the constructor arguments. Accepted code and a genuine signer entry
for the expected credential can coexist with authority held elsewhere.

What both checks have in common is that they read **current state**, and current
state at a squatted address is chosen by whoever put code there. Signer/policy
equality against trusted local state would exclude it, but a fresh device — the
scenario derivation exists to serve — has no such state.

Until the provenance check described below ships, treat a derivation-resolved
address as **unauthenticated**: do not present it as a deposit address. Today
storage-first resolution, not a better state check, is the mitigation.

## Planned mitigation: genesis-signer provenance

Every state check above fails for the same reason — it reads state the squatter
wrote. Deploy-time provenance does not: it is history, and the ledger cannot be
made to say a contract was born with a signer it was not.

The wallet's `__constructor` seeds its first signer through `add_signer_impl`,
which publishes `SignerAdded`, and there is no other unauthenticated path to add
one. So a contract's **genesis signer** is well defined, immutable, and readable:
the constructor arguments of its creating transaction, equivalently the first
`SignerAdded` event it ever emitted.

The check, for an address reached by derivation from `credentialId`:

> the genesis signer of the contract at `derive(credentialId)` must be
> `Secp256r1(credentialId)`.

An attacker cannot satisfy it and retain authority. The two cases are exhaustive
because the constructor takes exactly one signer:

| Attacker's genesis signer | Check | Attacker authority |
|---|---|---|
| The victim's credential | passes | **none** — they hold no key, and `add_signer`/`upgrade` require wallet auth only the victim's authenticator can produce |
| Their own key or a policy | **fails** — mismatch | yes, but detected |

This degrades the attack from theft to a confusing duplicate: a squat that passes
is one the victim solely controls, so value sent there stays recoverable.

Two properties make this usable where the state checks are not:

- **It needs no trusted local state** — only the `credentialId` already in hand,
  which is exactly what the fresh-device path has. That is why it closes the case
  signer-set equality cannot.
- **It is not blind trust in an indexer.** The indexer's answer names a
  transaction; a client can fetch that transaction and verify the constructor
  arguments itself.

Implementation notes and the honest limits:

- This reads history, not state, so RPC event retention does not cover older
  contracts. It is an indexer capability — Mercury already indexes signer events
  and holds the genesis one.
- The sibling smart-account-kit constructor takes a signer **array** and a policy
  **map**, so there the predicate must cover the whole genesis signer set *and*
  the genesis policies. A `[victim]` genesis with an attacker-controlled policy
  would otherwise pass while granting the attacker authority.
- It does not make derivation authoritative for a *secondary* credential.
  `derive(keyId_2)` is still an address no legitimate deploy occupies; the check
  only guarantees that whatever sits there is not attacker-controlled.
- **It closes the derivation path only, not indexer discovery.** A candidate
  returned by the reverse lookup is not at a derived address and has no expected
  genesis relationship to a secondary credential — the real wallet's genesis is
  the user's *first* credential, which a fresh client does not know. See
  "Reverse-lookup forgery" below.

## Why code identity is bound before signer state

An address obtained from an indexer reverse lookup or from address derivation is
a **claim by an untrusted party**, not a fact. Neither the discovery signal nor
the on-chain state read back is self-authenticating: contract-emitted events are
unprivileged, and a contract controls its own storage, so code of the author's
choosing can present whatever state a client inspects.

The consequence is that a signer entry only means "this passkey was authorized
onto this wallet" **if the code that wrote it enforced authorization**. Under
arbitrary code it means nothing. That is why the ordering matters, and why the
SDK now binds accepted code identity *before* reading any signer state.

Note this is independent of the deployer key: it needs no derived address and no
squatting. It is a property of unauthenticated discovery.

### What is enforced (since `0.16.0`)

`connectWallet` checks the resolved contract's executable against
`acceptedWasmHashes` whenever the address came from an untrusted source. Defaults
to `[walletWasmHash]`; `verifyWasmHash` overrides per call. An address resolved
from trusted local storage is not checked, so a legitimately upgraded wallet still
opens for a returning user.

### What this does and does not cover

It removes the case that costs an attacker nothing — arbitrary code, deployed
once. It does not make a discovery result authoritative on its own: an attacker
willing to run accepted code and pay for a genuine, authorized `add_signer` can
still produce a contract on which the victim really is a signer, and for a
secondary credential on a device with no local state that is not distinguishable
client-side from the real wallet.

Bound that residual in the flow rather than with another state check:

- Never auto-select from a multi-candidate reverse lookup — treat more than one
  result as requiring an explicit choice.
- Surface provenance (genesis credential, code identity) at selection rather than
  a bare address list.
- Prefer recovery with the credential that created the wallet, which reduces to
  the derivation case that genesis provenance closes.
- Keep an unverified discovery result unauthenticated — never present it as a
  deposit address.

This supersedes the WASM-hash allowlist as the tracked mitigation. An allowlist
binds code identity and is worth having against lying code, but it does not bind
the constructor signer set and so cannot authenticate an address on its own.

Operational verification of the mainnet geometry below is scripted — see
[`mainnet-hardening.md`](./mainnet-hardening.md) and
`scripts/check-mainnet-deployer.mjs`, which exits non-zero on drift.

## Deployer inventory

| Generation | Derivation | Address | State / action |
|---|---|---|---|
| Current smart-account-kit | `sha256("openzeppelin-smart-account-kit")` seed | `GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N` | Shared sign-only identity; do not fund or rotate. |
| Current passkey-kit | `sha256("kalepail")` seed | `GC2C7AWLS2FMFTQAHW3IBUB4ZXVP4E37XNLEF2IK7IVXBB6CMEPCSXFO` | Shared sign-only identity; do not fund or rotate. |
| Legacy passkey-kit mainnet, before `23597d8` | `sha256(mainnet network passphrase)` seed | `GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7` | Locked: master weight `0`; cannot sign. |
| Legacy passkey-kit testnet, before `23597d8` | `sha256(testnet network passphrase)` seed | *(withheld — see internal ops tracker)* | Superseded, unhardened, testnet only. Tracked for retirement. |

Changing a deployer changes the address preimage for every wallet derived from
it. Keep legacy identities in discovery/migration logic; use `restoreSource` for
footprint fees instead of rotating `deploySource`.

## Operational follow-ups (outside this change)

Open ops tasks, not SDK defects. The sign-only SDK works without them; they
reduce operational risk on testnet.

- Harden the testnet deployers (`0/0/0` today) and make post-reset provisioning
  fail closed, so a network reset cannot recreate an unhardened `AccountEntry`
  that address authorization then depends on. The relayer proxy already refuses
  to Friendbot-fund a shared deployer.
- Sweep or retire the superseded testnet deployer listed above. Like every shared
  deployer its key is publicly derivable, so it must not hold a balance.
