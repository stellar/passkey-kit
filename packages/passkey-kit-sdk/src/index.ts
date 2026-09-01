import { Buffer } from "buffer";
import { Address } from "@stellar/stellar-sdk";
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Timepoint,
  Duration,
} from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";

if (typeof window !== "undefined") {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}




/**
 * Contract errors.
 *
 * Deliberately renumbered for the v1 interface so the error space is disjoint
 * from the legacy (pre-1.0) contract's 1-9 range. A client decoding an error
 * code < 100 is talking to a legacy wallet.
 *
 * Ranges:
 * - 100-109: signer storage / management
 * - 110-119: auth (`__check_auth`)
 * - 120-129: WebAuthn (secp256r1) verification
 * - 130-139: Secp256r1 signer binding
 */
export const Errors = {
  /**
   * The requested signer does not exist on this smart wallet.
   */
  100: {message:"SignerNotFound"},
  /**
   * `add_signer` was called with a signer key that already exists.
   */
  101: {message:"SignerAlreadyExists"},
  /**
   * The signer's expiration timestamp is in the past.
   */
  102: {message:"SignerExpired"},
  /**
   * The operation would remove — or demote via `update_signer` — the
   * wallet's LAST durable admin signer: a signer stored `Persistent`,
   * non-expiring (`SignerExpiration(None)`), and independently
   * admin-capable — either unlimited (`SignerLimits(None)`) or holding a
   * limits entry for the wallet's own address with no required co-signers
   * (`None` or an empty list). With zero such signers no `add_signer` or
   * `upgrade` could ever be authorized again, permanently locking the
   * wallet on an immutable network, so the transition is rejected.
   * To retire the last admin signer, add (or promote) a replacement
   * durable admin signer first.
   *
   * Case this guard CANNOT catch (statically undecidable): a POLICY
   * signer with an admin-shaped grant counts as an admin even if its
   * `policy__` rejects every request. If such a policy is your only
   * remaining admin, the wallet's admin surface is unrecoverable even
   * though the signer still exists. Keep a non-policy admin (or a second
   * admin) at all times.
   */
  103: {message:"LastAdminSigner"},
  /**
   * The operation would leave the wallet without any DURABLE signer — one
   * stored `Persistent` with `SignerExpiration(None)`, any limits. Fired
   * by `remove_signer` (removing the last durable signer), `update_signer`
   * (demoting it to `Temporary` storage or to an expiring value), and
   * `__constructor` (the wallet's first signer must be durable).
   * Non-durable signers can evict or expire with NO contract
   * call, so only a durable signer guarantees the wallet always keeps at
   * least one live signer; with zero live signers nothing — not even
   * `add_signer` — can ever be authorized again. This is the
   * classification-independent backstop beneath `LastAdminSigner`. To
   * retire the last durable signer, add a durable replacement first.
   */
  104: {message:"LastSigner"},
  /**
   * No signer in the signatures map is permitted to authorize one of the
   * requested auth contexts.
   */
  110: {message:"MissingContext"},
  /**
   * A signature's variant does not match the stored signer it claims to be
   * for (e.g. an Ed25519 signature submitted for a Policy signer key).
   */
  111: {message:"SignatureKeyValueMismatch"},
  /**
   * clientDataJSON exceeds the 1024 byte parse buffer.
   */
  120: {message:"ClientDataJsonTooLarge"},
  /**
   * clientDataJSON is not parseable JSON (or is missing required fields).
   */
  121: {message:"ClientDataJsonParseError"},
  /**
   * The challenge in clientDataJSON does not match the base64url-encoded
   * signature payload. This binds the WebAuthn assertion to the Soroban
   * authorization entry and MUST NOT be weakened.
   */
  122: {message:"ClientDataJsonChallengeIncorrect"},
  /**
   * clientDataJSON `type` is not "webauthn.get".
   */
  123: {message:"InvalidWebAuthnType"},
  /**
   * authenticatorData is shorter than the WebAuthn minimum of 37 bytes
   * (rpIdHash 32 + flags 1 + signCount 4).
   */
  124: {message:"InvalidAuthenticatorData"},
  /**
   * The authenticator did not set the User Present (UP) flag.
   *
   * UP-only is the deliberate default. Requiring UP keeps
   * silent, non-interactive assertions out while staying compatible with
   * authenticators that cannot do User Verification (UV — biometric/PIN).
   * UV is therefore NOT required by this contract. A deployment that wants
   * UV-required assertions should enforce it at the client/relayer layer,
   * or via a future per-signer flag (which would be a signer-model change,
   * not a change to this check); the contract cannot upgrade UP-only
   * signers to UV-required retroactively without such a flag.
   */
  125: {message:"UserPresenceRequired"},
  /**
   * authenticatorData exceeds the 1024 byte cap (symmetric with
   * `ClientDataJsonTooLarge`). Real assertions are ~37 bytes; the cap
   * rejects oversized input BEFORE it is hashed, since this path is
   * reachable without a valid signature.
   */
  126: {message:"AuthenticatorDataTooLarge"},
  /**
   * A Secp256r1 signer was supplied without its binding proof. Passkeys
   * enter a wallet only through `__constructor` (GENESIS proof) or
   * `add_secp256r1` (ADD proof) — never through the generic `add_signer`.
   */
  130: {message:"BindingProofRequired"},
  /**
   * A binding proof was supplied for a signer that is not Secp256r1.
   */
  131: {message:"BindingProofUnexpected"},
  /**
   * `update_signer` may not change a Secp256r1 signer's public key: the
   * binding proof commits to it. Remove the signer and re-add it with a
   * fresh proof through `add_secp256r1` instead.
   *
   * Code 132 is retired with `bind_secp256r1`; 134 with its
   * already-bound guard. Neither is reused.
   */
  133: {message:"BindingPublicKeyImmutable"}
}

/**
 * Full signer description used by `__constructor`, `add_signer` and
 * `update_signer`.
 */
export type Signer = {tag: "Policy", values: readonly [string, SignerExpiration, SignerLimits, SignerStorage]} | {tag: "Ed25519", values: readonly [Buffer, SignerExpiration, SignerLimits, SignerStorage]} | {tag: "Secp256r1", values: readonly [Buffer, Buffer, SignerExpiration, SignerLimits, SignerStorage]};

/**
 * A signature entry in the signatures map. `Policy` carries no signature
 * material: inclusion of the policy key authorizes an on-chain `policy__`
 * check instead.
 */
export type Signature = {tag: "Policy", values: void} | {tag: "Ed25519", values: readonly [Buffer]} | {tag: "Secp256r1", values: readonly [Secp256r1Signature]};

/**
 * Storage key identifying a signer. Secp256r1 carries the WebAuthn
 * credential id (`keyId`).
 */
export type SignerKey = {tag: "Policy", values: readonly [string]} | {tag: "Ed25519", values: readonly [Buffer]} | {tag: "Secp256r1", values: readonly [Buffer]};

/**
 * Stored signer value. Secp256r1 carries the SEC-1 uncompressed public key.
 */
export type SignerVal = {tag: "Policy", values: readonly [SignerExpiration, SignerLimits]} | {tag: "Ed25519", values: readonly [SignerExpiration, SignerLimits]} | {tag: "Secp256r1", values: readonly [Buffer, SignerExpiration, SignerLimits]};

/**
 * Storage keys for wallet entries that are NOT signer entries. Every variant
 * name here must stay distinct from every `SignerKey` variant name: a
 * `#[contracttype]` enum encodes as `[Symbol(variant), fields…]` with no
 * type name, so a shared variant name would collide in contract storage.
 */
export type BindingKey = {tag: "Secp256r1Binding", values: readonly [Buffer]};

/**
 * The `__check_auth` signature object: a map of signer keys to signatures.
 * Map ordering is the host's ScVal ordering. EVERY entry must verify (pass
 * 2 of `__check_auth`) — include only signatures that are needed.
 */
export type Signatures = readonly [Map<SignerKey, Signature>];

/**
 * Authorization limits for a signer.
 *
 * - `None`: unlimited.
 * - `Some(empty map)`: no independent authority.
 * - `Some({address -> None})`: any invocation of `address`.
 * - `Some({address -> Some([keys])})`: any invocation of `address` only when
 * every listed key also approves.
 *
 * A required key approves independently of its own limits. A required
 * non-policy key must appear in the signatures map and pass full verification.
 * A required policy need not appear there, but it must remain stored and
 * unexpired. It must also approve through `policy__`. Removing it revokes all
 * dependent signers.
 *
 * Limited signers cannot authorize `CreateContract*`. A limited cryptographic
 * signer can remove itself without satisfying its limits. A policy signature
 * always calls `policy__`, including during self-removal. A limit for the
 * wallet address grants access to the wallet administration functions.
 */
export type SignerLimits = readonly [Option<Map<string, Option<Array<SignerKey>>>>];

/**
 * Which durability a signer entry is stored under. At most one entry exists
 * per signer key; lookups check Temporary before Persistent.
 */
export type SignerStorage = {tag: "Persistent", values: void} | {tag: "Temporary", values: void};

/**
 * What a binding proof authorizes. Carried in the challenge preimage AND
 * reflected in the domain separator, so the two proof spaces are disjoint
 * twice over: a GENESIS proof can never be replayed into `add_secp256r1`,
 * and an ADD proof can never seed a constructor.
 */
export type BindingPurpose = {tag: "Genesis", values: void} | {tag: "Add", values: void};

/**
 * Optional expiration for a signer as a UNIX timestamp in seconds, INCLUSIVE:
 * the signer is valid while `ledger timestamp <= expiration` and expired once
 * `ledger timestamp > expiration`. `None` never expires.
 *
 * v1 breaking change: this was a ledger sequence number pre-1.0. Timestamps
 * don't drift with changes to ledger close time (e.g. CAP-0070 dynamic
 * timing), which ledger-sequence expirations did.
 */
export type SignerExpiration = readonly [Option<u64>];


/**
 * A WebAuthn assertion over the Soroban authorization payload. The signed
 * message is `authenticator_data || sha256(client_data_json)` and the
 * payload binding lives in clientDataJSON's `challenge` field.
 */
export interface Secp256r1Signature {
  authenticator_data: Buffer;
  client_data_json: Buffer;
  signature: Buffer;
}


/**
 * A passkey's binding to this wallet: the exact signer it consented to, the
 * purpose that consent was given for, and the WebAuthn assertion it produced
 * over the corresponding challenge.
 *
 * Stored under `BindingKey::Secp256r1Binding(key_id)` in the signer's
 * durability; written only by `__constructor` and `add_secp256r1`, each of
 * which verifies `proof` first.
 *
 * `signer` is the ORIGINAL value and is never rewritten: `update_signer` may
 * reshape the live signer's mutable policy fields, and the record continues
 * to attest what was actually signed. Its key id and public key must still
 * equal the live signer's — `get_secp256r1_binding` enforces that on read.
 */
export interface Secp256r1BindingRecord {
  proof: Secp256r1Signature;
  purpose: BindingPurpose;
  signer: Signer;
}


/**
 * The preimage of a Secp256r1 binding challenge. The challenge is
 * `sha256(XDR(payload))` — see `binding::secp256r1_binding_challenge`.
 *
 * The proof commits to the FULL original `Signer`, not just its key
 * material. A holder consents to one exact signer value on one wallet on one
 * network for one purpose, so a stolen pending proof cannot be re-aimed at a
 * different shape — in particular it cannot be used to seat the holder's
 * passkey with limits that leave the wallet with no admin.
 */
export interface Secp256r1BindingPayload {
  /**
 * The wallet address (`env.current_contract_address()` when checked).
 */
contract: string;
  /**
 * `binding::SECP256R1_GENESIS_DOMAIN` or `binding::SECP256R1_ADD_DOMAIN`.
 */
domain: string;
  /**
 * `env.ledger().network_id()` of the network the wallet lives on.
 */
network_id: Buffer;
  /**
 * Which entry point the proof authorizes.
 */
purpose: BindingPurpose;
  /**
 * The complete signer value the holder consented to, including
 * expiration, limits, and storage durability.
 */
signer: Signer;
}





export interface Client {
  /**
   * Construct and simulate a upgrade transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  upgrade: ({new_wasm_hash}: {new_wasm_hash: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a add_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  add_signer: ({signer}: {signer: Signer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a get_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_signer: ({signer_key}: {signer_key: SignerKey}, options?: MethodOptions) => Promise<AssembledTransaction<Option<SignerVal>>>

  /**
   * Construct and simulate a add_secp256r1 transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  add_secp256r1: ({signer, proof}: {signer: Signer, proof: Secp256r1Signature}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a remove_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  remove_signer: ({signer_key}: {signer_key: SignerKey}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a update_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  update_signer: ({signer}: {signer: Signer}, options?: MethodOptions) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a get_secp256r1_binding transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  get_secp256r1_binding: ({key_id}: {key_id: Buffer}, options?: MethodOptions) => Promise<AssembledTransaction<Option<Secp256r1BindingRecord>>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
        /** Constructor/Initialization Args for the contract's `__constructor` method */
        {signer, proof}: {signer: Signer, proof: Option<Secp256r1Signature>},
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy({signer, proof}, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAAAAAAAAAAAHdXBncmFkZQAAAAABAAAAAAAAAA1uZXdfd2FzbV9oYXNoAAAAAAAD7gAAACAAAAABAAAD6QAAAAIAAAAD",
        "AAAAAAAAAAAAAAAKYWRkX3NpZ25lcgAAAAAAAQAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAAKZ2V0X3NpZ25lcgAAAAAAAQAAAAAAAAAKc2lnbmVyX2tleQAAAAAH0AAAAAlTaWduZXJLZXkAAAAAAAABAAAD6AAAB9AAAAAJU2lnbmVyVmFsAAAA",
        "AAAAAAAAAAAAAAAMX19jaGVja19hdXRoAAAAAwAAAAAAAAARc2lnbmF0dXJlX3BheWxvYWQAAAAAAAPuAAAAIAAAAAAAAAAKc2lnbmF0dXJlcwAAAAAH0AAAAApTaWduYXR1cmVzAAAAAAAAAAAADWF1dGhfY29udGV4dHMAAAAAAAPqAAAH0AAAAAdDb250ZXh0AAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAANX19jb25zdHJ1Y3RvcgAAAAAAAAIAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAAAAAAFcHJvb2YAAAAAAAPoAAAH0AAAABJTZWNwMjU2cjFTaWduYXR1cmUAAAAAAAA=",
        "AAAAAAAAAAAAAAANYWRkX3NlY3AyNTZyMQAAAAAAAAIAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAAAAAAFcHJvb2YAAAAAAAfQAAAAElNlY3AyNTZyMVNpZ25hdHVyZQAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAANcmVtb3ZlX3NpZ25lcgAAAAAAAAEAAAAAAAAACnNpZ25lcl9rZXkAAAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAA+kAAAACAAAAAw==",
        "AAAAAAAAAAAAAAANdXBkYXRlX3NpZ25lcgAAAAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAAAAAAAVZ2V0X3NlY3AyNTZyMV9iaW5kaW5nAAAAAAAAAQAAAAAAAAAGa2V5X2lkAAAAAAAOAAAAAQAAA+gAAAfQAAAAFlNlY3AyNTZyMUJpbmRpbmdSZWNvcmQAAA==",
        "AAAABAAAAXRDb250cmFjdCBlcnJvcnMuCgpEZWxpYmVyYXRlbHkgcmVudW1iZXJlZCBmb3IgdGhlIHYxIGludGVyZmFjZSBzbyB0aGUgZXJyb3Igc3BhY2UgaXMgZGlzam9pbnQKZnJvbSB0aGUgbGVnYWN5IChwcmUtMS4wKSBjb250cmFjdCdzIDEtOSByYW5nZS4gQSBjbGllbnQgZGVjb2RpbmcgYW4gZXJyb3IKY29kZSA8IDEwMCBpcyB0YWxraW5nIHRvIGEgbGVnYWN5IHdhbGxldC4KClJhbmdlczoKLSAxMDAtMTA5OiBzaWduZXIgc3RvcmFnZSAvIG1hbmFnZW1lbnQKLSAxMTAtMTE5OiBhdXRoIChgX19jaGVja19hdXRoYCkKLSAxMjAtMTI5OiBXZWJBdXRobiAoc2VjcDI1NnIxKSB2ZXJpZmljYXRpb24KLSAxMzAtMTM5OiBTZWNwMjU2cjEgc2lnbmVyIGJpbmRpbmcAAAAAAAAABUVycm9yAAAAAAAAEQAAADlUaGUgcmVxdWVzdGVkIHNpZ25lciBkb2VzIG5vdCBleGlzdCBvbiB0aGlzIHNtYXJ0IHdhbGxldC4AAAAAAAAOU2lnbmVyTm90Rm91bmQAAAAAAGQAAAA+YGFkZF9zaWduZXJgIHdhcyBjYWxsZWQgd2l0aCBhIHNpZ25lciBrZXkgdGhhdCBhbHJlYWR5IGV4aXN0cy4AAAAAABNTaWduZXJBbHJlYWR5RXhpc3RzAAAAAGUAAAAxVGhlIHNpZ25lcidzIGV4cGlyYXRpb24gdGltZXN0YW1wIGlzIGluIHRoZSBwYXN0LgAAAAAAAA1TaWduZXJFeHBpcmVkAAAAAAAAZgAAA85UaGUgb3BlcmF0aW9uIHdvdWxkIHJlbW92ZSDigJQgb3IgZGVtb3RlIHZpYSBgdXBkYXRlX3NpZ25lcmAg4oCUIHRoZQp3YWxsZXQncyBMQVNUIGR1cmFibGUgYWRtaW4gc2lnbmVyOiBhIHNpZ25lciBzdG9yZWQgYFBlcnNpc3RlbnRgLApub24tZXhwaXJpbmcgKGBTaWduZXJFeHBpcmF0aW9uKE5vbmUpYCksIGFuZCBpbmRlcGVuZGVudGx5CmFkbWluLWNhcGFibGUg4oCUIGVpdGhlciB1bmxpbWl0ZWQgKGBTaWduZXJMaW1pdHMoTm9uZSlgKSBvciBob2xkaW5nIGEKbGltaXRzIGVudHJ5IGZvciB0aGUgd2FsbGV0J3Mgb3duIGFkZHJlc3Mgd2l0aCBubyByZXF1aXJlZCBjby1zaWduZXJzCihgTm9uZWAgb3IgYW4gZW1wdHkgbGlzdCkuIFdpdGggemVybyBzdWNoIHNpZ25lcnMgbm8gYGFkZF9zaWduZXJgIG9yCmB1cGdyYWRlYCBjb3VsZCBldmVyIGJlIGF1dGhvcml6ZWQgYWdhaW4sIHBlcm1hbmVudGx5IGxvY2tpbmcgdGhlCndhbGxldCBvbiBhbiBpbW11dGFibGUgbmV0d29yaywgc28gdGhlIHRyYW5zaXRpb24gaXMgcmVqZWN0ZWQuClRvIHJldGlyZSB0aGUgbGFzdCBhZG1pbiBzaWduZXIsIGFkZCAob3IgcHJvbW90ZSkgYSByZXBsYWNlbWVudApkdXJhYmxlIGFkbWluIHNpZ25lciBmaXJzdC4KCkNhc2UgdGhpcyBndWFyZCBDQU5OT1QgY2F0Y2ggKHN0YXRpY2FsbHkgdW5kZWNpZGFibGUpOiBhIFBPTElDWQpzaWduZXIgd2l0aCBhbiBhZG1pbi1zaGFwZWQgZ3JhbnQgY291bnRzIGFzIGFuIGFkbWluIGV2ZW4gaWYgaXRzCmBwb2xpY3lfX2AgcmVqZWN0cyBldmVyeSByZXF1ZXN0LiBJZiBzdWNoIGEgcG9saWN5IGlzIHlvdXIgb25seQpyZW1haW5pbmcgYWRtaW4sIHRoZSB3YWxsZXQncyBhZG1pbiBzdXJmYWNlIGlzIHVucmVjb3ZlcmFibGUgZXZlbgp0aG91Z2ggdGhlIHNpZ25lciBzdGlsbCBleGlzdHMuIEtlZXAgYSBub24tcG9saWN5IGFkbWluIChvciBhIHNlY29uZAphZG1pbikgYXQgYWxsIHRpbWVzLgAAAAAAD0xhc3RBZG1pblNpZ25lcgAAAABnAAAC0VRoZSBvcGVyYXRpb24gd291bGQgbGVhdmUgdGhlIHdhbGxldCB3aXRob3V0IGFueSBEVVJBQkxFIHNpZ25lciDigJQgb25lCnN0b3JlZCBgUGVyc2lzdGVudGAgd2l0aCBgU2lnbmVyRXhwaXJhdGlvbihOb25lKWAsIGFueSBsaW1pdHMuIEZpcmVkCmJ5IGByZW1vdmVfc2lnbmVyYCAocmVtb3ZpbmcgdGhlIGxhc3QgZHVyYWJsZSBzaWduZXIpLCBgdXBkYXRlX3NpZ25lcmAKKGRlbW90aW5nIGl0IHRvIGBUZW1wb3JhcnlgIHN0b3JhZ2Ugb3IgdG8gYW4gZXhwaXJpbmcgdmFsdWUpLCBhbmQKYF9fY29uc3RydWN0b3JgICh0aGUgd2FsbGV0J3MgZmlyc3Qgc2lnbmVyIG11c3QgYmUgZHVyYWJsZSkuCk5vbi1kdXJhYmxlIHNpZ25lcnMgY2FuIGV2aWN0IG9yIGV4cGlyZSB3aXRoIE5PIGNvbnRyYWN0CmNhbGwsIHNvIG9ubHkgYSBkdXJhYmxlIHNpZ25lciBndWFyYW50ZWVzIHRoZSB3YWxsZXQgYWx3YXlzIGtlZXBzIGF0CmxlYXN0IG9uZSBsaXZlIHNpZ25lcjsgd2l0aCB6ZXJvIGxpdmUgc2lnbmVycyBub3RoaW5nIOKAlCBub3QgZXZlbgpgYWRkX3NpZ25lcmAg4oCUIGNhbiBldmVyIGJlIGF1dGhvcml6ZWQgYWdhaW4uIFRoaXMgaXMgdGhlCmNsYXNzaWZpY2F0aW9uLWluZGVwZW5kZW50IGJhY2tzdG9wIGJlbmVhdGggYExhc3RBZG1pblNpZ25lcmAuIFRvCnJldGlyZSB0aGUgbGFzdCBkdXJhYmxlIHNpZ25lciwgYWRkIGEgZHVyYWJsZSByZXBsYWNlbWVudCBmaXJzdC4AAAAAAAAKTGFzdFNpZ25lcgAAAAAAaAAAAF1ObyBzaWduZXIgaW4gdGhlIHNpZ25hdHVyZXMgbWFwIGlzIHBlcm1pdHRlZCB0byBhdXRob3JpemUgb25lIG9mIHRoZQpyZXF1ZXN0ZWQgYXV0aCBjb250ZXh0cy4AAAAAAAAOTWlzc2luZ0NvbnRleHQAAAAAAG4AAACJQSBzaWduYXR1cmUncyB2YXJpYW50IGRvZXMgbm90IG1hdGNoIHRoZSBzdG9yZWQgc2lnbmVyIGl0IGNsYWltcyB0byBiZQpmb3IgKGUuZy4gYW4gRWQyNTUxOSBzaWduYXR1cmUgc3VibWl0dGVkIGZvciBhIFBvbGljeSBzaWduZXIga2V5KS4AAAAAAAAZU2lnbmF0dXJlS2V5VmFsdWVNaXNtYXRjaAAAAAAAAG8AAAAyY2xpZW50RGF0YUpTT04gZXhjZWVkcyB0aGUgMTAyNCBieXRlIHBhcnNlIGJ1ZmZlci4AAAAAABZDbGllbnREYXRhSnNvblRvb0xhcmdlAAAAAAB4AAAARWNsaWVudERhdGFKU09OIGlzIG5vdCBwYXJzZWFibGUgSlNPTiAob3IgaXMgbWlzc2luZyByZXF1aXJlZCBmaWVsZHMpLgAAAAAAABhDbGllbnREYXRhSnNvblBhcnNlRXJyb3IAAAB5AAAAtlRoZSBjaGFsbGVuZ2UgaW4gY2xpZW50RGF0YUpTT04gZG9lcyBub3QgbWF0Y2ggdGhlIGJhc2U2NHVybC1lbmNvZGVkCnNpZ25hdHVyZSBwYXlsb2FkLiBUaGlzIGJpbmRzIHRoZSBXZWJBdXRobiBhc3NlcnRpb24gdG8gdGhlIFNvcm9iYW4KYXV0aG9yaXphdGlvbiBlbnRyeSBhbmQgTVVTVCBOT1QgYmUgd2Vha2VuZWQuAAAAAAAgQ2xpZW50RGF0YUpzb25DaGFsbGVuZ2VJbmNvcnJlY3QAAAB6AAAALGNsaWVudERhdGFKU09OIGB0eXBlYCBpcyBub3QgIndlYmF1dGhuLmdldCIuAAAAE0ludmFsaWRXZWJBdXRoblR5cGUAAAAAewAAAGlhdXRoZW50aWNhdG9yRGF0YSBpcyBzaG9ydGVyIHRoYW4gdGhlIFdlYkF1dGhuIG1pbmltdW0gb2YgMzcgYnl0ZXMKKHJwSWRIYXNoIDMyICsgZmxhZ3MgMSArIHNpZ25Db3VudCA0KS4AAAAAAAAYSW52YWxpZEF1dGhlbnRpY2F0b3JEYXRhAAAAfAAAAkxUaGUgYXV0aGVudGljYXRvciBkaWQgbm90IHNldCB0aGUgVXNlciBQcmVzZW50IChVUCkgZmxhZy4KClVQLW9ubHkgaXMgdGhlIGRlbGliZXJhdGUgZGVmYXVsdC4gUmVxdWlyaW5nIFVQIGtlZXBzCnNpbGVudCwgbm9uLWludGVyYWN0aXZlIGFzc2VydGlvbnMgb3V0IHdoaWxlIHN0YXlpbmcgY29tcGF0aWJsZSB3aXRoCmF1dGhlbnRpY2F0b3JzIHRoYXQgY2Fubm90IGRvIFVzZXIgVmVyaWZpY2F0aW9uIChVViDigJQgYmlvbWV0cmljL1BJTikuClVWIGlzIHRoZXJlZm9yZSBOT1QgcmVxdWlyZWQgYnkgdGhpcyBjb250cmFjdC4gQSBkZXBsb3ltZW50IHRoYXQgd2FudHMKVVYtcmVxdWlyZWQgYXNzZXJ0aW9ucyBzaG91bGQgZW5mb3JjZSBpdCBhdCB0aGUgY2xpZW50L3JlbGF5ZXIgbGF5ZXIsCm9yIHZpYSBhIGZ1dHVyZSBwZXItc2lnbmVyIGZsYWcgKHdoaWNoIHdvdWxkIGJlIGEgc2lnbmVyLW1vZGVsIGNoYW5nZSwKbm90IGEgY2hhbmdlIHRvIHRoaXMgY2hlY2spOyB0aGUgY29udHJhY3QgY2Fubm90IHVwZ3JhZGUgVVAtb25seQpzaWduZXJzIHRvIFVWLXJlcXVpcmVkIHJldHJvYWN0aXZlbHkgd2l0aG91dCBzdWNoIGEgZmxhZy4AAAAUVXNlclByZXNlbmNlUmVxdWlyZWQAAAB9AAAA4mF1dGhlbnRpY2F0b3JEYXRhIGV4Y2VlZHMgdGhlIDEwMjQgYnl0ZSBjYXAgKHN5bW1ldHJpYyB3aXRoCmBDbGllbnREYXRhSnNvblRvb0xhcmdlYCkuIFJlYWwgYXNzZXJ0aW9ucyBhcmUgfjM3IGJ5dGVzOyB0aGUgY2FwCnJlamVjdHMgb3ZlcnNpemVkIGlucHV0IEJFRk9SRSBpdCBpcyBoYXNoZWQsIHNpbmNlIHRoaXMgcGF0aCBpcwpyZWFjaGFibGUgd2l0aG91dCBhIHZhbGlkIHNpZ25hdHVyZS4AAAAAABlBdXRoZW50aWNhdG9yRGF0YVRvb0xhcmdlAAAAAAAAfgAAAMpBIFNlY3AyNTZyMSBzaWduZXIgd2FzIHN1cHBsaWVkIHdpdGhvdXQgaXRzIGJpbmRpbmcgcHJvb2YuIFBhc3NrZXlzCmVudGVyIGEgd2FsbGV0IG9ubHkgdGhyb3VnaCBgX19jb25zdHJ1Y3RvcmAgKEdFTkVTSVMgcHJvb2YpIG9yCmBhZGRfc2VjcDI1NnIxYCAoQUREIHByb29mKSDigJQgbmV2ZXIgdGhyb3VnaCB0aGUgZ2VuZXJpYyBgYWRkX3NpZ25lcmAuAAAAAAAUQmluZGluZ1Byb29mUmVxdWlyZWQAAACCAAAAQEEgYmluZGluZyBwcm9vZiB3YXMgc3VwcGxpZWQgZm9yIGEgc2lnbmVyIHRoYXQgaXMgbm90IFNlY3AyNTZyMS4AAAAWQmluZGluZ1Byb29mVW5leHBlY3RlZAAAAAAAgwAAARVgdXBkYXRlX3NpZ25lcmAgbWF5IG5vdCBjaGFuZ2UgYSBTZWNwMjU2cjEgc2lnbmVyJ3MgcHVibGljIGtleTogdGhlCmJpbmRpbmcgcHJvb2YgY29tbWl0cyB0byBpdC4gUmVtb3ZlIHRoZSBzaWduZXIgYW5kIHJlLWFkZCBpdCB3aXRoIGEKZnJlc2ggcHJvb2YgdGhyb3VnaCBgYWRkX3NlY3AyNTZyMWAgaW5zdGVhZC4KCkNvZGUgMTMyIGlzIHJldGlyZWQgd2l0aCBgYmluZF9zZWNwMjU2cjFgOyAxMzQgd2l0aCBpdHMKYWxyZWFkeS1ib3VuZCBndWFyZC4gTmVpdGhlciBpcyByZXVzZWQuAAAAAAAAGUJpbmRpbmdQdWJsaWNLZXlJbW11dGFibGUAAAAAAACF",
        "AAAAAgAAAFJGdWxsIHNpZ25lciBkZXNjcmlwdGlvbiB1c2VkIGJ5IGBfX2NvbnN0cnVjdG9yYCwgYGFkZF9zaWduZXJgIGFuZApgdXBkYXRlX3NpZ25lcmAuAAAAAAAAAAAABlNpZ25lcgAAAAAAAwAAAAEAAAAAAAAABlBvbGljeQAAAAAABAAAABMAAAfQAAAAEFNpZ25lckV4cGlyYXRpb24AAAfQAAAADFNpZ25lckxpbWl0cwAAB9AAAAANU2lnbmVyU3RvcmFnZQAAAAAAAAEAAAAAAAAAB0VkMjU1MTkAAAAABAAAA+4AAAAgAAAH0AAAABBTaWduZXJFeHBpcmF0aW9uAAAH0AAAAAxTaWduZXJMaW1pdHMAAAfQAAAADVNpZ25lclN0b3JhZ2UAAAAAAAABAAAAAAAAAAlTZWNwMjU2cjEAAAAAAAAFAAAADgAAA+4AAABBAAAH0AAAABBTaWduZXJFeHBpcmF0aW9uAAAH0AAAAAxTaWduZXJMaW1pdHMAAAfQAAAADVNpZ25lclN0b3JhZ2UAAAA=",
        "AAAAAgAAAJ1BIHNpZ25hdHVyZSBlbnRyeSBpbiB0aGUgc2lnbmF0dXJlcyBtYXAuIGBQb2xpY3lgIGNhcnJpZXMgbm8gc2lnbmF0dXJlCm1hdGVyaWFsOiBpbmNsdXNpb24gb2YgdGhlIHBvbGljeSBrZXkgYXV0aG9yaXplcyBhbiBvbi1jaGFpbiBgcG9saWN5X19gCmNoZWNrIGluc3RlYWQuAAAAAAAAAAAAAAlTaWduYXR1cmUAAAAAAAADAAAAAAAAAAAAAAAGUG9saWN5AAAAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAQAAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAEAAAfQAAAAElNlY3AyNTZyMVNpZ25hdHVyZQAA",
        "AAAAAgAAAFlTdG9yYWdlIGtleSBpZGVudGlmeWluZyBhIHNpZ25lci4gU2VjcDI1NnIxIGNhcnJpZXMgdGhlIFdlYkF1dGhuCmNyZWRlbnRpYWwgaWQgKGBrZXlJZGApLgAAAAAAAAAAAAAJU2lnbmVyS2V5AAAAAAAAAwAAAAEAAAAAAAAABlBvbGljeQAAAAAAAQAAABMAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAEAAAPuAAAAIAAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAEAAAAO",
        "AAAAAgAAAElTdG9yZWQgc2lnbmVyIHZhbHVlLiBTZWNwMjU2cjEgY2FycmllcyB0aGUgU0VDLTEgdW5jb21wcmVzc2VkIHB1YmxpYyBrZXkuAAAAAAAAAAAAAAlTaWduZXJWYWwAAAAAAAADAAAAAQAAAAAAAAAGUG9saWN5AAAAAAACAAAH0AAAABBTaWduZXJFeHBpcmF0aW9uAAAH0AAAAAxTaWduZXJMaW1pdHMAAAABAAAAAAAAAAdFZDI1NTE5AAAAAAIAAAfQAAAAEFNpZ25lckV4cGlyYXRpb24AAAfQAAAADFNpZ25lckxpbWl0cwAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAMAAAPuAAAAQQAAB9AAAAAQU2lnbmVyRXhwaXJhdGlvbgAAB9AAAAAMU2lnbmVyTGltaXRz",
        "AAAAAgAAAR5TdG9yYWdlIGtleXMgZm9yIHdhbGxldCBlbnRyaWVzIHRoYXQgYXJlIE5PVCBzaWduZXIgZW50cmllcy4gRXZlcnkgdmFyaWFudApuYW1lIGhlcmUgbXVzdCBzdGF5IGRpc3RpbmN0IGZyb20gZXZlcnkgYFNpZ25lcktleWAgdmFyaWFudCBuYW1lOiBhCmAjW2NvbnRyYWN0dHlwZV1gIGVudW0gZW5jb2RlcyBhcyBgW1N5bWJvbCh2YXJpYW50KSwgZmllbGRz4oCmXWAgd2l0aCBubwp0eXBlIG5hbWUsIHNvIGEgc2hhcmVkIHZhcmlhbnQgbmFtZSB3b3VsZCBjb2xsaWRlIGluIGNvbnRyYWN0IHN0b3JhZ2UuAAAAAAAAAAAACkJpbmRpbmdLZXkAAAAAAAEAAAABAAAAdkEgYFNlY3AyNTZyMUJpbmRpbmdSZWNvcmRgLCBrZXllZCBieSB0aGUgc2lnbmVyJ3MgY3JlZGVudGlhbCBpZCBhbmQKc3RvcmVkIGluIHRoZSBzYW1lIGR1cmFiaWxpdHkgYXMgdGhlIHNpZ25lciBlbnRyeS4AAAAAABBTZWNwMjU2cjFCaW5kaW5nAAAAAQAAAA4=",
        "AAAAAQAAANNUaGUgYF9fY2hlY2tfYXV0aGAgc2lnbmF0dXJlIG9iamVjdDogYSBtYXAgb2Ygc2lnbmVyIGtleXMgdG8gc2lnbmF0dXJlcy4KTWFwIG9yZGVyaW5nIGlzIHRoZSBob3N0J3MgU2NWYWwgb3JkZXJpbmcuIEVWRVJZIGVudHJ5IG11c3QgdmVyaWZ5IChwYXNzCjIgb2YgYF9fY2hlY2tfYXV0aGApIOKAlCBpbmNsdWRlIG9ubHkgc2lnbmF0dXJlcyB0aGF0IGFyZSBuZWVkZWQuAAAAAAAAAAAKU2lnbmF0dXJlcwAAAAAAAQAAAAAAAAABMAAAAAAAA+wAAAfQAAAACVNpZ25lcktleQAAAAAAB9AAAAAJU2lnbmF0dXJlAAAA",
        "AAAAAQAAA2lBdXRob3JpemF0aW9uIGxpbWl0cyBmb3IgYSBzaWduZXIuCgotIGBOb25lYDogdW5saW1pdGVkLgotIGBTb21lKGVtcHR5IG1hcClgOiBubyBpbmRlcGVuZGVudCBhdXRob3JpdHkuCi0gYFNvbWUoe2FkZHJlc3MgLT4gTm9uZX0pYDogYW55IGludm9jYXRpb24gb2YgYGFkZHJlc3NgLgotIGBTb21lKHthZGRyZXNzIC0+IFNvbWUoW2tleXNdKX0pYDogYW55IGludm9jYXRpb24gb2YgYGFkZHJlc3NgIG9ubHkgd2hlbgpldmVyeSBsaXN0ZWQga2V5IGFsc28gYXBwcm92ZXMuCgpBIHJlcXVpcmVkIGtleSBhcHByb3ZlcyBpbmRlcGVuZGVudGx5IG9mIGl0cyBvd24gbGltaXRzLiBBIHJlcXVpcmVkCm5vbi1wb2xpY3kga2V5IG11c3QgYXBwZWFyIGluIHRoZSBzaWduYXR1cmVzIG1hcCBhbmQgcGFzcyBmdWxsIHZlcmlmaWNhdGlvbi4KQSByZXF1aXJlZCBwb2xpY3kgbmVlZCBub3QgYXBwZWFyIHRoZXJlLCBidXQgaXQgbXVzdCByZW1haW4gc3RvcmVkIGFuZAp1bmV4cGlyZWQuIEl0IG11c3QgYWxzbyBhcHByb3ZlIHRocm91Z2ggYHBvbGljeV9fYC4gUmVtb3ZpbmcgaXQgcmV2b2tlcyBhbGwKZGVwZW5kZW50IHNpZ25lcnMuCgpMaW1pdGVkIHNpZ25lcnMgY2Fubm90IGF1dGhvcml6ZSBgQ3JlYXRlQ29udHJhY3QqYC4gQSBsaW1pdGVkIGNyeXB0b2dyYXBoaWMKc2lnbmVyIGNhbiByZW1vdmUgaXRzZWxmIHdpdGhvdXQgc2F0aXNmeWluZyBpdHMgbGltaXRzLiBBIHBvbGljeSBzaWduYXR1cmUKYWx3YXlzIGNhbGxzIGBwb2xpY3lfX2AsIGluY2x1ZGluZyBkdXJpbmcgc2VsZi1yZW1vdmFsLiBBIGxpbWl0IGZvciB0aGUKd2FsbGV0IGFkZHJlc3MgZ3JhbnRzIGFjY2VzcyB0byB0aGUgd2FsbGV0IGFkbWluaXN0cmF0aW9uIGZ1bmN0aW9ucy4AAAAAAAAAAAAADFNpZ25lckxpbWl0cwAAAAEAAAAAAAAAATAAAAAAAAPoAAAD7AAAABMAAAPoAAAD6gAAB9AAAAAJU2lnbmVyS2V5AAAA",
        "AAAAAgAAAIRXaGljaCBkdXJhYmlsaXR5IGEgc2lnbmVyIGVudHJ5IGlzIHN0b3JlZCB1bmRlci4gQXQgbW9zdCBvbmUgZW50cnkgZXhpc3RzCnBlciBzaWduZXIga2V5OyBsb29rdXBzIGNoZWNrIFRlbXBvcmFyeSBiZWZvcmUgUGVyc2lzdGVudC4AAAAAAAAADVNpZ25lclN0b3JhZ2UAAAAAAAACAAAAAAAAAAAAAAAKUGVyc2lzdGVudAAAAAAAAAAAAAAAAAAJVGVtcG9yYXJ5AAAA",
        "AAAAAgAAAQVXaGF0IGEgYmluZGluZyBwcm9vZiBhdXRob3JpemVzLiBDYXJyaWVkIGluIHRoZSBjaGFsbGVuZ2UgcHJlaW1hZ2UgQU5ECnJlZmxlY3RlZCBpbiB0aGUgZG9tYWluIHNlcGFyYXRvciwgc28gdGhlIHR3byBwcm9vZiBzcGFjZXMgYXJlIGRpc2pvaW50CnR3aWNlIG92ZXI6IGEgR0VORVNJUyBwcm9vZiBjYW4gbmV2ZXIgYmUgcmVwbGF5ZWQgaW50byBgYWRkX3NlY3AyNTZyMWAsCmFuZCBhbiBBREQgcHJvb2YgY2FuIG5ldmVyIHNlZWQgYSBjb25zdHJ1Y3Rvci4AAAAAAAAAAAAADkJpbmRpbmdQdXJwb3NlAAAAAAACAAAAAAAAADdUaGUgd2FsbGV0J3MgZmlyc3Qgc2lnbmVyLCBzdXBwbGllZCB0byBgX19jb25zdHJ1Y3RvcmAuAAAAAAdHZW5lc2lzAAAAAAAAAAAsQSBsYXRlciBzaWduZXIsIHN1cHBsaWVkIHRvIGBhZGRfc2VjcDI1NnIxYC4AAAADQWRkAA==",
        "AAAAAQAAAY5PcHRpb25hbCBleHBpcmF0aW9uIGZvciBhIHNpZ25lciBhcyBhIFVOSVggdGltZXN0YW1wIGluIHNlY29uZHMsIElOQ0xVU0lWRToKdGhlIHNpZ25lciBpcyB2YWxpZCB3aGlsZSBgbGVkZ2VyIHRpbWVzdGFtcCA8PSBleHBpcmF0aW9uYCBhbmQgZXhwaXJlZCBvbmNlCmBsZWRnZXIgdGltZXN0YW1wID4gZXhwaXJhdGlvbmAuIGBOb25lYCBuZXZlciBleHBpcmVzLgoKdjEgYnJlYWtpbmcgY2hhbmdlOiB0aGlzIHdhcyBhIGxlZGdlciBzZXF1ZW5jZSBudW1iZXIgcHJlLTEuMC4gVGltZXN0YW1wcwpkb24ndCBkcmlmdCB3aXRoIGNoYW5nZXMgdG8gbGVkZ2VyIGNsb3NlIHRpbWUgKGUuZy4gQ0FQLTAwNzAgZHluYW1pYwp0aW1pbmcpLCB3aGljaCBsZWRnZXItc2VxdWVuY2UgZXhwaXJhdGlvbnMgZGlkLgAAAAAAAAAAABBTaWduZXJFeHBpcmF0aW9uAAAAAQAAAAAAAAABMAAAAAAAA+gAAAAG",
        "AAAAAQAAAMhBIFdlYkF1dGhuIGFzc2VydGlvbiBvdmVyIHRoZSBTb3JvYmFuIGF1dGhvcml6YXRpb24gcGF5bG9hZC4gVGhlIHNpZ25lZAptZXNzYWdlIGlzIGBhdXRoZW50aWNhdG9yX2RhdGEgfHwgc2hhMjU2KGNsaWVudF9kYXRhX2pzb24pYCBhbmQgdGhlCnBheWxvYWQgYmluZGluZyBsaXZlcyBpbiBjbGllbnREYXRhSlNPTidzIGBjaGFsbGVuZ2VgIGZpZWxkLgAAAAAAAAASU2VjcDI1NnIxU2lnbmF0dXJlAAAAAAADAAAAAAAAABJhdXRoZW50aWNhdG9yX2RhdGEAAAAAAA4AAAAAAAAAEGNsaWVudF9kYXRhX2pzb24AAAAOAAAAAAAAAAlzaWduYXR1cmUAAAAAAAPuAAAAQA==",
        "AAAAAQAAAoxBIHBhc3NrZXkncyBiaW5kaW5nIHRvIHRoaXMgd2FsbGV0OiB0aGUgZXhhY3Qgc2lnbmVyIGl0IGNvbnNlbnRlZCB0bywgdGhlCnB1cnBvc2UgdGhhdCBjb25zZW50IHdhcyBnaXZlbiBmb3IsIGFuZCB0aGUgV2ViQXV0aG4gYXNzZXJ0aW9uIGl0IHByb2R1Y2VkCm92ZXIgdGhlIGNvcnJlc3BvbmRpbmcgY2hhbGxlbmdlLgoKU3RvcmVkIHVuZGVyIGBCaW5kaW5nS2V5OjpTZWNwMjU2cjFCaW5kaW5nKGtleV9pZClgIGluIHRoZSBzaWduZXIncwpkdXJhYmlsaXR5OyB3cml0dGVuIG9ubHkgYnkgYF9fY29uc3RydWN0b3JgIGFuZCBgYWRkX3NlY3AyNTZyMWAsIGVhY2ggb2YKd2hpY2ggdmVyaWZpZXMgYHByb29mYCBmaXJzdC4KCmBzaWduZXJgIGlzIHRoZSBPUklHSU5BTCB2YWx1ZSBhbmQgaXMgbmV2ZXIgcmV3cml0dGVuOiBgdXBkYXRlX3NpZ25lcmAgbWF5CnJlc2hhcGUgdGhlIGxpdmUgc2lnbmVyJ3MgbXV0YWJsZSBwb2xpY3kgZmllbGRzLCBhbmQgdGhlIHJlY29yZCBjb250aW51ZXMKdG8gYXR0ZXN0IHdoYXQgd2FzIGFjdHVhbGx5IHNpZ25lZC4gSXRzIGtleSBpZCBhbmQgcHVibGljIGtleSBtdXN0IHN0aWxsCmVxdWFsIHRoZSBsaXZlIHNpZ25lcidzIOKAlCBgZ2V0X3NlY3AyNTZyMV9iaW5kaW5nYCBlbmZvcmNlcyB0aGF0IG9uIHJlYWQuAAAAAAAAABZTZWNwMjU2cjFCaW5kaW5nUmVjb3JkAAAAAAADAAAAAAAAAAVwcm9vZgAAAAAAB9AAAAASU2VjcDI1NnIxU2lnbmF0dXJlAAAAAAAAAAAAB3B1cnBvc2UAAAAH0AAAAA5CaW5kaW5nUHVycG9zZQAAAAAAAAAAAAZzaWduZXIAAAAAB9AAAAAGU2lnbmVyAAA=",
        "AAAAAQAAAeFUaGUgcHJlaW1hZ2Ugb2YgYSBTZWNwMjU2cjEgYmluZGluZyBjaGFsbGVuZ2UuIFRoZSBjaGFsbGVuZ2UgaXMKYHNoYTI1NihYRFIocGF5bG9hZCkpYCDigJQgc2VlIGBiaW5kaW5nOjpzZWNwMjU2cjFfYmluZGluZ19jaGFsbGVuZ2VgLgoKVGhlIHByb29mIGNvbW1pdHMgdG8gdGhlIEZVTEwgb3JpZ2luYWwgYFNpZ25lcmAsIG5vdCBqdXN0IGl0cyBrZXkKbWF0ZXJpYWwuIEEgaG9sZGVyIGNvbnNlbnRzIHRvIG9uZSBleGFjdCBzaWduZXIgdmFsdWUgb24gb25lIHdhbGxldCBvbiBvbmUKbmV0d29yayBmb3Igb25lIHB1cnBvc2UsIHNvIGEgc3RvbGVuIHBlbmRpbmcgcHJvb2YgY2Fubm90IGJlIHJlLWFpbWVkIGF0IGEKZGlmZmVyZW50IHNoYXBlIOKAlCBpbiBwYXJ0aWN1bGFyIGl0IGNhbm5vdCBiZSB1c2VkIHRvIHNlYXQgdGhlIGhvbGRlcidzCnBhc3NrZXkgd2l0aCBsaW1pdHMgdGhhdCBsZWF2ZSB0aGUgd2FsbGV0IHdpdGggbm8gYWRtaW4uAAAAAAAAAAAAABdTZWNwMjU2cjFCaW5kaW5nUGF5bG9hZAAAAAAFAAAAQ1RoZSB3YWxsZXQgYWRkcmVzcyAoYGVudi5jdXJyZW50X2NvbnRyYWN0X2FkZHJlc3MoKWAgd2hlbiBjaGVja2VkKS4AAAAACGNvbnRyYWN0AAAAEwAAAEdgYmluZGluZzo6U0VDUDI1NlIxX0dFTkVTSVNfRE9NQUlOYCBvciBgYmluZGluZzo6U0VDUDI1NlIxX0FERF9ET01BSU5gLgAAAAAGZG9tYWluAAAAAAARAAAAP2BlbnYubGVkZ2VyKCkubmV0d29ya19pZCgpYCBvZiB0aGUgbmV0d29yayB0aGUgd2FsbGV0IGxpdmVzIG9uLgAAAAAKbmV0d29ya19pZAAAAAAD7gAAACAAAAAnV2hpY2ggZW50cnkgcG9pbnQgdGhlIHByb29mIGF1dGhvcml6ZXMuAAAAAAdwdXJwb3NlAAAAB9AAAAAOQmluZGluZ1B1cnBvc2UAAAAAAGhUaGUgY29tcGxldGUgc2lnbmVyIHZhbHVlIHRoZSBob2xkZXIgY29uc2VudGVkIHRvLCBpbmNsdWRpbmcKZXhwaXJhdGlvbiwgbGltaXRzLCBhbmQgc3RvcmFnZSBkdXJhYmlsaXR5LgAAAAZzaWduZXIAAAAAB9AAAAAGU2lnbmVyAAA=",
        "AAAABQAAASBUaGUgY29udHJhY3QncyB3YXNtIHdhcyByZXBsYWNlZCB2aWEgYHVwZ3JhZGVgLiBgb2xkX2hhc2hgIGlzIGBOb25lYCBvbiBhCndhbGxldCdzIGZpcnN0LWV2ZXIgdXBncmFkZTogdGhlIGhvc3QgZXhwb3NlcyBubyB3YXkgZm9yIGEgY29udHJhY3QgdG8KcmVhZCBpdHMgb3duIGV4ZWN1dGFibGUgaGFzaCwgc28gdGhlIHdhbGxldCBjYWNoZXMgdGhlIGhhc2ggaW4gaW5zdGFuY2UKc3RvcmFnZSBhdCBlYWNoIHVwZ3JhZGUgYW5kIHRoZSBnZW5lc2lzIGhhc2ggaXMgdW5rbm93YWJsZSBpbi1jb250cmFjdC4AAAAAAAAACFVwZ3JhZGVkAAAAAQAAAAh1cGdyYWRlZAAAAAIAAAAAAAAACG9sZF9oYXNoAAAD6AAAA+4AAAAgAAAAAAAAAAAAAAAIbmV3X2hhc2gAAAPuAAAAIAAAAAAAAAAC",
        "AAAABQAAADlBIHNpZ25lciB3YXMgYWRkZWQgKHZpYSBgX19jb25zdHJ1Y3RvcmAgb3IgYGFkZF9zaWduZXJgKS4AAAAAAAAAAAAAC1NpZ25lckFkZGVkAAAAAAEAAAAMc2lnbmVyX2FkZGVkAAAAAwAAAAAAAAADa2V5AAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAAAAAAAADdmFsAAAAB9AAAAAJU2lnbmVyVmFsAAAAAAAAAAAAAAAAAAAHc3RvcmFnZQAAAAfQAAAADVNpZ25lclN0b3JhZ2UAAAAAAAAAAAAAAg==",
        "AAAABQAAAGFBIHNpZ25lciB3YXMgcmVtb3ZlZCB2aWEgYHJlbW92ZV9zaWduZXJgLiBgc3RvcmFnZWAgaXMgdGhlIGR1cmFiaWxpdHkgdGhlCmVudHJ5IHdhcyByZW1vdmVkIGZyb20uAAAAAAAAAAAAAA1TaWduZXJSZW1vdmVkAAAAAAAAAQAAAA5zaWduZXJfcmVtb3ZlZAAAAAAAAgAAAAAAAAADa2V5AAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAAAAAAAAHc3RvcmFnZQAAAAfQAAAADVNpZ25lclN0b3JhZ2UAAAAAAAAAAAAAAg==",
        "AAAABQAAADRBbiBleGlzdGluZyBzaWduZXIgd2FzIG1vZGlmaWVkIHZpYSBgdXBkYXRlX3NpZ25lcmAuAAAAAAAAAA1TaWduZXJVcGRhdGVkAAAAAAAAAQAAAA5zaWduZXJfdXBkYXRlZAAAAAAABAAAAAAAAAADa2V5AAAAB9AAAAAJU2lnbmVyS2V5AAAAAAAAAQAAAAAAAAADdmFsAAAAB9AAAAAJU2lnbmVyVmFsAAAAAAAAAAAAAAAAAAAHc3RvcmFnZQAAAAfQAAAADVNpZ25lclN0b3JhZ2UAAAAAAAAAAAAAAAAAAAtvbGRfc3RvcmFnZQAAAAfQAAAADVNpZ25lclN0b3JhZ2UAAAAAAAAAAAAAAg==" ]),
      options
    )
  }
  public readonly fromJSON = {
    upgrade: this.txFromJSON<Result<void>>,
        add_signer: this.txFromJSON<Result<void>>,
        get_signer: this.txFromJSON<Option<SignerVal>>,
        add_secp256r1: this.txFromJSON<Result<void>>,
        remove_signer: this.txFromJSON<Result<void>>,
        update_signer: this.txFromJSON<Result<void>>,
        get_secp256r1_binding: this.txFromJSON<Option<Secp256r1BindingRecord>>
  }
}