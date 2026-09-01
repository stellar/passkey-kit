/**
 * Client-side cryptography for the Secp256r1 signer-binding protocol.
 *
 * Three things live here, all browser-safe (WebCrypto + stellar-sdk hashing,
 * no Node-only modules):
 *
 * 1. **The binding challenge.** `sha256(XDR(Secp256r1BindingPayload))`, where
 *    the payload contains the network, wallet, purpose, and complete original
 *    signer. GENESIS and ADD use separate domains. The payload is encoded
 *    through the contract `Spec` and canonicalized to the host's map order.
 *    This is the exact value the wallet contract recomputes.
 *
 * 2. **WebAuthn assertion verification.** For a STORED proof (the contract's
 *    64-byte compact `r||s` signature) and for a FRESH `AuthenticationResponseJSON`
 *    (DER signature straight from the authenticator). Checks: clientDataJSON
 *    `type`, `challenge`, optional origin allowlist, `rpIdHash`, User Presence,
 *    optional User Verification, the credential id where one is available, and
 *    the P-256 signature over `authenticatorData || sha256(clientDataJSON)`.
 *
 * 3. **Binding-record verification.** The record's immutable `keyId` and
 *    `publicKey` must equal the LIVE signer entry. The proof verifies
 *    against the ORIGINAL signer in the record. This permits authorized policy
 *    updates without changing the signed deployment or addition consent.
 *    The caller must also verify the wallet's accepted birth code. Custom birth
 *    code can copy a pending proof before it upgrades to accepted current code.
 *
 * Every verifier returns a result object rather than throwing, so a candidate
 * filter can drop a wallet for a named reason without aborting the whole
 * resolution. Only programmer errors (missing WebCrypto, malformed inputs to the
 * challenge builder) throw.
 *
 * @packageDocumentation
 */

import { hash, xdr } from "@stellar/stellar-sdk";
import type { Spec as ContractSpec } from "@stellar/stellar-sdk/contract";
import type { AuthenticationResponseJSON } from "@simplewebauthn/browser";
import type {
  BindingPurpose,
  Secp256r1BindingRecord as ContractSecp256r1BindingRecord,
  Signer as ContractSigner,
} from "passkey-kit-sdk";
import base64url from "../base64url.js";
import { compactSignature } from "../utils.js";
import { SECP256R1_PUBLIC_KEY_SIZE } from "../constants.js";

/** First byte of a SEC-1 uncompressed P-256 public key. */
const SECP256R1_PUBLIC_KEY_PREFIX = 0x04;

/**
 * Copy bytes into a fresh, non-shared `ArrayBuffer`. WebCrypto's `BufferSource`
 * parameters reject views over a `SharedArrayBuffer` at the type level, and a
 * `Buffer` from the pool may alias a larger allocation, so every input handed
 * to `crypto.subtle` goes through here.
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

// ============================================================================
// Binding challenge
// ============================================================================

/**
 * Fixed domain separators. These values must equal the contract constants.
 */
export const SECP256R1_GENESIS_DOMAIN = "secp256r1_genesis_v1";
export const SECP256R1_ADD_DOMAIN = "secp256r1_add_v1";

/** The contract spec UDT name of the binding payload struct. */
export const SECP256R1_BINDING_PAYLOAD_TYPE = "Secp256r1BindingPayload";

/** Inputs that fully determine a binding challenge. */
export interface BindingChallengeInput {
  /** A contract `Spec` that defines `Secp256r1BindingPayload`. */
  spec: ContractSpec;
  /** Network passphrase; hashed to the `network_id` the wallet reads. */
  networkPassphrase: string;
  /** The wallet contract address (`C…`) the proof binds to. */
  contractId: string;
  /** Entry point that will consume this proof. */
  purpose: BindingPurpose["tag"];
  /** The complete original signer value, including its mutable policy fields. */
  signer: ContractSigner;
}

/** Normalize a base64url string or raw bytes to bytes. */
export function toKeyIdBytes(keyId: Uint8Array | string): Uint8Array {
  return typeof keyId === "string"
    ? new Uint8Array(base64url.toBuffer(keyId))
    : keyId;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Canonicalize an `ScVal` map into the host's storage order.
 *
 * The contract hashes `to_xdr(payload)`, and the host serializes a struct as
 * an `ScMap` sorted by key. `Spec.nativeToScVal` emits struct fields in spec
 * declaration order, which for the Rust struct is NOT sorted, so the map is
 * re-sorted here by symbol key (bytewise, the host's order for symbols).
 * Non-map values pass through unchanged.
 */
export function canonicalScVal(value: xdr.ScVal): xdr.ScVal {
  if (value.switch().name === "scvVec") {
    const entries = value.vec();
    return entries
      ? xdr.ScVal.scvVec(entries.map((entry) => canonicalScVal(entry)))
      : value;
  }
  if (value.switch().name !== "scvMap") return value;
  const entries = value.map();
  if (!entries) return value;

  const sorted = entries
    .map(
      (entry) =>
        new xdr.ScMapEntry({
          key: canonicalScVal(entry.key()),
          val: canonicalScVal(entry.val()),
        })
    )
    .sort((a, b) => compareScValMapKeys(a.key(), b.key()));
  return xdr.ScVal.scvMap(sorted);
}

/** Compare map keys as the Soroban host compares them. */
function compareScValMapKeys(a: xdr.ScVal, b: xdr.ScVal): number {
  if (
    a.switch().name === "scvSymbol" &&
    b.switch().name === "scvSymbol"
  ) {
    return Buffer.compare(
      Buffer.from(a.sym().toString(), "utf8"),
      Buffer.from(b.sym().toString(), "utf8")
    );
  }

  // The binding payload only uses fixed-width address keys outside structs.
  // Their XDR byte order matches the host order for address type and payload.
  return Buffer.compare(a.toXDR(), b.toXDR());
}

/**
 * The binding payload as a canonical `ScVal`, encoded through the contract
 * `Spec` so field types are exactly the on-chain ones.
 */
export function bindingPayloadScVal(input: BindingChallengeInput): xdr.ScVal {
  if (input.signer.tag !== "Secp256r1") {
    throw new TypeError("binding signer must be Secp256r1");
  }
  const publicKey = input.signer.values[1];
  if (publicKey.length !== SECP256R1_PUBLIC_KEY_SIZE) {
    throw new TypeError(
      `publicKey must be ${SECP256R1_PUBLIC_KEY_SIZE} bytes (got ${publicKey.length})`
    );
  }

  const payload = {
    domain:
      input.purpose === "Genesis"
        ? SECP256R1_GENESIS_DOMAIN
        : SECP256R1_ADD_DOMAIN,
    network_id: hash(Buffer.from(input.networkPassphrase)),
    contract: input.contractId,
    purpose: { tag: input.purpose, values: undefined },
    signer: input.signer,
  };

  const scVal = input.spec.nativeToScVal(
    payload,
    xdr.ScSpecTypeDef.scSpecTypeUdt(
      new xdr.ScSpecTypeUdt({ name: SECP256R1_BINDING_PAYLOAD_TYPE })
    )
  );
  return canonicalScVal(scVal);
}

/**
 * The 32-byte binding challenge: `sha256(XDR(payload))`. This is the value a
 * WebAuthn ceremony must carry (base64url-encoded) as its `challenge`.
 */
export function bindingChallenge(input: BindingChallengeInput): Uint8Array {
  return new Uint8Array(hash(bindingPayloadScVal(input).toXDR()));
}

/** The binding challenge as the base64url string WebAuthn puts in clientDataJSON. */
export function bindingChallengeBase64url(input: BindingChallengeInput): string {
  return base64url.encode(Buffer.from(bindingChallenge(input)));
}

// ============================================================================
// WebAuthn assertion verification
// ============================================================================

/** Why an assertion failed to verify. */
export type AssertionFailure =
  | "key_id"
  | "client_data"
  | "type"
  | "challenge"
  | "origin"
  | "authenticator_data"
  | "rp_id"
  | "user_presence"
  | "user_verification"
  | "public_key"
  | "signature";

export type AssertionResult =
  | { ok: true }
  | { ok: false; reason: AssertionFailure; detail: string };

/** What an assertion must satisfy. */
export interface AssertionPolicy {
  /** The 32-byte challenge the assertion must carry. */
  expectedChallenge: Uint8Array;
  /** Relying Party id; `sha256(rpId)` must equal `authenticatorData[0..32]`. */
  rpId: string;
  /** 65-byte P-256 public key the signature must verify under. */
  publicKey: Uint8Array;
  /**
   * Credential id the assertion must come from. Checked only where the
   * assertion carries one (a fresh response has `id`; a stored proof does not).
   */
  expectedKeyId?: Uint8Array | string;
  /** Require the User Verification flag (biometric/PIN). Default: UP only. */
  requireUserVerification?: boolean;
  /** When set (non-empty), `clientDataJSON.origin` must be listed. */
  allowedOrigins?: readonly string[];
}

/** A stored proof as the contract keeps it (compact 64-byte `r||s`). */
export interface StoredWebAuthnProof {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  /** 64 bytes: `r || s`, low-S. */
  signature: Uint8Array;
}

/** WebAuthn authenticatorData layout. */
const AUTHENTICATOR_DATA_MIN_LEN = 37;
const RP_ID_HASH_LEN = 32;
const FLAGS_INDEX = 32;
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const WEBAUTHN_GET = "webauthn.get";

function fail(reason: AssertionFailure, detail: string): AssertionResult {
  return { ok: false, reason, detail };
}

function subtle(): SubtleCrypto {
  const subtleCrypto = globalThis.crypto?.subtle;
  if (!subtleCrypto) {
    throw new Error("WebCrypto (crypto.subtle) is not available in this runtime");
  }
  return subtleCrypto;
}

/**
 * Verify a P-256 ECDSA signature (compact `r||s`) over
 * `authenticatorData || sha256(clientDataJSON)` — the WebAuthn signed message.
 */
async function verifyP256(
  publicKey: Uint8Array,
  compactSig: Uint8Array,
  authenticatorData: Uint8Array,
  clientDataJSON: Uint8Array
): Promise<AssertionResult> {
  if (
    publicKey.length !== SECP256R1_PUBLIC_KEY_SIZE ||
    publicKey[0] !== SECP256R1_PUBLIC_KEY_PREFIX
  ) {
    return fail("public_key", "public key must be a 65-byte 0x04-prefixed P-256 point");
  }
  if (compactSig.length !== 64) {
    return fail("signature", `compact signature must be 64 bytes (got ${compactSig.length})`);
  }

  let key: CryptoKey;
  try {
    key = await subtle().importKey(
      "raw",
      toArrayBuffer(publicKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  } catch (err) {
    return fail("public_key", `public key rejected by WebCrypto: ${String(err)}`);
  }

  const signed = Buffer.concat([
    Buffer.from(authenticatorData),
    hash(Buffer.from(clientDataJSON)),
  ]);

  let valid: boolean;
  try {
    valid = await subtle().verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      toArrayBuffer(compactSig),
      toArrayBuffer(signed)
    );
  } catch (err) {
    return fail("signature", `WebCrypto verify threw: ${String(err)}`);
  }
  return valid ? { ok: true } : fail("signature", "P-256 signature does not verify");
}

/**
 * Verify one WebAuthn assertion with a compact signature against a policy.
 * Every structural check runs before the signature, so a malformed assertion
 * never costs a curve operation.
 */
export async function verifyAssertion(
  proof: StoredWebAuthnProof,
  policy: AssertionPolicy,
  presentedKeyId?: string
): Promise<AssertionResult> {
  // Credential id, where the assertion carries one.
  if (policy.expectedKeyId !== undefined && presentedKeyId !== undefined) {
    const expected = base64url.encode(Buffer.from(toKeyIdBytes(policy.expectedKeyId)));
    if (presentedKeyId !== expected) {
      return fail("key_id", "assertion credential id does not match the expected keyId");
    }
  }

  // clientDataJSON: type, challenge, origin.
  let clientData: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    clientData = JSON.parse(Buffer.from(proof.clientDataJSON).toString("utf8"));
  } catch {
    return fail("client_data", "clientDataJSON is not valid JSON");
  }
  if (typeof clientData !== "object" || clientData === null) {
    return fail("client_data", "clientDataJSON is not an object");
  }
  if (clientData.type !== WEBAUTHN_GET) {
    return fail("type", `clientDataJSON.type must be "${WEBAUTHN_GET}"`);
  }
  const expectedChallenge = base64url.encode(Buffer.from(policy.expectedChallenge));
  if (clientData.challenge !== expectedChallenge) {
    return fail("challenge", "clientDataJSON.challenge does not match the expected challenge");
  }
  if (policy.allowedOrigins && policy.allowedOrigins.length > 0) {
    if (
      typeof clientData.origin !== "string" ||
      !policy.allowedOrigins.includes(clientData.origin)
    ) {
      return fail("origin", "clientDataJSON.origin is not in the allowed origins");
    }
  }

  // authenticatorData: length, rpIdHash, flags.
  const authData = proof.authenticatorData;
  if (authData.length < AUTHENTICATOR_DATA_MIN_LEN) {
    return fail("authenticator_data", "authenticatorData is shorter than 37 bytes");
  }
  const rpIdHash = hash(Buffer.from(policy.rpId));
  if (!bytesEqual(authData.subarray(0, RP_ID_HASH_LEN), new Uint8Array(rpIdHash))) {
    return fail("rp_id", "authenticatorData.rpIdHash does not match the relying party id");
  }
  const flags = authData[FLAGS_INDEX]!;
  if ((flags & FLAG_USER_PRESENT) === 0) {
    return fail("user_presence", "User Present flag is not set");
  }
  if (policy.requireUserVerification && (flags & FLAG_USER_VERIFIED) === 0) {
    return fail("user_verification", "User Verified flag is not set");
  }

  return verifyP256(policy.publicKey, proof.signature, authData, proof.clientDataJSON);
}

/** Verify a STORED binding proof (contract compact signature). */
export function verifyStoredProof(
  proof: StoredWebAuthnProof,
  policy: AssertionPolicy
): Promise<AssertionResult> {
  return verifyAssertion(proof, policy);
}

/**
 * Verify a FRESH `AuthenticationResponseJSON` from `startAuthentication`. The
 * DER signature is converted to compact form (with low-S) through the same
 * `compactSignature` the signing pipeline uses, and `response.id` is checked
 * against `policy.expectedKeyId` when that is set.
 */
export async function verifyFreshAssertion(
  response: AuthenticationResponseJSON,
  policy: AssertionPolicy
): Promise<AssertionResult> {
  let signature: Uint8Array;
  try {
    signature = compactSignature(base64url.toBuffer(response.response.signature));
  } catch (err) {
    return fail("signature", `DER signature is malformed: ${String(err)}`);
  }

  return verifyAssertion(
    {
      authenticatorData: new Uint8Array(
        base64url.toBuffer(response.response.authenticatorData)
      ),
      clientDataJSON: new Uint8Array(base64url.toBuffer(response.response.clientDataJSON)),
      signature,
    },
    policy,
    response.id
  );
}

// ============================================================================
// Binding record verification
// ============================================================================

/** The contract's `Secp256r1BindingRecord`, as read from the ledger. */
export type Secp256r1BindingRecord = ContractSecp256r1BindingRecord;

/** The live `Secp256r1` signer entry the record must agree with. */
export interface LiveSecp256r1Signer {
  keyId: Uint8Array | string;
  publicKey: Uint8Array;
}

/** What a binding record must satisfy for one candidate wallet. */
export interface BindingRecordPolicy {
  spec: ContractSpec;
  networkPassphrase: string;
  /** The CANDIDATE address the challenge is recomputed for. */
  contractId: string;
  rpId: string;
  allowedOrigins?: readonly string[];
  requireUserVerification?: boolean;
}

export type BindingFailure =
  | AssertionFailure
  | "signer_kind"
  | "key_id_mismatch"
  | "public_key_mismatch";

export type BindingResult =
  | { ok: true; challenge: Uint8Array }
  | { ok: false; reason: BindingFailure; detail: string };

/**
 * Verify that `record` binds `liveSigner` to `policy.contractId`.
 *
 * 1. The record's signer keyId and public key equal the live signer.
 * 2. The challenge uses the record's original full signer and purpose.
 * 3. The stored proof must be a valid `webauthn.get` assertion over that
 *    challenge under that key, with the rpId/UP/UV/origin policy applied.
 */
export async function verifyBindingRecord(
  record: Secp256r1BindingRecord,
  liveSigner: LiveSecp256r1Signer,
  policy: BindingRecordPolicy
): Promise<BindingResult> {
  if (record.signer.tag !== "Secp256r1") {
    return {
      ok: false,
      reason: "signer_kind",
      detail: "binding record does not contain a Secp256r1 signer",
    };
  }
  const [recordKeyId, recordPublicKey] = record.signer.values;
  if (!bytesEqual(recordKeyId, toKeyIdBytes(liveSigner.keyId))) {
    return {
      ok: false,
      reason: "key_id_mismatch",
      detail: "binding record keyId does not equal the live signer keyId",
    };
  }
  if (!bytesEqual(recordPublicKey, liveSigner.publicKey)) {
    return {
      ok: false,
      reason: "public_key_mismatch",
      detail: "binding record public key does not equal the live signer public key",
    };
  }

  const challenge = bindingChallenge({
    spec: policy.spec,
    networkPassphrase: policy.networkPassphrase,
    contractId: policy.contractId,
    purpose: record.purpose.tag,
    signer: record.signer,
  });

  const result = await verifyStoredProof(
    {
      authenticatorData: record.proof.authenticator_data,
      clientDataJSON: record.proof.client_data_json,
      signature: record.proof.signature,
    },
    {
      expectedChallenge: challenge,
      rpId: policy.rpId,
      publicKey: recordPublicKey,
      allowedOrigins: policy.allowedOrigins,
      requireUserVerification: policy.requireUserVerification,
    }
  );

  return result.ok ? { ok: true, challenge } : result;
}
