/**
 * Client cryptography for the Secp256r1 binding protocol (no-factory design):
 *
 * - The challenge commits to the GENESIS/ADD domain, the network, the wallet
 *   address, and the COMPLETE original Signer (keyId, public key, expiration,
 *   limits, storage). Pinned byte-for-byte against the golden vectors in
 *   `contracts/smart-wallet/src/tests/test_binding.rs`.
 * - GENESIS and ADD domains produce different challenges.
 * - Any change to limits, expiration, storage, keyId, public key, address, or
 *   network changes the challenge.
 * - Stored (compact) and fresh (DER) assertions verify, each policy check
 *   rejecting for its own named reason.
 * - A binding record `{signer, purpose, proof}` is accepted only when it names
 *   the live key and its proof re-verifies for the candidate address.
 *
 * Keys are generated with WebCrypto, signatures are real P-256, and every
 * assertion is shaped like authenticator output.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { Networks, StrKey, hash } from "@stellar/stellar-sdk";
import type { Spec as ContractSpec } from "@stellar/stellar-sdk/contract";
import type { AuthenticationResponseJSON } from "@simplewebauthn/browser";
import {
  Client as PasskeyClient,
  type BindingPurpose,
  type Secp256r1BindingRecord,
  type Signer as ContractSigner,
} from "passkey-kit-sdk";
import base64url from "../base64url.js";
import {
  SECP256R1_ADD_DOMAIN,
  SECP256R1_GENESIS_DOMAIN,
  bindingChallenge,
  bindingChallengeBase64url,
  bindingPayloadScVal,
  verifyBindingRecord,
  verifyFreshAssertion,
  verifyStoredProof,
  type StoredWebAuthnProof,
} from "./webauthn-verify.js";

// ---------------------------------------------------------------------------
// Golden vectors from contracts/smart-wallet/src/tests/test_binding.rs
// ---------------------------------------------------------------------------

const FIXED_CONTRACT = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const GOLDEN_NETWORK_ID =
  "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472";
const GENESIS_PAYLOAD_XDR =
  "0000001100000001000000050000000f00000008636f6e74726163740000001200000001d7928b72c2703ccfeaf7eb9ff4ef4d504a55a8b979fc9b450ea2c842b4d1ce610000000f00000006646f6d61696e00000000000f000000147365637032353672315f67656e657369735f76310000000f0000000a6e6574776f726b5f696400000000000d00000020cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd4720000000f00000007707572706f7365000000001000000001000000010000000f0000000747656e65736973000000000f000000067369676e657200000000001000000001000000060000000f000000095365637032353672310000000000000d0000001422222222222222222222222222222222222222220000000d00000041333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333300000000000010000000010000000100000001000000100000000100000001000000010000001000000001000000010000000f0000000a50657273697374656e740000";
const GENESIS_CHALLENGE =
  "f8ba40008c5c0776bb975f9a7f5d0476ee18c7d49b2066cfc6411b5f6077e2c3";
const ADD_PAYLOAD_XDR =
  "0000001100000001000000050000000f00000008636f6e74726163740000001200000001d7928b72c2703ccfeaf7eb9ff4ef4d504a55a8b979fc9b450ea2c842b4d1ce610000000f00000006646f6d61696e00000000000f000000107365637032353672315f6164645f76310000000f0000000a6e6574776f726b5f696400000000000d00000020cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd4720000000f00000007707572706f7365000000001000000001000000010000000f00000003416464000000000f000000067369676e657200000000001000000001000000060000000f000000095365637032353672310000000000000d0000001422222222222222222222222222222222222222220000000d00000041333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333300000000000010000000010000000100000001000000100000000100000001000000010000001000000001000000010000000f0000000a50657273697374656e740000";
const ADD_CHALLENGE =
  "2847ba4e42719703a6f100dfce5a0e5d58f0246b62a187694416ed40c7db7c83";

const RP_ID = "localhost";
const ORIGIN = "http://localhost:4507";

/**
 * The generated bindings spec. It defines `Secp256r1BindingPayload` and its
 * nested `Signer` / `BindingPurpose`, so the challenge helper encodes the exact
 * on-chain field types. This is the authoritative spec the SDK itself uses.
 */
const spec = (
  new PasskeyClient({
    contractId: FIXED_CONTRACT,
    networkPassphrase: Networks.TESTNET,
    rpcUrl: "https://rpc.invalid",
  }) as unknown as { spec: ContractSpec }
).spec;

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

/** Build the complete on-chain `Signer` a binding proof commits to. */
function signerOf(
  keyId: Uint8Array,
  publicKey: Uint8Array,
  opts: {
    expiration?: bigint;
    limits?: Map<string, unknown> | undefined;
    storage?: "Persistent" | "Temporary";
  } = {}
): ContractSigner {
  return {
    tag: "Secp256r1",
    values: [
      Buffer.from(keyId),
      Buffer.from(publicKey),
      [opts.expiration],
      ["limits" in opts ? (opts.limits as never) : undefined],
      { tag: opts.storage ?? "Persistent", values: undefined },
    ],
  };
}

// ---------------------------------------------------------------------------
// Passkey + assertion fixtures (WebCrypto)
// ---------------------------------------------------------------------------

interface Passkey {
  keyId: Uint8Array;
  keyIdBase64: string;
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

async function makePasskey(seed: number): Promise<Passkey> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const keyId = new Uint8Array(20).fill(seed);
  return {
    keyId,
    keyIdBase64: base64url.encode(Buffer.from(keyId)),
    publicKey,
    privateKey: pair.privateKey,
  };
}

interface AssertionOptions {
  type?: string;
  origin?: string;
  rpId?: string;
  flags?: number;
  challengeOverride?: string;
  malformedJson?: boolean;
  truncateAuthData?: boolean;
}

/** Build a real assertion (compact signature) over `challenge`. */
async function sign(
  passkey: Passkey,
  challenge: Uint8Array,
  options: AssertionOptions = {}
): Promise<StoredWebAuthnProof> {
  const challengeB64 = options.challengeOverride ?? base64url.encode(Buffer.from(challenge));
  const clientDataJSON = Buffer.from(
    options.malformedJson
      ? "this is not json"
      : JSON.stringify({
          type: options.type ?? "webauthn.get",
          challenge: challengeB64,
          origin: options.origin ?? ORIGIN,
          crossOrigin: false,
        })
  );

  let authenticatorData = Buffer.concat([
    hash(Buffer.from(options.rpId ?? RP_ID)),
    Buffer.from([options.flags ?? 0x05]),
    Buffer.alloc(4),
  ]);
  if (options.truncateAuthData) authenticatorData = authenticatorData.subarray(0, 36);

  const signed = Buffer.concat([authenticatorData, hash(clientDataJSON)]);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.privateKey, signed)
  );

  return {
    authenticatorData: new Uint8Array(authenticatorData),
    clientDataJSON: new Uint8Array(clientDataJSON),
    signature,
  };
}

/** The contract's snake_case `Secp256r1Signature` shape a record carries. */
function toContractProof(proof: StoredWebAuthnProof) {
  return {
    authenticator_data: Buffer.from(proof.authenticatorData),
    client_data_json: Buffer.from(proof.clientDataJSON),
    signature: Buffer.from(proof.signature),
  };
}

/** Encode a compact `r||s` signature as DER, as an authenticator returns it. */
function derFromCompact(compact: Uint8Array): Buffer {
  const int = (bytes: Uint8Array) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let body = Buffer.from(bytes.subarray(i));
    if (body[0]! & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const r = int(compact.subarray(0, 32));
  const s = int(compact.subarray(32, 64));
  return Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
}

/** Wrap a compact assertion as the browser's `AuthenticationResponseJSON`. */
function asFreshResponse(
  proof: StoredWebAuthnProof,
  id: string,
  derOverride?: Buffer
): AuthenticationResponseJSON {
  return {
    id,
    rawId: id,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      authenticatorData: base64url.encode(Buffer.from(proof.authenticatorData)),
      clientDataJSON: base64url.encode(Buffer.from(proof.clientDataJSON)),
      signature: base64url.encode(derOverride ?? derFromCompact(proof.signature)),
    },
  };
}

/** The binding challenge for a passkey's default (persistent, unlimited) signer. */
function challengeFor(
  passkey: Passkey,
  contractId: string,
  purpose: BindingPurpose["tag"] = "Genesis",
  network: string = Networks.TESTNET
): Uint8Array {
  return bindingChallenge({
    spec,
    networkPassphrase: network,
    contractId,
    purpose,
    signer: signerOf(passkey.keyId, passkey.publicKey),
  });
}

const WALLET = "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ";
const OTHER_WALLET = "CDXICVKLHPPAZ3EM65OESOGBSQE4YQGFN6JK7ICPYUXDAQPAVXBZ4PAT";

let alice: Passkey;
let mallory: Passkey;

beforeAll(async () => {
  alice = await makePasskey(0x11);
  mallory = await makePasskey(0x22);
});

// ---------------------------------------------------------------------------
// Binding challenge — golden vectors + full-shape commitment
// ---------------------------------------------------------------------------

describe("binding challenge golden vectors", () => {
  const GOLDEN_KEY_ID = new Uint8Array(20).fill(0x22);
  const GOLDEN_PUBLIC_KEY = new Uint8Array(65).fill(0x33);
  const goldenSigner = signerOf(GOLDEN_KEY_ID, GOLDEN_PUBLIC_KEY);

  const goldenInput = (purpose: BindingPurpose["tag"]) => ({
    spec,
    networkPassphrase: Networks.TESTNET,
    contractId: FIXED_CONTRACT,
    purpose,
    signer: goldenSigner,
  });

  it("pins the domains and the network id", () => {
    expect(SECP256R1_GENESIS_DOMAIN).toBe("secp256r1_genesis_v1");
    expect(SECP256R1_ADD_DOMAIN).toBe("secp256r1_add_v1");
    expect(hash(Buffer.from(Networks.TESTNET)).toString("hex")).toBe(GOLDEN_NETWORK_ID);
  });

  it("reproduces the GENESIS payload XDR and challenge byte for byte", () => {
    const input = goldenInput("Genesis");
    expect(bindingPayloadScVal(input).toXDR().toString("hex")).toBe(GENESIS_PAYLOAD_XDR);
    expect(hex(bindingChallenge(input))).toBe(GENESIS_CHALLENGE);
    expect(bindingChallengeBase64url(input)).toBe(
      base64url.encode(Buffer.from(GENESIS_CHALLENGE, "hex"))
    );
  });

  it("reproduces the ADD payload XDR and challenge byte for byte", () => {
    const input = goldenInput("Add");
    expect(bindingPayloadScVal(input).toXDR().toString("hex")).toBe(ADD_PAYLOAD_XDR);
    expect(hex(bindingChallenge(input))).toBe(ADD_CHALLENGE);
  });

  it("proves GENESIS and ADD differ for the same signer, address, and network", () => {
    expect(GENESIS_CHALLENGE).not.toBe(ADD_CHALLENGE);
    expect(hex(bindingChallenge(goldenInput("Genesis")))).not.toBe(
      hex(bindingChallenge(goldenInput("Add")))
    );
  });

  it("canonicalizes the payload map into the host's sorted key order", () => {
    const keys = bindingPayloadScVal(goldenInput("Genesis"))
      .map()!
      .map((entry) => String(entry.key().sym()));
    expect(keys).toEqual(["contract", "domain", "network_id", "purpose", "signer"]);
  });
});

describe("binding challenge commits to every field", () => {
  it("changes with address, network, keyId, public key, expiration, limits, and storage", () => {
    const keyId = new Uint8Array(20).fill(0x41);
    const otherKeyId = new Uint8Array(20).fill(0x42);
    const publicKey = new Uint8Array(65).fill(0x04);
    const otherPublicKey = new Uint8Array(65).fill(0x05);
    const base = {
      spec,
      networkPassphrase: Networks.TESTNET,
      contractId: WALLET,
      purpose: "Genesis" as const,
      signer: signerOf(keyId, publicKey),
    };
    const baseHex = hex(bindingChallenge(base));

    const variants: Record<string, Uint8Array> = {
      address: bindingChallenge({ ...base, contractId: OTHER_WALLET }),
      network: bindingChallenge({ ...base, networkPassphrase: Networks.PUBLIC }),
      purpose: bindingChallenge({ ...base, purpose: "Add" }),
      keyId: bindingChallenge({ ...base, signer: signerOf(otherKeyId, publicKey) }),
      publicKey: bindingChallenge({ ...base, signer: signerOf(keyId, otherPublicKey) }),
      expiration: bindingChallenge({
        ...base,
        signer: signerOf(keyId, publicKey, { expiration: 1_000n }),
      }),
      limits: bindingChallenge({
        ...base,
        signer: signerOf(keyId, publicKey, { limits: new Map() }),
      }),
      storage: bindingChallenge({
        ...base,
        signer: signerOf(keyId, publicKey, { storage: "Temporary" }),
      }),
    };

    for (const [name, challenge] of Object.entries(variants)) {
      expect(hex(challenge), `${name} must change the challenge`).not.toBe(baseHex);
    }
    expect(StrKey.isValidContract(WALLET)).toBe(true);
  });

  it("rejects a non-Secp256r1 signer and a wrong-length public key", () => {
    const ed25519: ContractSigner = {
      tag: "Ed25519",
      values: [Buffer.alloc(32), [undefined], [undefined], { tag: "Persistent", values: undefined }],
    };
    expect(() =>
      bindingChallenge({
        spec,
        networkPassphrase: Networks.TESTNET,
        contractId: WALLET,
        purpose: "Genesis",
        signer: ed25519,
      })
    ).toThrow(/Secp256r1/);

    expect(() =>
      bindingChallenge({
        spec,
        networkPassphrase: Networks.TESTNET,
        contractId: WALLET,
        purpose: "Genesis",
        signer: signerOf(new Uint8Array(20).fill(1), new Uint8Array(33)),
      })
    ).toThrow(/65 bytes/);
  });
});

// ---------------------------------------------------------------------------
// Cross-language golden vector: SignerLimits with an account + a contract key
// ---------------------------------------------------------------------------

describe("binding challenge golden vector with SignerLimits", () => {
  // Deterministic addresses: ed25519 public key [0x11; 32] and contract id
  // [0x22; 32]. Pinned identically in
  // contracts/smart-wallet/src/tests/test_binding.rs.
  const LIMITS_ACCOUNT = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
  const LIMITS_CONTRACT = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";
  const LIMITS_PAYLOAD_XDR =
    "0000001100000001000000050000000f00000008636f6e74726163740000001200000001d7928b72c2703ccfeaf7eb9ff4ef4d504a55a8b979fc9b450ea2c842b4d1ce610000000f00000006646f6d61696e00000000000f000000147365637032353672315f67656e657369735f76310000000f0000000a6e6574776f726b5f696400000000000d00000020cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd4720000000f00000007707572706f7365000000001000000001000000010000000f0000000747656e65736973000000000f000000067369676e657200000000001000000001000000060000000f000000095365637032353672310000000000000d0000001422222222222222222222222222222222222222220000000d0000004133333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333330000000000001000000001000000010000000100000010000000010000000100000011000000010000000200000012000000000000000011111111111111111111111111111111111111111111111111111111111111110000000100000012000000012222222222222222222222222222222222222222222222222222222222222222000000010000001000000001000000010000000f0000000a50657273697374656e740000";
  const LIMITS_CHALLENGE =
    "f1f01d9d02b880c9e9ec32eeb0ce224efb8036b190931715fd3c2f55e684c99d";

  // Two SignerLimits entries with `None` co-signers, INSERTED contract-first to
  // prove the client re-sorts to the host key order (account before contract).
  const limits = new Map<string, undefined>([
    [LIMITS_CONTRACT, undefined],
    [LIMITS_ACCOUNT, undefined],
  ]);
  const input = {
    spec,
    networkPassphrase: Networks.TESTNET,
    contractId: FIXED_CONTRACT,
    purpose: "Genesis" as const,
    signer: signerOf(new Uint8Array(20).fill(0x22), new Uint8Array(65).fill(0x33), { limits }),
  };

  it("matches the Rust payload XDR and challenge byte for byte", () => {
    expect(bindingPayloadScVal(input).toXDR().toString("hex")).toBe(LIMITS_PAYLOAD_XDR);
    expect(hex(bindingChallenge(input))).toBe(LIMITS_CHALLENGE);
  });

  it("orders the address map account-before-contract, matching the host", () => {
    const xdr = bindingPayloadScVal(input).toXDR().toString("hex");
    const accountRaw = "11".repeat(32);
    const contractRaw = "22".repeat(32);
    const accountAt = xdr.indexOf(accountRaw);
    const contractAt = xdr.indexOf(contractRaw);
    expect(accountAt).toBeGreaterThanOrEqual(0);
    expect(contractAt).toBeGreaterThanOrEqual(0);
    // Account ScAddress discriminant (0) sorts before Contract (1), regardless
    // of the contract-first insertion order above.
    expect(accountAt).toBeLessThan(contractAt);
  });
});

// ---------------------------------------------------------------------------
// Stored (compact) assertion verification
// ---------------------------------------------------------------------------

describe("verifyStoredProof", () => {
  const policy = (challenge: Uint8Array, overrides: Record<string, unknown> = {}) => ({
    expectedChallenge: challenge,
    rpId: RP_ID,
    publicKey: alice.publicKey,
    ...overrides,
  });

  it("accepts a genuine assertion over the expected challenge", async () => {
    const challenge = challengeFor(alice, WALLET);
    const proof = await sign(alice, challenge);
    await expect(verifyStoredProof(proof, policy(challenge))).resolves.toEqual({ ok: true });
  });

  it("enforces the origin allowlist and UV only when asked", async () => {
    const challenge = challengeFor(alice, WALLET);
    const proof = await sign(alice, challenge, { flags: 0x01 }); // UP only

    await expect(
      verifyStoredProof(proof, policy(challenge, { allowedOrigins: [ORIGIN] }))
    ).resolves.toEqual({ ok: true });
    await expect(
      verifyStoredProof(proof, policy(challenge, { allowedOrigins: ["https://evil.example"] }))
    ).resolves.toMatchObject({ ok: false, reason: "origin" });
    await expect(
      verifyStoredProof(proof, policy(challenge, { requireUserVerification: true }))
    ).resolves.toMatchObject({ ok: false, reason: "user_verification" });
  });

  it("rejects the wrong challenge, wrong type, and foreign rpId", async () => {
    const challenge = challengeFor(alice, WALLET);
    await expect(
      verifyStoredProof(await sign(alice, challengeFor(alice, OTHER_WALLET)), policy(challenge))
    ).resolves.toMatchObject({ ok: false, reason: "challenge" });
    await expect(
      verifyStoredProof(await sign(alice, challenge, { type: "webauthn.create" }), policy(challenge))
    ).resolves.toMatchObject({ ok: false, reason: "type" });
    await expect(
      verifyStoredProof(await sign(alice, challenge, { rpId: "evil.example" }), policy(challenge))
    ).resolves.toMatchObject({ ok: false, reason: "rp_id" });
  });

  it("rejects a missing User Present flag, malformed JSON, and short authenticatorData", async () => {
    const challenge = challengeFor(alice, WALLET);
    await expect(
      verifyStoredProof(await sign(alice, challenge, { flags: 0x04 }), policy(challenge))
    ).resolves.toMatchObject({ ok: false, reason: "user_presence" });
    await expect(
      verifyStoredProof(await sign(alice, challenge, { malformedJson: true }), policy(challenge))
    ).resolves.toMatchObject({ ok: false, reason: "client_data" });
    await expect(
      verifyStoredProof(await sign(alice, challenge, { truncateAuthData: true }), policy(challenge))
    ).resolves.toMatchObject({ ok: false, reason: "authenticator_data" });
  });

  it("rejects a foreign-key signature, a tampered signature, and a bad public key", async () => {
    const challenge = challengeFor(alice, WALLET);

    await expect(
      verifyStoredProof(await sign(mallory, challenge), policy(challenge))
    ).resolves.toMatchObject({ ok: false, reason: "signature" });

    const genuine = await sign(alice, challenge);
    const tampered = { ...genuine, signature: new Uint8Array(genuine.signature) };
    tampered.signature[63] ^= 0xff;
    await expect(verifyStoredProof(tampered, policy(challenge))).resolves.toMatchObject({
      ok: false,
      reason: "signature",
    });

    await expect(
      verifyStoredProof(genuine, policy(challenge, { publicKey: new Uint8Array(65).fill(0x33) }))
    ).resolves.toMatchObject({ ok: false, reason: "public_key" });
  });
});

// ---------------------------------------------------------------------------
// Fresh (DER) assertion verification
// ---------------------------------------------------------------------------

describe("verifyFreshAssertion", () => {
  it("accepts a genuine browser response and checks the credential id", async () => {
    const challenge = new Uint8Array(32).fill(7);
    const response = asFreshResponse(await sign(alice, challenge), alice.keyIdBase64);

    await expect(
      verifyFreshAssertion(response, {
        expectedChallenge: challenge,
        rpId: RP_ID,
        publicKey: alice.publicKey,
        expectedKeyId: alice.keyId,
        allowedOrigins: [ORIGIN],
      })
    ).resolves.toEqual({ ok: true });
  });

  it("rejects a response from a different credential id", async () => {
    const challenge = new Uint8Array(32).fill(7);
    const response = asFreshResponse(await sign(alice, challenge), mallory.keyIdBase64);

    await expect(
      verifyFreshAssertion(response, {
        expectedChallenge: challenge,
        rpId: RP_ID,
        publicKey: alice.publicKey,
        expectedKeyId: alice.keyId,
      })
    ).resolves.toMatchObject({ ok: false, reason: "key_id" });
  });

  it("rejects the attacker's key under the victim's credential id", async () => {
    const challenge = new Uint8Array(32).fill(9);
    const response = asFreshResponse(await sign(mallory, challenge), alice.keyIdBase64);

    await expect(
      verifyFreshAssertion(response, {
        expectedChallenge: challenge,
        rpId: RP_ID,
        publicKey: alice.publicKey,
        expectedKeyId: alice.keyId,
      })
    ).resolves.toMatchObject({ ok: false, reason: "signature" });
  });

  it("rejects a malformed DER signature and a wrong challenge", async () => {
    const challenge = new Uint8Array(32).fill(7);
    const proof = await sign(alice, challenge);

    await expect(
      verifyFreshAssertion(asFreshResponse(proof, alice.keyIdBase64, Buffer.from([0x30, 0x01])), {
        expectedChallenge: challenge,
        rpId: RP_ID,
        publicKey: alice.publicKey,
      })
    ).resolves.toMatchObject({ ok: false, reason: "signature" });

    await expect(
      verifyFreshAssertion(asFreshResponse(proof, alice.keyIdBase64), {
        expectedChallenge: new Uint8Array(32).fill(8),
        rpId: RP_ID,
        publicKey: alice.publicKey,
      })
    ).resolves.toMatchObject({ ok: false, reason: "challenge" });
  });
});

// ---------------------------------------------------------------------------
// Binding record verification — {signer, purpose, proof}
// ---------------------------------------------------------------------------

describe("verifyBindingRecord", () => {
  const policyFor = (contractId: string, network = Networks.TESTNET) => ({
    spec,
    networkPassphrase: network,
    contractId,
    rpId: RP_ID,
    allowedOrigins: [ORIGIN],
  });

  /** A genuine record: the passkey signs the challenge for its own signer. */
  async function genuineRecord(
    passkey: Passkey,
    contractId: string,
    purpose: BindingPurpose["tag"] = "Genesis"
  ): Promise<Secp256r1BindingRecord> {
    const signer = signerOf(passkey.keyId, passkey.publicKey);
    const challenge = bindingChallenge({
      spec,
      networkPassphrase: Networks.TESTNET,
      contractId,
      purpose,
      signer,
    });
    return {
      signer,
      purpose: { tag: purpose, values: undefined },
      proof: toContractProof(await sign(passkey, challenge)),
    };
  }

  const live = (passkey: Passkey) => ({
    keyId: passkey.keyId,
    publicKey: passkey.publicKey,
  });

  it("accepts a record that names the live key and proves this address", async () => {
    const record = await genuineRecord(alice, WALLET);
    const result = await verifyBindingRecord(record, live(alice), policyFor(WALLET));
    expect(result.ok).toBe(true);
    if (result.ok) {
      const expected = bindingChallenge({
        spec,
        networkPassphrase: Networks.TESTNET,
        contractId: WALLET,
        purpose: "Genesis",
        signer: record.signer,
      });
      expect(Buffer.from(result.challenge).equals(Buffer.from(expected))).toBe(true);
    }
  });

  it("accepts an ADD-purpose record and binds the purpose", async () => {
    const addRecord = await genuineRecord(alice, WALLET, "Add");
    await expect(verifyBindingRecord(addRecord, live(alice), policyFor(WALLET))).resolves.toEqual(
      { ok: true, challenge: expect.anything() }
    );

    // The same proof re-labeled Genesis no longer verifies: purpose is bound.
    const relabeled: Secp256r1BindingRecord = {
      ...addRecord,
      purpose: { tag: "Genesis", values: undefined },
    };
    await expect(
      verifyBindingRecord(relabeled, live(alice), policyFor(WALLET))
    ).resolves.toMatchObject({ ok: false, reason: "challenge" });
  });

  it("rejects a proof minted for another address or another network", async () => {
    const record = await genuineRecord(alice, WALLET);
    await expect(
      verifyBindingRecord(record, live(alice), policyFor(OTHER_WALLET))
    ).resolves.toMatchObject({ ok: false, reason: "challenge" });
    await expect(
      verifyBindingRecord(record, live(alice), policyFor(WALLET, Networks.PUBLIC))
    ).resolves.toMatchObject({ ok: false, reason: "challenge" });
  });

  it("rejects a record whose keyId or public key differs from the live signer", async () => {
    const record = await genuineRecord(alice, WALLET);
    await expect(
      verifyBindingRecord(
        record,
        { keyId: mallory.keyId, publicKey: alice.publicKey },
        policyFor(WALLET)
      )
    ).resolves.toMatchObject({ ok: false, reason: "key_id_mismatch" });
    await expect(
      verifyBindingRecord(
        record,
        { keyId: alice.keyId, publicKey: mallory.publicKey },
        policyFor(WALLET)
      )
    ).resolves.toMatchObject({ ok: false, reason: "public_key_mismatch" });
  });

  it("rejects the mixed-key split: record proves attacker key, live shows victim key", async () => {
    // Custom birth code writes a record for the attacker's key and pairs it
    // with a victim live signer. Public-key equality drops it before crypto.
    const attackerSigner = signerOf(alice.keyId, mallory.publicKey);
    const attackerRecord: Secp256r1BindingRecord = {
      signer: attackerSigner,
      purpose: { tag: "Genesis", values: undefined },
      proof: toContractProof(
        await sign(
          mallory,
          bindingChallenge({
            spec,
            networkPassphrase: Networks.TESTNET,
            contractId: WALLET,
            purpose: "Genesis",
            signer: attackerSigner,
          })
        )
      ),
    };
    await expect(
      verifyBindingRecord(attackerRecord, live(alice), policyFor(WALLET))
    ).resolves.toMatchObject({ ok: false, reason: "public_key_mismatch" });
  });

  it("rejects a forged record: victim key material, proof by another key", async () => {
    const signer = signerOf(alice.keyId, alice.publicKey);
    const forged: Secp256r1BindingRecord = {
      signer,
      purpose: { tag: "Genesis", values: undefined },
      proof: toContractProof(
        await sign(
          mallory,
          bindingChallenge({
            spec,
            networkPassphrase: Networks.TESTNET,
            contractId: WALLET,
            purpose: "Genesis",
            signer,
          })
        )
      ),
    };
    await expect(
      verifyBindingRecord(forged, live(alice), policyFor(WALLET))
    ).resolves.toMatchObject({ ok: false, reason: "signature" });
  });

  it("rejects a non-Secp256r1 record signer", async () => {
    const record = {
      signer: {
        tag: "Ed25519",
        values: [Buffer.alloc(32), [undefined], [undefined], { tag: "Persistent", values: undefined }],
      },
      purpose: { tag: "Genesis", values: undefined },
      proof: toContractProof(await sign(alice, challengeFor(alice, WALLET))),
    } as unknown as Secp256r1BindingRecord;
    await expect(
      verifyBindingRecord(record, live(alice), policyFor(WALLET))
    ).resolves.toMatchObject({ ok: false, reason: "signer_kind" });
  });

  it("applies the rpId and origin policy to the stored proof", async () => {
    const signer = signerOf(alice.keyId, alice.publicKey);
    const challenge = bindingChallenge({
      spec,
      networkPassphrase: Networks.TESTNET,
      contractId: WALLET,
      purpose: "Genesis",
      signer,
    });
    const foreignRp: Secp256r1BindingRecord = {
      signer,
      purpose: { tag: "Genesis", values: undefined },
      proof: toContractProof(await sign(alice, challenge, { rpId: "evil.example" })),
    };
    await expect(
      verifyBindingRecord(foreignRp, live(alice), policyFor(WALLET))
    ).resolves.toMatchObject({ ok: false, reason: "rp_id" });

    const foreignOrigin: Secp256r1BindingRecord = {
      signer,
      purpose: { tag: "Genesis", values: undefined },
      proof: toContractProof(await sign(alice, challenge, { origin: "https://evil.example" })),
    };
    await expect(
      verifyBindingRecord(foreignOrigin, live(alice), policyFor(WALLET))
    ).resolves.toMatchObject({ ok: false, reason: "origin" });
  });
});
