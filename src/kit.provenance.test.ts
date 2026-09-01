/**
 * Integration tests for constructor-only signer-provenance verification.
 *
 * These drive the kit's private `assertSignerProvenance` glue with REAL
 * WebCrypto P-256 material, a generated `{signer, purpose, proof}` binding
 * record, and a real fresh WebAuthn assertion. They prove the two load-bearing
 * controls wire correctly: the stored binding record re-verifies for the
 * candidate address, and the fresh assertion must verify under the LIVE signer
 * public key. No factory, no genesis-namespace derivation.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { Networks, hash } from "@stellar/stellar-sdk";
import type { Spec as ContractSpec } from "@stellar/stellar-sdk/contract";
import type { AuthenticationResponseJSON } from "@simplewebauthn/browser";
import {
  Client as PasskeyClient,
  type BindingPurpose,
  type Secp256r1BindingRecord,
  type Signer as ContractSigner,
  type SignerVal,
} from "passkey-kit-sdk";
import { PasskeyKit } from "./kit.js";
import { WalletOwnershipError } from "./errors.js";
import base64url from "./base64url.js";
import { bindingChallenge } from "./kit/webauthn-verify.js";

const REAL_WALLET = "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ";
const OTHER_WALLET = "CDXICVKLHPPAZ3EM65OESOGBSQE4YQGFN6JK7ICPYUXDAQPAVXBZ4PAT";
const WALLET_HASH = "ab".repeat(32);
const RP_ID = "app.example";
const ORIGIN = "https://app.example";

function makeKit(): PasskeyKit {
  return new PasskeyKit({
    rpcUrl: "https://rpc.example",
    networkPassphrase: Networks.TESTNET,
    walletWasmHash: WALLET_HASH,
    rpId: RP_ID,
    allowedOrigins: [ORIGIN],
    WebAuthn: {
      startRegistration: async () => {
        throw new Error("not used");
      },
      startAuthentication: async () => {
        throw new Error("not used");
      },
    },
  });
}

function contractSpec(contractId: string): ContractSpec {
  return (
    new PasskeyClient({
      contractId,
      rpcUrl: "https://rpc.example",
      networkPassphrase: Networks.TESTNET,
    }) as unknown as { spec: ContractSpec }
  ).spec;
}

// --- Passkey + assertion fixtures ------------------------------------------

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

function signerOf(keyId: Uint8Array, publicKey: Uint8Array): ContractSigner {
  return {
    tag: "Secp256r1",
    values: [
      Buffer.from(keyId),
      Buffer.from(publicKey),
      [undefined],
      [undefined],
      { tag: "Persistent", values: undefined },
    ],
  };
}

async function assertionOver(
  passkey: Passkey,
  challenge: Uint8Array
): Promise<{ authenticatorData: Buffer; clientDataJSON: Buffer; signature: Buffer }> {
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: base64url.encode(Buffer.from(challenge)),
      origin: ORIGIN,
      crossOrigin: false,
    })
  );
  const authenticatorData = Buffer.concat([
    hash(Buffer.from(RP_ID)),
    Buffer.from([0x05]),
    Buffer.alloc(4),
  ]);
  const signed = Buffer.concat([authenticatorData, hash(clientDataJSON)]);
  const signature = Buffer.from(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, passkey.privateKey, signed)
  );
  return { authenticatorData, clientDataJSON, signature };
}

function derFromCompact(compact: Uint8Array): Buffer {
  const integer = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let body = Buffer.from(bytes.subarray(start));
    if (body[0]! & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const r = integer(compact.subarray(0, 32));
  const s = integer(compact.subarray(32, 64));
  return Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
}

async function freshResponse(
  passkey: Passkey,
  presentedKeyId: string,
  challenge: Uint8Array
): Promise<AuthenticationResponseJSON> {
  const a = await assertionOver(passkey, challenge);
  return {
    id: presentedKeyId,
    rawId: presentedKeyId,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      authenticatorData: base64url.encode(a.authenticatorData),
      clientDataJSON: base64url.encode(a.clientDataJSON),
      signature: base64url.encode(derFromCompact(a.signature)),
    },
  };
}

/** A genuine on-chain binding record for `passkey` at `contractId`. */
async function bindingRecord(
  passkey: Passkey,
  contractId: string,
  purpose: BindingPurpose["tag"] = "Genesis"
): Promise<Secp256r1BindingRecord> {
  const signer = signerOf(passkey.keyId, passkey.publicKey);
  const challenge = bindingChallenge({
    spec: contractSpec(contractId),
    networkPassphrase: Networks.TESTNET,
    contractId,
    purpose,
    signer,
  });
  const a = await assertionOver(passkey, challenge);
  return {
    signer,
    purpose: { tag: purpose, values: undefined },
    proof: {
      authenticator_data: a.authenticatorData,
      client_data_json: a.clientDataJSON,
      signature: a.signature,
    },
  };
}

/** A stub wallet client exposing only what `assertSignerProvenance` reads. */
function walletStub(contractId: string, record: Secp256r1BindingRecord | undefined) {
  return {
    spec: contractSpec(contractId),
    get_secp256r1_binding: async () => ({ result: record }),
  } as unknown as PasskeyClient;
}

function liveSigner(publicKey: Uint8Array): Extract<SignerVal, { tag: "Secp256r1" }> {
  return { tag: "Secp256r1", values: [Buffer.from(publicKey), [undefined], [undefined]] };
}

type ProvenanceFn = (
  wallet: PasskeyClient,
  contractId: string,
  keyId: Buffer,
  signerVal: Extract<SignerVal, { tag: "Secp256r1" }>,
  response: AuthenticationResponseJSON,
  challenge: Buffer
) => Promise<void>;

const provenanceOf = (kit: PasskeyKit): ProvenanceFn =>
  (kit as unknown as { assertSignerProvenance: ProvenanceFn }).assertSignerProvenance.bind(kit);

let alice: Passkey;
let mallory: Passkey;
const FRESH = Buffer.alloc(32, 0x44);

beforeAll(async () => {
  alice = await makePasskey(0x11);
  mallory = await makePasskey(0x22);
});

describe("assertSignerProvenance", () => {
  it("accepts a genuine binding record and a fresh assertion under the live key", async () => {
    const kit = makeKit();
    const record = await bindingRecord(alice, REAL_WALLET, "Add");
    const wallet = walletStub(REAL_WALLET, record);
    const response = await freshResponse(alice, alice.keyIdBase64, FRESH);

    await expect(
      provenanceOf(kit)(
        wallet,
        REAL_WALLET,
        Buffer.from(alice.keyId),
        liveSigner(alice.publicKey),
        response,
        FRESH
      )
    ).resolves.toBeUndefined();
  });

  it("rejects the attacker's key under the victim's credential id", async () => {
    // Live signer is the victim; the record is genuine; the fresh assertion is
    // produced by the attacker under the victim's keyId — it cannot verify
    // against the live victim public key.
    const kit = makeKit();
    const record = await bindingRecord(alice, REAL_WALLET);
    const wallet = walletStub(REAL_WALLET, record);
    const attackerResponse = await freshResponse(mallory, alice.keyIdBase64, FRESH);

    await expect(
      provenanceOf(kit)(
        wallet,
        REAL_WALLET,
        Buffer.from(alice.keyId),
        liveSigner(alice.publicKey),
        attackerResponse,
        FRESH
      )
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });

  it("rejects a binding record proven for a different address", async () => {
    const kit = makeKit();
    const foreignRecord = await bindingRecord(alice, OTHER_WALLET);
    const wallet = walletStub(REAL_WALLET, foreignRecord);
    const response = await freshResponse(alice, alice.keyIdBase64, FRESH);

    await expect(
      provenanceOf(kit)(
        wallet,
        REAL_WALLET,
        Buffer.from(alice.keyId),
        liveSigner(alice.publicKey),
        response,
        FRESH
      )
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });

  it("rejects a wallet with no binding record for the passkey", async () => {
    const kit = makeKit();
    const wallet = walletStub(REAL_WALLET, undefined);
    const response = await freshResponse(alice, alice.keyIdBase64, FRESH);

    await expect(
      provenanceOf(kit)(
        wallet,
        REAL_WALLET,
        Buffer.from(alice.keyId),
        liveSigner(alice.publicKey),
        response,
        FRESH
      )
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });

  it("rejects a record whose live public key was swapped", async () => {
    // Record proves the victim; live signer claims the attacker's key. Public-key
    // equality drops it before any signature check.
    const kit = makeKit();
    const record = await bindingRecord(alice, REAL_WALLET);
    const wallet = walletStub(REAL_WALLET, record);
    const response = await freshResponse(mallory, alice.keyIdBase64, FRESH);

    await expect(
      provenanceOf(kit)(
        wallet,
        REAL_WALLET,
        Buffer.from(alice.keyId),
        liveSigner(mallory.publicKey),
        response,
        FRESH
      )
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });
});
