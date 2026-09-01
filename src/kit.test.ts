/**
 * `PasskeyKit` no-factory release behavior:
 *
 * - Discovery uses verified local storage OR one complete, non-stale indexer
 *   response; there is no derivation-only connect and no legacy bypass flags.
 * - Every candidate must prove its immutable birth through RPC, run accepted
 *   current code, hold the live signer, pass the binding record + fresh
 *   assertion, and be the ONLY candidate that passes.
 * - `createWallet` never persists until `confirmWalletCreation` verifies birth.
 * - `addSecp256r1` copies the connected wallet's verified birth metadata.
 * - Restore-source resolution is preserved.
 *
 * Birth verification runs for real against crafted CreateContractV2 envelopes;
 * the WebAuthn provenance glue is exercised end-to-end in
 * `kit.provenance.test.ts`, so selection tests stub `assertSignerProvenance`.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  Account,
  Address,
  Keypair,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
  hash,
  xdr,
} from "@stellar/stellar-sdk";
import { Api } from "@stellar/stellar-sdk/rpc";
import { PasskeyKit, type PasskeyKitConfig } from "./kit.js";
import { SignerStore, type StoredPasskey } from "./types.js";
import { MemoryStorage } from "./storage/memory.js";
import { ConfigurationError, WalletAmbiguousError, WalletOwnershipError } from "./errors.js";
import base64url from "./base64url.js";

const WASM_HASH = "ab".repeat(32); // accepted birth + current code
const EVIL_HASH = "cd".repeat(32); // unaccepted birth (evil-birth wasm)
const KEY_ID = Buffer.alloc(16, 7);
const KEY_ID_B64 = base64url.encode(KEY_ID);
const PUBLIC_KEY = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xc1)]);
const BINDING_PROOF = {
  authenticator_data: Buffer.alloc(37),
  client_data_json: Buffer.from("{}"),
  signature: Buffer.alloc(64),
};
const RP_ID = "app.example";
const ORIGIN = "https://app.example";

// A minimal but shape-valid discovery assertion the kit re-runs before verifying
// candidates. Its signature is never checked here because `assertSignerProvenance`
// is stubbed in the selection tests.
const AUTH_RESPONSE = {
  id: KEY_ID_B64,
  rawId: KEY_ID_B64,
  type: "public-key" as const,
  clientExtensionResults: {},
  response: {
    authenticatorData: base64url.encode(Buffer.alloc(37)),
    clientDataJSON: base64url.encode(Buffer.from("{}")),
    signature: base64url.encode(Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])),
  },
};

function makeKit(storage?: MemoryStorage, overrides?: Partial<PasskeyKitConfig>): PasskeyKit {
  return new PasskeyKit({
    rpcUrl: "https://rpc.example",
    networkPassphrase: Networks.TESTNET,
    walletWasmHash: WASM_HASH,
    rpId: RP_ID,
    allowedOrigins: [ORIGIN],
    storage,
    WebAuthn: {
      startRegistration: vi.fn(),
      startAuthentication: vi.fn(async () => AUTH_RESPONSE),
    } as never,
    ...overrides,
  });
}

// --- Birth-transaction fixtures --------------------------------------------

interface Birth {
  contractId: string;
  txHash: string;
  envelopeXdr: string;
  ledger: number;
  wasmHash: string;
}

/** Craft a real CreateContractV2 transaction and the address it creates. */
function makeBirth(saltSeed: number, wasmHex: string, ledger: number): Birth {
  const deployer = Keypair.random().publicKey();
  const salt = Buffer.alloc(32, saltSeed);
  const preimage = xdr.ContractIdPreimage.contractIdPreimageFromAddress(
    new xdr.ContractIdPreimageFromAddress({
      address: Address.fromString(deployer).toScAddress(),
      salt,
    })
  );
  const func = xdr.HostFunction.hostFunctionTypeCreateContractV2(
    new xdr.CreateContractArgsV2({
      contractIdPreimage: preimage,
      executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.from(wasmHex, "hex")),
      constructorArgs: [],
    })
  );
  const source = new Account(deployer, "0");
  const tx = new TransactionBuilder(source, {
    fee: "100",
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(Operation.invokeHostFunction({ func, auth: [] }))
    .setTimeout(30)
    .build();

  const contractId = StrKey.encodeContract(
    hash(
      xdr.HashIdPreimage.envelopeTypeContractId(
        new xdr.HashIdPreimageContractId({
          networkId: hash(Buffer.from(Networks.TESTNET)),
          contractIdPreimage: preimage,
        })
      ).toXDR()
    )
  );

  return {
    contractId,
    txHash: tx.hash().toString("hex"),
    envelopeXdr: tx.toEnvelope().toXDR("base64"),
    ledger,
    wasmHash: wasmHex,
  };
}

const candidateOf = (birth: Birth) => ({
  contractId: birth.contractId,
  birthWasmHash: birth.wasmHash,
  creationTransactionHash: birth.txHash,
  creationLedger: birth.ledger,
});

function completeLookup(births: Birth[], indexedThroughLedger: number) {
  return {
    schema: 2 as const,
    complete: true as const,
    indexedThroughLedger,
    candidates: births.map(candidateOf),
  };
}

/** A `getTransaction` stub that answers SUCCESS for the given births. */
function txStub(births: Birth[]) {
  const byHash = new Map(
    births.map((b) => [
      b.txHash,
      { status: Api.GetTransactionStatus.SUCCESS, ledger: b.ledger, envelopeXdr: b.envelopeXdr },
    ])
  );
  return vi.fn(async (h: string) => byHash.get(h) ?? { status: Api.GetTransactionStatus.NOT_FOUND });
}

/** `getContractData` result carrying a WASM executable hash. */
function instanceWithWasm(hashHex: string) {
  return {
    val: {
      contractData: () => ({
        val: () => ({
          instance: () => ({
            executable: () => ({
              switch: () => ({ name: "contractExecutableWasm" }),
              wasmHash: () => Buffer.from(hashHex, "hex"),
            }),
          }),
        }),
      }),
    },
  };
}

function liveSignerVal() {
  return { tag: "Secp256r1", values: [PUBLIC_KEY, [undefined], [undefined]] };
}

/** Wire the current-code, live-signer, and provenance stubs a passing candidate needs. */
function stubProvenance(kit: PasskeyKit, opts: { liveSigner?: unknown } = {}) {
  vi.spyOn(kit.rpc, "getContractData").mockResolvedValue(instanceWithWasm(WASM_HASH) as never);
  vi.spyOn(
    (kit as unknown as { signerManager: { getSigner: unknown } }).signerManager as never,
    "getSigner"
  ).mockResolvedValue(
    ("liveSigner" in opts ? opts.liveSigner : liveSignerVal()) as never
  );
  vi.spyOn(kit as never, "assertSignerProvenance" as never).mockResolvedValue(undefined as never);
}

function storedPasskeyFrom(birth: Birth): StoredPasskey {
  return {
    keyId: KEY_ID_B64,
    publicKey: PUBLIC_KEY,
    contractId: birth.contractId,
    birthWasmHash: birth.wasmHash,
    creationTransactionHash: birth.txHash,
    creationLedger: birth.ledger,
    createdAt: 0,
  };
}

// ---------------------------------------------------------------------------
// Restore-source resolution (preserved)
// ---------------------------------------------------------------------------

describe("restore source resolution", () => {
  const restoreKeypairOf = (kit: PasskeyKit) =>
    (
      kit as unknown as {
        submissionManager: { deps: { restoreKeypair?: { publicKey(): string } } };
      }
    ).submissionManager.deps.restoreKeypair;

  const base = {
    rpcUrl: "https://rpc.example",
    networkPassphrase: Networks.TESTNET,
    walletWasmHash: WASM_HASH,
    rpId: RP_ID,
    allowedOrigins: [ORIGIN],
    WebAuthn: { startRegistration: vi.fn(), startAuthentication: vi.fn() } as never,
  };

  it("leaves restores unconfigured for the SHARED default deployer", () => {
    expect(restoreKeypairOf(new PasskeyKit({ ...base }))).toBeUndefined();
  });

  it("falls back to a CUSTOM funded deploySource (address-preserving)", () => {
    const custom = Keypair.random();
    const kit = new PasskeyKit({ ...base, deploySource: custom.secret() });
    expect(restoreKeypairOf(kit)?.publicKey()).toBe(custom.publicKey());
  });

  it("prefers an explicit restoreSource over the custom deploySource", () => {
    const custom = Keypair.random();
    const restore = Keypair.random();
    const kit = new PasskeyKit({
      ...base,
      deploySource: custom.secret(),
      restoreSource: restore.secret(),
    });
    expect(restoreKeypairOf(kit)?.publicKey()).toBe(restore.publicKey());
  });
});

// ---------------------------------------------------------------------------
// WebAuthn verification config
// ---------------------------------------------------------------------------

describe("WebAuthn verification config", () => {
  it("requires rpId and allowedOrigins before minting a binding proof", async () => {
    // No rpId/allowedOrigins and no browser globals: provenance config fails closed.
    const kit = new PasskeyKit({
      rpcUrl: "https://rpc.example",
      networkPassphrase: Networks.TESTNET,
      walletWasmHash: WASM_HASH,
      WebAuthn: { startRegistration: vi.fn(), startAuthentication: vi.fn() } as never,
    });
    vi.spyOn(kit, "createKey").mockResolvedValue({
      rawResponse: {} as never,
      keyId: KEY_ID_B64,
      keyIdBuffer: KEY_ID,
      publicKey: PUBLIC_KEY,
    } as never);
    vi.spyOn(
      (kit as unknown as { submissionManager: { deriveWalletAddress: unknown } })
        .submissionManager as never,
      "deriveWalletAddress"
    ).mockReturnValue("CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ" as never);

    await expect(kit.createWallet("App", "User")).rejects.toBeInstanceOf(ConfigurationError);
  });
});

// ---------------------------------------------------------------------------
// connectWallet — candidate discovery + birth-gated verification
// ---------------------------------------------------------------------------

describe("connectWallet discovery", () => {
  let birth: Birth;

  beforeEach(() => {
    birth = makeBirth(0x01, WASM_HASH, 40);
  });

  it("rejects an incomplete indexer lookup", async () => {
    const kit = makeKit();
    stubProvenance(kit);
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);

    await expect(
      kit.connectWallet({
        keyId: KEY_ID_B64,
        getWalletCandidates: async () => ({ complete: false, candidates: [] }),
      })
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });

  it("rejects a lookup whose indexedThroughLedger is below the pre-lookup RPC ledger", async () => {
    const kit = makeKit();
    stubProvenance(kit);
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 100 } as never);

    const error = await kit
      .connectWallet({
        keyId: KEY_ID_B64,
        getWalletCandidates: async () => completeLookup([birth], 99),
      })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(WalletOwnershipError);
    expect((error as WalletOwnershipError).context).toMatchObject({
      indexedThroughLedger: 99,
      requiredLedger: 100,
    });
  });

  it("connects when a fresh, complete lookup yields exactly one verified candidate", async () => {
    const kit = makeKit();
    stubProvenance(kit);
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);
    vi.spyOn(kit.rpc, "getTransaction").mockImplementation(txStub([birth]) as never);

    const result = await kit.connectWallet({
      keyId: KEY_ID_B64,
      getWalletCandidates: async () => completeLookup([birth], 45),
    });

    expect(result.contractId).toBe(birth.contractId);
    expect(kit.contractId).toBe(birth.contractId);
  });

  it("fails closed when a candidate is missing birth fields", async () => {
    const kit = makeKit();
    stubProvenance(kit);
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);
    const getTransaction = vi.spyOn(kit.rpc, "getTransaction");

    const lookup = {
      schema: 2 as const,
      complete: true as const,
      indexedThroughLedger: 45,
      candidates: [
        { contractId: birth.contractId, birthWasmHash: "", creationTransactionHash: "", creationLedger: 0 },
      ],
    };

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64, getWalletCandidates: async () => lookup })
    ).rejects.toBeInstanceOf(WalletOwnershipError);
    // Malformed birth metadata is rejected before any RPC round-trip.
    expect(getTransaction).not.toHaveBeenCalled();
  });

  it("requires the birth transaction to be RPC-verified (not found fails closed)", async () => {
    const kit = makeKit();
    stubProvenance(kit);
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);
    vi.spyOn(kit.rpc, "getTransaction").mockResolvedValue({
      status: Api.GetTransactionStatus.NOT_FOUND,
    } as never);

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64, getWalletCandidates: async () => completeLookup([birth], 45) })
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });

  it("rejects evil birth even when the current code is accepted", async () => {
    // Custom code was born at the address, then upgraded to accepted WASM. The
    // immutable birth WASM is not accepted, so the candidate is rejected.
    const evil = makeBirth(0x02, EVIL_HASH, 41);
    const kit = makeKit();
    stubProvenance(kit); // getContractData returns the ACCEPTED current code
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);
    vi.spyOn(kit.rpc, "getTransaction").mockImplementation(txStub([evil]) as never);

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64, getWalletCandidates: async () => completeLookup([evil], 45) })
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });

  it("rejects an accepted-birth candidate with no live signer for the passkey", async () => {
    const kit = makeKit();
    stubProvenance(kit, { liveSigner: null });
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);
    vi.spyOn(kit.rpc, "getTransaction").mockImplementation(txStub([birth]) as never);

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64, getWalletCandidates: async () => completeLookup([birth], 45) })
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });

  it("raises WalletAmbiguousError when two candidates both fully verify", async () => {
    const a = makeBirth(0x03, WASM_HASH, 42);
    const b = makeBirth(0x04, WASM_HASH, 43);
    const kit = makeKit();
    stubProvenance(kit);
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);
    vi.spyOn(kit.rpc, "getTransaction").mockImplementation(txStub([a, b]) as never);

    const error = await kit
      .connectWallet({ keyId: KEY_ID_B64, getWalletCandidates: async () => completeLookup([a, b], 45) })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(WalletAmbiguousError);
    expect((error as WalletAmbiguousError).candidates.sort()).toEqual([a.contractId, b.contractId].sort());
    expect(kit.contractId).toBeUndefined();
  });

  it("drops one invalid candidate and connects to the single valid one", async () => {
    const evil = makeBirth(0x05, EVIL_HASH, 44);
    const good = makeBirth(0x06, WASM_HASH, 45);
    const kit = makeKit();
    stubProvenance(kit);
    vi.spyOn(kit.rpc, "getLatestLedger").mockResolvedValue({ sequence: 40 } as never);
    vi.spyOn(kit.rpc, "getTransaction").mockImplementation(txStub([evil, good]) as never);

    const result = await kit.connectWallet({
      keyId: KEY_ID_B64,
      getWalletCandidates: async () => completeLookup([evil, good], 46),
    });

    expect(result.contractId).toBe(good.contractId);
  });

  it("uses a verified local storage candidate and rechecks its birth on-chain", async () => {
    const storage = new MemoryStorage();
    await storage.save(storedPasskeyFrom(birth));
    const kit = makeKit(storage);
    stubProvenance(kit);
    const getTransaction = vi
      .spyOn(kit.rpc, "getTransaction")
      .mockImplementation(txStub([birth]) as never);
    const getWalletCandidates = vi.fn();

    const result = await kit.connectWallet({ keyId: KEY_ID_B64, getWalletCandidates });

    expect(result.contractId).toBe(birth.contractId);
    // Storage is trusted only after the recent creation transaction is re-verified.
    expect(getTransaction).toHaveBeenCalledWith(birth.txHash);
    // A verified stored candidate needs no indexer lookup.
    expect(getWalletCandidates).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// createWallet / confirmWalletCreation
// ---------------------------------------------------------------------------

describe("createWallet persistence", () => {
  it("stays unpersisted until confirmWalletCreation verifies birth", async () => {
    const birth = makeBirth(0x11, WASM_HASH, 70);
    const storage = new MemoryStorage();
    const kit = makeKit(storage);

    vi.spyOn(kit, "createKey").mockResolvedValue({
      rawResponse: {} as never,
      keyId: KEY_ID_B64,
      keyIdBuffer: KEY_ID,
      publicKey: PUBLIC_KEY,
    } as never);
    const submissionManager = (
      kit as unknown as {
        submissionManager: {
          deriveWalletAddress: unknown;
          buildDeployTransaction: unknown;
          signDeploy: unknown;
        };
      }
    ).submissionManager;
    vi.spyOn(submissionManager as never, "deriveWalletAddress").mockReturnValue(
      birth.contractId as never
    );
    vi.spyOn(kit as never, "createBindingProof" as never).mockResolvedValue(
      BINDING_PROOF as never
    );
    vi.spyOn(submissionManager as never, "buildDeployTransaction").mockResolvedValue({
      result: { options: { contractId: birth.contractId } },
    } as never);
    vi.spyOn(submissionManager as never, "signDeploy").mockResolvedValue("signed-xdr" as never);

    const created = await kit.createWallet("App", "User");
    expect(created).toMatchObject({ contractId: birth.contractId, signedTx: "signed-xdr" });

    // Nothing is persisted before confirmation.
    expect(await storage.get(KEY_ID_B64)).toBeNull();

    vi.spyOn(kit.rpc, "getTransaction").mockImplementation(txStub([birth]) as never);
    const verified = await kit.confirmWalletCreation(created, birth.txHash);

    expect(verified.birthWasmHash).toBe(WASM_HASH);
    const stored = await storage.get(KEY_ID_B64);
    expect(stored).toMatchObject({
      contractId: birth.contractId,
      birthWasmHash: WASM_HASH,
      creationTransactionHash: birth.txHash,
      creationLedger: birth.ledger,
    });
  });

  it("refuses to confirm a wallet whose birth WASM is not accepted", async () => {
    const evil = makeBirth(0x12, EVIL_HASH, 71);
    const kit = makeKit(new MemoryStorage());
    vi.spyOn(kit.rpc, "getTransaction").mockImplementation(txStub([evil]) as never);

    const created = {
      rawResponse: {} as never,
      keyId: KEY_ID,
      keyIdBase64: KEY_ID_B64,
      publicKey: PUBLIC_KEY,
      contractId: evil.contractId,
      signedTx: "signed",
    };

    await expect(kit.confirmWalletCreation(created, evil.txHash)).rejects.toBeInstanceOf(
      WalletOwnershipError
    );
  });
});

// ---------------------------------------------------------------------------
// addSecp256r1 birth-metadata copy
// ---------------------------------------------------------------------------

describe("addSecp256r1 persistence", () => {
  const NEW_KEY = base64url.encode(Buffer.alloc(16, 9));
  const NEW_PUB = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xa9)]);

  it("copies the connected wallet's verified birth metadata to the new signer", async () => {
    const birth = makeBirth(0x21, WASM_HASH, 80);
    const storage = new MemoryStorage();
    await storage.save(storedPasskeyFrom(birth));
    const kit = makeKit(storage);
    kit.wallet = { options: { contractId: birth.contractId } } as never;
    kit.keyId = KEY_ID_B64;

    vi.spyOn(kit as never, "createBindingProof" as never).mockResolvedValue(
      BINDING_PROOF as never
    );
    vi.spyOn(
      (kit as unknown as { signerManager: { addSecp256r1: unknown } }).signerManager as never,
      "addSecp256r1"
    ).mockResolvedValue("AT_ADD" as never);

    const tx = await kit.addSecp256r1(NEW_KEY, NEW_PUB, undefined as never, SignerStore.Persistent);
    expect(tx).toBe("AT_ADD");

    const stored = await storage.get(NEW_KEY);
    expect(stored).toMatchObject({
      contractId: birth.contractId,
      publicKey: NEW_PUB,
      birthWasmHash: birth.wasmHash,
      creationTransactionHash: birth.txHash,
      creationLedger: birth.ledger,
    });
  });

  it("refuses to add when the connected wallet has no verified birth record", async () => {
    const kit = makeKit(new MemoryStorage());
    kit.wallet = { options: { contractId: "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ" } } as never;
    kit.keyId = KEY_ID_B64; // no stored record for this keyId
    vi.spyOn(kit as never, "createBindingProof" as never).mockResolvedValue(
      BINDING_PROOF as never
    );
    vi.spyOn(
      (kit as unknown as { signerManager: { addSecp256r1: unknown } }).signerManager as never,
      "addSecp256r1"
    ).mockResolvedValue("AT_ADD" as never);

    await expect(
      kit.addSecp256r1(NEW_KEY, NEW_PUB, undefined as never, SignerStore.Persistent)
    ).rejects.toBeInstanceOf(WalletOwnershipError);
  });
});
