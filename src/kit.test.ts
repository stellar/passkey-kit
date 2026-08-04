/**
 * `connectWallet` resolution + verification behavior:
 *
 * - Address resolution is trusted-state-first: local storage, then the injected
 *   indexer, then deterministic derivation LAST. Derivation is only correct for
 *   a wallet's first credential and is the one path a squatted contract at the
 *   derived address can hijack, so it must never win over a stored/indexed
 *   association.
 * - A transport error on the derived-address instance read PROPAGATES — it must
 *   never be misread as not-found (derivation is reached only when storage and
 *   the indexer both miss).
 * - A failed opt-in `verifyWasmHash` leaves the kit disconnected, so a
 *   subsequent `sign` cannot operate on the rejected contract.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { Keypair, Networks, xdr } from "@stellar/stellar-sdk";
import type { Spec as ContractSpec } from "@stellar/stellar-sdk/contract";
import { Client as PasskeyClient, type SignerVal } from "passkey-kit-sdk";
import { PasskeyKit } from "./kit.js";
import { SignerStore } from "./types.js";
import { MemoryStorage } from "./storage/memory.js";
import { WalletOwnershipError } from "./errors.js";
import { SIGNER_VAL_UDT } from "./kit/auth-payload.js";
import base64url from "./base64url.js";

const WASM_HASH = "ab".repeat(32);
const KEY_ID = Buffer.alloc(16, 7);
const KEY_ID_B64 = base64url.encode(KEY_ID);
const INDEXED_WALLET = "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ";
const STORED_WALLET = "CDXICVKLHPPAZ3EM65OESOGBSQE4YQGFN6JK7ICPYUXDAQPAVXBZ4PAT";

function makeKit(
  storage?: MemoryStorage,
  overrides?: { acceptedWasmHashes?: string[] }
): PasskeyKit {
  return new PasskeyKit({
    rpcUrl: "https://rpc.example",
    networkPassphrase: Networks.TESTNET,
    walletWasmHash: WASM_HASH,
    storage,
    ...overrides,
    WebAuthn: {
      startRegistration: vi.fn(),
      startAuthentication: vi.fn(),
    } as never,
  });
}

describe("restore source resolution", () => {
  /** Read the keypair the kit wired into SubmissionManager for restores. */
  const restoreKeypairOf = (kit: PasskeyKit) =>
    (kit as unknown as { submissionManager: { deps: { restoreKeypair?: { publicKey(): string } } } })
      .submissionManager.deps.restoreKeypair;

  const base = {
    rpcUrl: "https://rpc.example",
    networkPassphrase: Networks.TESTNET,
    walletWasmHash: WASM_HASH,
    WebAuthn: { startRegistration: vi.fn(), startAuthentication: vi.fn() } as never,
  };

  it("leaves restores unconfigured for the SHARED default deployer", () => {
    // The shared deployer must never source or fund a transaction, so there is
    // deliberately no fallback — restoreFootprint fails closed until the
    // integrator supplies a funded restoreSource.
    expect(restoreKeypairOf(new PasskeyKit({ ...base }))).toBeUndefined();
  });

  it("falls back to a CUSTOM funded deploySource (address-preserving)", () => {
    const custom = Keypair.random();
    const kit = new PasskeyKit({ ...base, deploySource: custom.secret() });
    // Custom deployers keep their pre-existing ability to source restores; their
    // derived addresses are unaffected because the deployer identity is unchanged.
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

/** A ledger entry whose contractData().val() decodes to a live SignerVal. */
function signerEntry() {
  const spec = (
    new PasskeyClient({
      contractId: INDEXED_WALLET,
      networkPassphrase: Networks.TESTNET,
      rpcUrl: "https://rpc.example",
    }) as unknown as { spec: ContractSpec }
  ).spec;
  const signerVal: SignerVal = {
    tag: "Secp256r1",
    values: [
      Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xc1)]),
      [undefined],
      [undefined],
    ],
  };
  const scVal = spec.nativeToScVal(signerVal, SIGNER_VAL_UDT);
  return { val: { contractData: () => ({ val: () => scVal }) } };
}

/** An instance-shaped entry for the bare "does the instance exist" probe. */
function instanceEntry() {
  return { val: { contractData: () => ({ val: () => xdr.ScVal.scvVoid() }) } };
}

/** Fake `getContractData` result carrying a WASM executable hash. */
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

describe("connectWallet address resolution", () => {
  let kit: PasskeyKit;

  beforeEach(() => {
    kit = makeKit();
    // Untrusted resolution (indexer/derivation) now binds code identity before
    // reading signer state, so these paths perform an instance read. Accepted
    // code by default; the rejection cases live in their own describe below.
    vi.spyOn(kit.rpc, "getContractData").mockResolvedValue(
      instanceWithWasm(WASM_HASH) as never
    );
  });

  it("prefers stored state over a squattable derived address — no derivation probe", async () => {
    // The security fix: a stored association wins outright, so a secondary
    // passkey never resolves to derive(keyId) even if an attacker squatted code
    // there. `getLedgerEntries` is only the ownership check on the stored wallet.
    const storage = new MemoryStorage();
    await storage.save({
      keyId: KEY_ID_B64,
      publicKey: Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xc1)]),
      contractId: STORED_WALLET,
      createdAt: 0,
    });
    const kitS = makeKit(storage);
    const getLedgerEntries = vi
      .spyOn(kitS.rpc, "getLedgerEntries")
      // ownership check on the stored wallet (temporary durability): found
      .mockResolvedValueOnce({ entries: [signerEntry()] } as never);
    const getContractId = vi.fn(async () => INDEXED_WALLET);

    const result = await kitS.connectWallet({ keyId: KEY_ID_B64, getContractId });

    expect(result.contractId).toBe(STORED_WALLET);
    expect(kitS.contractId).toBe(STORED_WALLET);
    // Neither the indexer nor the derived-address instance probe was consulted.
    expect(getContractId).not.toHaveBeenCalled();
    expect(getLedgerEntries).toHaveBeenCalledTimes(1);
  });

  it("uses the indexer when storage misses — derivation is not consulted", async () => {
    const getLedgerEntries = vi
      .spyOn(kit.rpc, "getLedgerEntries")
      // ownership check on the indexer-resolved wallet (temporary durability)
      .mockResolvedValueOnce({ entries: [signerEntry()] } as never);
    const getContractId = vi.fn(async () => INDEXED_WALLET);

    const result = await kit.connectWallet({ keyId: KEY_ID_B64, getContractId });

    expect(getContractId).toHaveBeenCalledWith(KEY_ID_B64);
    expect(result.contractId).toBe(INDEXED_WALLET);
    expect(kit.contractId).toBe(INDEXED_WALLET);
    // Only the ownership read ran — no derived-address instance probe.
    expect(getLedgerEntries).toHaveBeenCalledTimes(1);
  });

  it("falls back to deterministic derivation only when storage AND indexer miss", async () => {
    vi.spyOn(kit.rpc, "getLedgerEntries")
      // 1) derived-address instance probe: found
      .mockResolvedValueOnce({ entries: [instanceEntry()] } as never)
      // 2) ownership check (temporary durability): found
      .mockResolvedValueOnce({ entries: [signerEntry()] } as never);
    const getContractId = vi.fn(async () => undefined);

    const result = await kit.connectWallet({ keyId: KEY_ID_B64, getContractId });

    // The indexer was tried first and missed, so derivation resolved it.
    expect(getContractId).toHaveBeenCalledWith(KEY_ID_B64);
    expect(result.contractId).not.toBe(INDEXED_WALLET);
    expect(result.contractId).toMatch(/^C/);
  });

  it("propagates a transport error on the derivation read — no not-found misread", async () => {
    // Reached only after storage + indexer miss; a 429 there must not be treated
    // as an authoritative not-found.
    vi.spyOn(kit.rpc, "getLedgerEntries").mockRejectedValue(
      new Error("429 too many requests")
    );
    const getContractId = vi.fn(async () => undefined);

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64, getContractId })
    ).rejects.toThrow("429");

    expect(getContractId).toHaveBeenCalledWith(KEY_ID_B64);
    expect(kit.wallet).toBeUndefined();
    expect(kit.keyId).toBeUndefined();
  });

  it("disconnects on an ownership mismatch (keyId not a signer)", async () => {
    vi.spyOn(kit.rpc, "getLedgerEntries")
      .mockResolvedValueOnce({ entries: [instanceEntry()] } as never) // instance
      .mockResolvedValueOnce({ entries: [] } as never) // signer: temporary
      .mockResolvedValueOnce({ entries: [] } as never); // signer: persistent

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64 })
    ).rejects.toBeInstanceOf(WalletOwnershipError);
    expect(kit.wallet).toBeUndefined();
    expect(kit.keyId).toBeUndefined();
  });
});

describe("addSecp256r1 persistence", () => {
  const NEW_KEY_ID = base64url.encode(Buffer.alloc(16, 9));
  const NEW_PUBKEY = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xa9)]);

  it("records the new keyId → connected-wallet mapping so a later connect is storage-first", async () => {
    const storage = new MemoryStorage();
    const kit = makeKit(storage);
    // Pretend a wallet is connected (add_signer is wallet-authorized).
    kit.wallet = { options: { contractId: STORED_WALLET } } as never;
    // Stub the build so no real tx is assembled.
    vi.spyOn(
      (kit as unknown as { signerManager: { addSecp256r1: unknown } })
        .signerManager as never,
      "addSecp256r1"
    ).mockResolvedValue("AT_ADD" as never);

    const tx = await kit.addSecp256r1(
      NEW_KEY_ID,
      NEW_PUBKEY,
      undefined as never,
      SignerStore.Persistent
    );

    expect(tx).toBe("AT_ADD");
    const stored = await storage.get(NEW_KEY_ID);
    expect(stored?.contractId).toBe(STORED_WALLET);
    expect(Buffer.from(stored!.publicKey)).toEqual(NEW_PUBKEY);
  });

  it("does not persist when no wallet is connected", async () => {
    const storage = new MemoryStorage();
    const kit = makeKit(storage);
    vi.spyOn(
      (kit as unknown as { signerManager: { addSecp256r1: unknown } })
        .signerManager as never,
      "addSecp256r1"
    ).mockResolvedValue("AT_ADD" as never);

    await kit.addSecp256r1(
      NEW_KEY_ID,
      NEW_PUBKEY,
      undefined as never,
      SignerStore.Persistent
    );

    expect(await storage.get(NEW_KEY_ID)).toBeNull();
  });
});

describe("connectWallet code identity (default-on for untrusted resolution)", () => {
  it("REJECTS an indexer row running unaccepted code, with no opt-in", async () => {
    // The reverse lookup is a claim by an untrusted party: any contract can emit
    // the signer events an indexer keys on AND write the signer ledger entry we
    // read back, so signer state alone proves nothing. Binding accepted code is
    // what makes that state meaningful. No flag is passed here on purpose.
    const kit = makeKit();
    const getLedgerEntries = vi
      .spyOn(kit.rpc, "getLedgerEntries")
      .mockResolvedValue({ entries: [signerEntry()] } as never);
    vi.spyOn(kit.rpc, "getContractData").mockResolvedValue(
      instanceWithWasm("cd".repeat(32)) as never // not the accepted hash
    );

    await expect(
      kit.connectWallet({
        keyId: KEY_ID_B64,
        getContractId: async () => INDEXED_WALLET,
      })
    ).rejects.toBeInstanceOf(WalletOwnershipError);

    expect(kit.wallet).toBeUndefined();
    expect(kit.keyId).toBeUndefined();
    // Code identity is bound BEFORE any signer read — a forged signer entry on
    // attacker-authored code must never be consulted at all.
    expect(getLedgerEntries).not.toHaveBeenCalled();
  });

  it("does NOT check a storage-resolved address, so an upgraded wallet still opens", async () => {
    const storage = new MemoryStorage();
    await storage.save({
      keyId: KEY_ID_B64,
      publicKey: Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xc1)]),
      contractId: STORED_WALLET,
      createdAt: 0,
    });
    const kitS = makeKit(storage);
    vi.spyOn(kitS.rpc, "getLedgerEntries").mockResolvedValueOnce({
      entries: [signerEntry()],
    } as never);
    const getContractData = vi
      .spyOn(kitS.rpc, "getContractData")
      .mockResolvedValue(instanceWithWasm("cd".repeat(32)) as never);

    const result = await kitS.connectWallet({ keyId: KEY_ID_B64 });

    expect(result.contractId).toBe(STORED_WALLET);
    expect(getContractData).not.toHaveBeenCalled();
  });

  it("accepts any hash on the allowlist, not just the deploy hash", async () => {
    const UPGRADED = "ef".repeat(32);
    const kit = makeKit(undefined, { acceptedWasmHashes: [WASM_HASH, UPGRADED] });
    vi.spyOn(kit.rpc, "getLedgerEntries").mockResolvedValue({
      entries: [signerEntry()],
    } as never);
    vi.spyOn(kit.rpc, "getContractData").mockResolvedValue(
      instanceWithWasm(UPGRADED) as never
    );

    const result = await kit.connectWallet({
      keyId: KEY_ID_B64,
      getContractId: async () => INDEXED_WALLET,
    });

    expect(result.contractId).toBe(INDEXED_WALLET);
  });

  it("lets a caller opt out explicitly", async () => {
    const kit = makeKit();
    vi.spyOn(kit.rpc, "getLedgerEntries").mockResolvedValue({
      entries: [signerEntry()],
    } as never);
    const getContractData = vi
      .spyOn(kit.rpc, "getContractData")
      .mockResolvedValue(instanceWithWasm("cd".repeat(32)) as never);

    const result = await kit.connectWallet({
      keyId: KEY_ID_B64,
      getContractId: async () => INDEXED_WALLET,
      verifyWasmHash: false,
    });

    expect(result.contractId).toBe(INDEXED_WALLET);
    expect(getContractData).not.toHaveBeenCalled();
  });
});

describe("connectWallet verifyWasmHash", () => {
  let kit: PasskeyKit;

  beforeEach(() => {
    kit = makeKit();
    vi.spyOn(kit.rpc, "getLedgerEntries")
      .mockResolvedValueOnce({ entries: [instanceEntry()] } as never) // instance
      .mockResolvedValueOnce({ entries: [signerEntry()] } as never); // signer
  });

  it("clears wallet/keyId when the WASM hash does not match", async () => {
    vi.spyOn(kit.rpc, "getContractData").mockResolvedValue(
      instanceWithWasm("cd".repeat(32)) as never
    );

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64, verifyWasmHash: true })
    ).rejects.toBeInstanceOf(WalletOwnershipError);

    // The rejected contract must NOT stay connected (a later sign() would
    // silently target it).
    expect(kit.wallet).toBeUndefined();
    expect(kit.keyId).toBeUndefined();
    expect(kit.contractId).toBeUndefined();
  });

  it("clears wallet/keyId when the hash read itself fails", async () => {
    vi.spyOn(kit.rpc, "getContractData").mockRejectedValue(
      new Error("503 upstream timeout")
    );

    await expect(
      kit.connectWallet({ keyId: KEY_ID_B64, verifyWasmHash: true })
    ).rejects.toThrow("503");
    expect(kit.wallet).toBeUndefined();
    expect(kit.keyId).toBeUndefined();
  });

  it("stays connected when the WASM hash matches", async () => {
    vi.spyOn(kit.rpc, "getContractData").mockResolvedValue(
      instanceWithWasm(WASM_HASH) as never
    );

    const result = await kit.connectWallet({
      keyId: KEY_ID_B64,
      verifyWasmHash: true,
    });

    expect(kit.contractId).toBe(result.contractId);
    expect(kit.keyId).toBe(KEY_ID_B64);
  });
});
