/**
 * Legacy-wallet upgrade helpers: classification, inspection against mocked
 * ledger state, transaction shape, and signing without a connected wallet.
 */

import { describe, expect, it, vi } from "vitest";
import { Address, Keypair, Networks, Operation, xdr } from "@stellar/stellar-sdk";
import { Server } from "@stellar/stellar-sdk/rpc";
import { Client as PasskeyClient } from "passkey-kit-sdk";

import {
  KNOWN_VULNERABLE_WALLET_WASM_HASHES,
  LEGACY_UPGRADE_TARGET_WASM_HASH,
  LEGACY_WALLET_WASM_HASHES,
} from "../constants.js";
import { PasskeyKitErrorCode, ValidationError } from "../errors.js";
import { Ed25519Signer } from "../signers.js";
import base64url from "../base64url.js";
import {
  BARE_LAYOUT_WALLET_WASM_HASHES,
  buildLegacyMigrateTx,
  buildLegacyUpgradeTx,
  classifyWasmHash,
  inspectLegacyWallet,
  signLegacyUpgradeTx,
} from "./legacy-ops.js";

const RPC_URL = "https://rpc.example";
const WALLET = "CA2W527X3BNSF5NOQ5GOCM2TFFYYTC6U3I2JDDIBA6PKAWVEBOJFSUC3";
const CURRENT = "ab".repeat(32);
const VULN_BARE = BARE_LAYOUT_WALLET_WASM_HASHES[0]!;
const VULN_WRAPPED = KNOWN_VULNERABLE_WALLET_WASM_HASHES.find(
  (h) => !BARE_LAYOUT_WALLET_WASM_HASHES.includes(h)
)!;
const PATCHED = LEGACY_WALLET_WASM_HASHES[0]!;

const spec = new PasskeyClient({
  contractId: WALLET,
  rpcUrl: RPC_URL,
  networkPassphrase: Networks.TESTNET,
}).spec;

describe("classifyWasmHash", () => {
  it("recognizes every known class, case-insensitively", () => {
    expect(classifyWasmHash(CURRENT, [CURRENT])).toEqual({ status: "current", cohort: null });
    expect(classifyWasmHash(VULN_BARE.toUpperCase(), [CURRENT])).toEqual({
      status: "vulnerable",
      cohort: "bare",
    });
    expect(classifyWasmHash(VULN_WRAPPED, [CURRENT])).toEqual({
      status: "vulnerable",
      cohort: "wrapped",
    });
    expect(classifyWasmHash(PATCHED, [CURRENT])).toEqual({ status: "legacy", cohort: "wrapped" });
    expect(classifyWasmHash("00".repeat(32), [CURRENT])).toEqual({
      status: "unknown",
      cohort: null,
    });
  });

  it("treats an accepted hash as current even if it is a legacy build", () => {
    expect(classifyWasmHash(PATCHED, [PATCHED]).status).toBe("current");
  });
});

/** A getLedgerEntries stub: `live` keys get a future TTL, the rest are archived. */
function ledgerEntriesStub(latestLedger: number, liveKeys: xdr.LedgerKey[]) {
  const live = new Set(liveKeys.map((k) => k.toXDR("base64")));
  return vi.fn(async (...keys: xdr.LedgerKey[]) => ({
    latestLedger,
    entries: keys.map((key) => ({
      key,
      val: xdr.LedgerEntryData.contractCode(
        new xdr.ContractCodeEntry({
          ext: new xdr.ContractCodeEntryExt(0),
          hash: Buffer.alloc(32),
          code: Buffer.alloc(0),
        })
      ),
      lastModifiedLedgerSeq: 1,
      liveUntilLedgerSeq: live.has(key.toXDR("base64")) ? latestLedger + 1000 : 0,
    })),
  }));
}

function codeKey(hash: string) {
  return xdr.LedgerKey.contractCode(
    new xdr.LedgerKeyContractCode({ hash: Buffer.from(hash, "hex") })
  );
}

describe("inspectLegacyWallet", () => {
  it("describes a bare-cohort vulnerable wallet with archived entries", async () => {
    const rpc = {
      getLedgerEntries: ledgerEntriesStub(100, [codeKey(LEGACY_UPGRADE_TARGET_WASM_HASH)]),
    } as unknown as Server;
    const inspection = await inspectLegacyWallet(
      { rpc, acceptedWasmHashes: [CURRENT], contractWasmHash: async () => VULN_BARE },
      WALLET
    );
    expect(inspection).toMatchObject({
      status: "vulnerable",
      cohort: "bare",
      upgradeRequired: true,
      migrateRequired: true,
      upgradeTarget: LEGACY_UPGRADE_TARGET_WASM_HASH,
      archived: { instance: true, code: true, target: false },
    });
    expect(inspection.recommendation).toContain("restore the archived entries (instance, current code)");
    expect(inspection.recommendation).toContain("migrate_signers");
  });

  it("describes a wrapped-cohort vulnerable wallet with everything live", async () => {
    const target = codeKey(LEGACY_UPGRADE_TARGET_WASM_HASH);
    const current = codeKey(VULN_WRAPPED);
    const instance = xdr.LedgerKey.contractData(
      new xdr.LedgerKeyContractData({
        contract: Address.fromString(WALLET).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent(),
      })
    );
    const rpc = {
      getLedgerEntries: ledgerEntriesStub(100, [target, current, instance]),
    } as unknown as Server;
    const inspection = await inspectLegacyWallet(
      { rpc, acceptedWasmHashes: [CURRENT], contractWasmHash: async () => VULN_WRAPPED },
      WALLET
    );
    expect(inspection).toMatchObject({
      status: "vulnerable",
      cohort: "wrapped",
      upgradeRequired: true,
      migrateRequired: false,
      archived: { instance: false, code: false, target: false },
    });
    expect(inspection.recommendation).not.toContain("restore");
    expect(inspection.recommendation).not.toContain("migrate_signers");
  });

  it("says nothing is needed for current code, and points patched legacy at the old kit", async () => {
    const rpc = { getLedgerEntries: ledgerEntriesStub(100, []) } as unknown as Server;
    const current = await inspectLegacyWallet(
      { rpc, acceptedWasmHashes: [CURRENT], contractWasmHash: async () => CURRENT },
      WALLET
    );
    expect(current.status).toBe("current");
    expect(current.upgradeRequired).toBe(false);
    const legacy = await inspectLegacyWallet(
      { rpc, acceptedWasmHashes: [CURRENT], contractWasmHash: async () => PATCHED },
      WALLET
    );
    expect(legacy.status).toBe("legacy");
    expect(legacy.upgradeRequired).toBe(false);
    expect(legacy.recommendation).toContain("0.10.20");
  });
});

/** A simulation stub that returns one wallet auth entry rooted at the invoked call. */
function simulationStub() {
  return vi.fn(async (tx: { operations: Operation[] }) => {
    const op = tx.operations[0] as Operation.InvokeHostFunction;
    const invoke = op.func.invokeContract();
    const entry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
        new xdr.SorobanAddressCredentials({
          address: invoke.contractAddress(),
          nonce: xdr.Int64.fromString("7"),
          signatureExpirationLedger: 0,
          signature: xdr.ScVal.scvVoid(),
        })
      ),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(invoke),
        subInvocations: [],
      }),
    });
    return {
      id: "1",
      latestLedger: 100,
      minResourceFee: "100",
      transactionData: new (await import("@stellar/stellar-sdk")).SorobanDataBuilder(),
      events: [],
      result: { auth: [entry], retval: xdr.ScVal.scvU32(1) },
      _parsed: true,
    };
  });
}

describe("buildLegacyUpgradeTx / buildLegacyMigrateTx", () => {
  const deps = { rpcUrl: RPC_URL, networkPassphrase: Networks.TESTNET, timeoutInSeconds: 30, spec };

  it("invokes update_contract_code(target) on the wallet", async () => {
    const sim = vi.spyOn(Server.prototype, "simulateTransaction").mockImplementation(simulationStub() as never);
    try {
      const tx = await buildLegacyUpgradeTx(deps, WALLET);
      const op = tx.built!.operations[0] as Operation.InvokeHostFunction;
      const invoke = op.func.invokeContract();
      expect(Address.fromScAddress(invoke.contractAddress()).toString()).toBe(WALLET);
      expect(invoke.functionName().toString()).toBe("update_contract_code");
      expect(Buffer.from(invoke.args()[0]!.bytes()).toString("hex")).toBe(LEGACY_UPGRADE_TARGET_WASM_HASH);
      expect(op.auth).toHaveLength(1);
    } finally {
      sim.mockRestore();
    }
  });

  it("rejects a malformed target", () => {
    expect(() => buildLegacyUpgradeTx(deps, WALLET, "nope")).toThrow(ValidationError);
  });

  it("invokes migrate_signers with encoded signer keys and parses the count", async () => {
    const sim = vi.spyOn(Server.prototype, "simulateTransaction").mockImplementation(simulationStub() as never);
    try {
      const cred = Buffer.alloc(16, 0xab);
      const tx = await buildLegacyMigrateTx(deps, WALLET, [
        { key: "Secp256r1", value: base64url(cred) },
        { key: "Ed25519", value: Keypair.random().publicKey() },
      ]);
      const invoke = (tx.built!.operations[0] as Operation.InvokeHostFunction).func.invokeContract();
      expect(invoke.functionName().toString()).toBe("migrate_signers");
      const keys = invoke.args()[0]!.vec()!;
      expect(keys).toHaveLength(2);
      expect(keys[0]!.vec()![0]!.sym().toString()).toBe("Secp256r1");
      expect(Buffer.from(keys[0]!.vec()![1]!.bytes()).toString("hex")).toBe(cred.toString("hex"));
      expect(keys[1]!.vec()![0]!.sym().toString()).toBe("Ed25519");
      expect(tx.result).toBe(1);
    } finally {
      sim.mockRestore();
    }
  });

  it("refuses an empty key list", () => {
    expect(() => buildLegacyMigrateTx(deps, WALLET, [])).toThrow(ValidationError);
  });
});

describe("signLegacyUpgradeTx", () => {
  it("signs the wallet's auth entry with an Ed25519 signer, address-bound, without a connected wallet", async () => {
    const sim = vi.spyOn(Server.prototype, "simulateTransaction").mockImplementation(simulationStub() as never);
    try {
      const kp = Keypair.random();
      const tx = await buildLegacyUpgradeTx(
        { rpcUrl: RPC_URL, networkPassphrase: Networks.TESTNET, timeoutInSeconds: 30, spec },
        WALLET
      );
      const signed = await signLegacyUpgradeTx(
        {
          networkPassphrase: Networks.TESTNET,
          spec,
          signerContext: { webAuthn: { startAuthentication: vi.fn() } as never } as never,
          calculateExpiration: async () => 150,
          contractId: WALLET,
        },
        tx,
        new Ed25519Signer(kp)
      );
      const op = signed.built!.operations[0] as Operation.InvokeHostFunction;
      const entry = op.auth[0]!;
      expect(entry.credentials().switch().name).toBe("sorobanCredentialsAddressV2");
      const creds = entry.credentials().addressV2();
      expect(creds.signatureExpirationLedger()).toBe(150);
      const sigMap = creds.signature().vec()![0]!.map()!;
      expect(sigMap).toHaveLength(1);
      expect(sigMap[0]!.key().vec()![0]!.sym().toString()).toBe("Ed25519");
      expect(sigMap[0]!.val().vec()![0]!.sym().toString()).toBe("Ed25519");
    } finally {
      sim.mockRestore();
    }
  });

  it("refuses to sign an entry whose root is not the transaction's own call", async () => {
    const other = "CBKMUZNFQIAL775XBB2W2GP5CNHBM5YGH6C3XB7AY6SUVO2IBU3VYK2V";
    const sim = vi.spyOn(Server.prototype, "simulateTransaction").mockImplementation((async (tx: { operations: Operation[] }) => {
      const base = await simulationStub()(tx);
      // Root the auth entry at a different contract's call.
      const entry = base.result.auth[0]!;
      const rooted = new xdr.SorobanAuthorizationEntry({
        credentials: entry.credentials(),
        rootInvocation: new xdr.SorobanAuthorizedInvocation({
          function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
            new xdr.InvokeContractArgs({
              contractAddress: Address.fromString(other).toScAddress(),
              functionName: "update_contract_code",
              args: [],
            })
          ),
          subInvocations: [],
        }),
      });
      return { ...base, result: { ...base.result, auth: [rooted] } };
    }) as never);
    try {
      const tx = await buildLegacyUpgradeTx(
        { rpcUrl: RPC_URL, networkPassphrase: Networks.TESTNET, timeoutInSeconds: 30, spec },
        WALLET
      );
      const error = await signLegacyUpgradeTx(
        {
          networkPassphrase: Networks.TESTNET,
          spec,
          signerContext: {} as never,
          calculateExpiration: async () => 150,
          contractId: WALLET,
        },
        tx,
        new Ed25519Signer(Keypair.random())
      ).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(Error);
      expect((error as { code?: number }).code).toBe(PasskeyKitErrorCode.SIGNING_FAILED);
    } finally {
      sim.mockRestore();
    }
  });
});

describe("signLegacyUpgradeTx target pin", () => {
  it("refuses an update_contract_code that carries a different WASM hash", async () => {
    const sim = vi.spyOn(Server.prototype, "simulateTransaction").mockImplementation(simulationStub() as never);
    try {
      const tx = await buildLegacyUpgradeTx(
        { rpcUrl: RPC_URL, networkPassphrase: Networks.TESTNET, timeoutInSeconds: 30, spec },
        WALLET,
        "ee".repeat(32)
      );
      const error = await signLegacyUpgradeTx(
        {
          networkPassphrase: Networks.TESTNET,
          spec,
          signerContext: {} as never,
          calculateExpiration: async () => 150,
          contractId: WALLET,
        },
        tx,
        new Ed25519Signer(Keypair.random())
      ).catch((e: unknown) => e);
      expect((error as { code?: number }).code).toBe(PasskeyKitErrorCode.SIGNING_FAILED);
      expect((error as Error).message).toContain("accepted upgrade target");
    } finally {
      sim.mockRestore();
    }
  });
});

describe("signLegacyUpgradeTx function pin", () => {
  it("refuses a top-level call that is not update_contract_code or migrate_signers", async () => {
    const sim = vi.spyOn(Server.prototype, "simulateTransaction").mockImplementation(simulationStub() as never);
    try {
      // A wallet-admin call built the same way, rooted at this wallet, no subs.
      const { AssembledTransaction } = await import("@stellar/stellar-sdk/contract");
      const tx = await AssembledTransaction.build<null>({
        method: "add_signer",
        args: [xdr.ScVal.scvVoid()],
        contractId: WALLET,
        rpcUrl: RPC_URL,
        networkPassphrase: Networks.TESTNET,
        timeoutInSeconds: 30,
        parseResultXdr: () => null,
      });
      const error = await signLegacyUpgradeTx(
        {
          networkPassphrase: Networks.TESTNET,
          spec,
          signerContext: {} as never,
          calculateExpiration: async () => 150,
          contractId: WALLET,
        },
        tx,
        new Ed25519Signer(Keypair.random())
      ).catch((e: unknown) => e);
      expect((error as { code?: number }).code).toBe(PasskeyKitErrorCode.SIGNING_FAILED);
      expect((error as Error).message).toContain("got add_signer");
    } finally {
      sim.mockRestore();
    }
  });
});
