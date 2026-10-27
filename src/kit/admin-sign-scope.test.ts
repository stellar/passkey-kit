/**
 * Authorization scope of the wallet-admin signing path.
 *
 * A Soroban signature covers the whole authorization tree, and the SDK signs
 * every auth entry whose credential address is the connected wallet. The auth
 * trees come from RPC simulation, so the admin path must sign exactly the one
 * wallet-admin call the caller built — the transaction's own top-level host
 * function, with no sub-invocations — and refuse anything else a simulation
 * response adds. These tests drive the real `SignerManager.signAdmin` / `sign`
 * / `signAuthEntry` and `signLegacyUpgradeTx` over real `AssembledTransaction`s
 * from the real builders, with only RPC simulation stubbed.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  Address,
  Keypair,
  Networks,
  Operation,
  SorobanDataBuilder,
  StrKey,
  hash,
  nativeToScVal,
  xdr,
} from "@stellar/stellar-sdk";
import { Server } from "@stellar/stellar-sdk/rpc";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import { Client as PasskeyClient } from "passkey-kit-sdk";

import { SignerManager } from "../managers/signer-manager.js";
import { Ed25519Signer, type Signer } from "../signers.js";
import { SignerStore } from "../types.js";
import { buildEd25519SignerTx } from "./wallet-ops.js";
import { buildLegacyUpgradeTx, signLegacyUpgradeTx } from "./legacy-ops.js";

const NET = Networks.TESTNET;
const RPC_URL = "https://rpc.example";
const cid = (tag: string) => StrKey.encodeContract(hash(Buffer.from(tag)));
const WALLET = cid("wallet");
const TOKEN = cid("token");
const EVIL = cid("evil");
const LEGACY = cid("legacy");
const LEGIT = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1)).publicKey();
const OTHER = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2)).publicKey();
const EXPIRATION = 5000;

const client = new PasskeyClient({ contractId: WALLET, rpcUrl: RPC_URL, networkPassphrase: NET });
const spec = (client as unknown as { spec: import("@stellar/stellar-sdk/contract").Spec }).spec;

// --- tree + signature helpers ----------------------------------------------

function label(inv: xdr.SorobanAuthorizedInvocation): string {
  const fn = inv.function();
  const kind = fn.switch().name;
  if (kind !== "sorobanAuthorizedFunctionTypeContractFn")
    return kind.replace("sorobanAuthorizedFunctionType", "");
  const a = fn.contractFn();
  const c = Address.fromScAddress(a.contractAddress()).toString();
  const name = { [WALLET]: "WALLET", [TOKEN]: "TOKEN", [EVIL]: "EVIL" }[c] ?? c;
  return `${name}.${a.functionName().toString()}`;
}

function tree(entry: xdr.SorobanAuthorizationEntry): string[] {
  const out: string[] = [];
  const walk = (inv: xdr.SorobanAuthorizedInvocation, depth: number) => {
    out.push(`${"  ".repeat(depth)}${label(inv)}`);
    for (const s of inv.subInvocations()) walk(s, depth + 1);
  };
  walk(entry.rootInvocation(), 0);
  return out;
}

function isSigned(entry: xdr.SorobanAuthorizationEntry): boolean {
  const kind = entry.credentials().switch().name;
  if (kind === "sorobanCredentialsAddressV2")
    return entry.credentials().addressV2().signature().switch().name === "scvVec";
  if (kind === "sorobanCredentialsAddress")
    return entry.credentials().address().signature().switch().name === "scvVec";
  return false;
}

// --- invocation / entry builders -------------------------------------------

function inv(contract: string, fn: string, subs: xdr.SorobanAuthorizedInvocation[] = []) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: Address.fromString(contract).toScAddress(),
        functionName: fn,
        args: [],
      })
    ),
    subInvocations: subs,
  });
}

function invFromArgs(args: xdr.InvokeContractArgs, subs: xdr.SorobanAuthorizedInvocation[] = []) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      xdr.InvokeContractArgs.fromXDR(args.toXDR())
    ),
    subInvocations: subs,
  });
}

function transfer(to: string, amount = 1_000_000_000n) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: Address.fromString(TOKEN).toScAddress(),
        functionName: "transfer",
        args: [
          nativeToScVal(Address.fromString(WALLET), { type: "address" }),
          nativeToScVal(Address.fromString(to), { type: "address" }),
          nativeToScVal(amount, { type: "i128" }),
        ],
      })
    ),
    subInvocations: [],
  });
}

function createContractNode() {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractV2HostFn(
      new xdr.CreateContractArgsV2({
        executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32, 9)),
        contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
          new xdr.ContractIdPreimageFromAddress({
            address: Address.fromString(WALLET).toScAddress(),
            salt: hash(Buffer.from("salt")),
          })
        ),
        constructorArgs: [],
      })
    ),
    subInvocations: [],
  });
}

function entry(root: xdr.SorobanAuthorizedInvocation, nonce = "7") {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(WALLET).toScAddress(),
        nonce: xdr.Int64.fromString(nonce),
        signatureExpirationLedger: 0,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation: root,
  });
}

/** A wallet-credentialed entry for an arbitrary wallet address and expiration. */
function entryForWallet(
  walletAddr: string,
  root: xdr.SorobanAuthorizedInvocation,
  nonce = "7",
  expirationLedger = 0
) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(walletAddr).toScAddress(),
        nonce: xdr.Int64.fromString(nonce),
        signatureExpirationLedger: expirationLedger,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation: root,
  });
}

/** Read the signature-expiration ledger off a V1 or V2 address credential. */
function expirationOf(entry: xdr.SorobanAuthorizationEntry): number {
  const kind = entry.credentials().switch().name;
  if (kind === "sorobanCredentialsAddressV2")
    return entry.credentials().addressV2().signatureExpirationLedger();
  if (kind === "sorobanCredentialsAddress")
    return entry.credentials().address().signatureExpirationLedger();
  return 0;
}

// --- simulation stub + kit wiring ------------------------------------------

function stubSimulation(authFor: (top: xdr.InvokeContractArgs) => xdr.SorobanAuthorizationEntry[]) {
  vi.spyOn(Server.prototype, "getLatestLedger").mockResolvedValue({ sequence: 1000 } as never);
  return vi.spyOn(Server.prototype, "simulateTransaction").mockImplementation((async (tx: {
    operations: Operation[];
  }) => {
    const top = (tx.operations[0] as Operation.InvokeHostFunction).func.invokeContract();
    return {
      id: "1",
      latestLedger: 1000,
      minResourceFee: "100",
      transactionData: new SorobanDataBuilder(),
      events: [],
      result: { auth: authFor(top), retval: xdr.ScVal.scvVoid() },
      _parsed: true,
    };
  }) as never);
}

const honest = (top: xdr.InvokeContractArgs) => [entry(invFromArgs(top))];

function manager() {
  return new SignerManager({
    networkPassphrase: NET,
    timeoutInSeconds: 30,
    rpc: new Server(RPC_URL),
    getWallet: () => client,
    getContractId: () => WALLET,
    getSignerContext: () => ({ webAuthn: { startAuthentication: vi.fn() } as never }),
    calculateExpiration: async () => EXPIRATION,
  });
}

function recordingSigner(): Signer {
  const inner = new Ed25519Signer(Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7)));
  return { sign: (payload, ctx) => inner.sign(payload, ctx) };
}

/** Real `add_signer(pk)` args, produced by the real builder. */
async function addSignerArgsFor(pk: string): Promise<xdr.InvokeContractArgs> {
  stubSimulation(honest);
  const tx = await buildEd25519SignerTx(
    { wallet: client, timeoutInSeconds: 30 },
    "add_signer",
    pk,
    undefined,
    SignerStore.Persistent
  );
  vi.restoreAllMocks();
  return (tx.built!.operations[0] as Operation.InvokeHostFunction).func.invokeContract();
}

/** The real dedicated builder `addEd25519(LEGIT)`, with the given simulated auth. */
async function adminTx(authFor: (top: xdr.InvokeContractArgs) => xdr.SorobanAuthorizationEntry[]) {
  stubSimulation(authFor);
  return manager().addEd25519(LEGIT, undefined, SignerStore.Persistent);
}

function authOf<T>(tx: AssembledTransaction<T>): xdr.SorobanAuthorizationEntry[] {
  return (tx.built!.operations[0] as Operation.InvokeHostFunction).auth ?? [];
}

afterEach(() => vi.restoreAllMocks());

// ---------------------------------------------------------------------------

describe("wallet-admin signing scope", () => {
  it("signs exactly the one admin entry the transaction invokes", async () => {
    const tx = await adminTx(honest);
    await manager().signAdmin(tx, recordingSigner());
    const auth = authOf(tx);
    expect(auth).toHaveLength(1);
    expect(isSigned(auth[0]!)).toBe(true);
    expect(tree(auth[0]!)).toEqual(["WALLET.add_signer"]);
  });

  it("refuses a sub-invocation grafted under the admin root", async () => {
    const otherArgs = await addSignerArgsFor(OTHER);
    const tx = await adminTx((top) => [
      entry(invFromArgs(top, [invFromArgs(otherArgs), transfer(OTHER)])),
    ]);
    await expect(manager().signAdmin(tx, recordingSigner())).rejects.toThrow();
    expect(authOf(tx).some(isSigned)).toBe(false);
  });

  it("refuses a detached second wallet entry rooted at a token transfer", async () => {
    const tx = await adminTx((top) => [entry(invFromArgs(top)), entry(transfer(OTHER), "8")]);
    await expect(manager().signAdmin(tx, recordingSigner())).rejects.toThrow();
    // Nothing is signed: the wallet-entry count is checked before signing, so
    // the admin entry gets no leftover signature before the transfer is
    // refused — not just the transfer entry stays unsigned.
    expect(authOf(tx).some(isSigned)).toBe(false);
  });

  it("refuses a second wallet entry whose root is a third-party call carrying add_signer", async () => {
    const otherArgs = await addSignerArgsFor(OTHER);
    const tx = await adminTx((top) => [
      entry(invFromArgs(top)),
      entry(inv(EVIL, "claim", [invFromArgs(otherArgs)]), "8"),
    ]);
    await expect(manager().signAdmin(tx, recordingSigner())).rejects.toThrow();
  });

  it("refuses contract-deploy authority on the admin path (as a child and as a second entry)", async () => {
    const asChild = await adminTx((top) => [entry(invFromArgs(top, [createContractNode()]))]);
    await expect(manager().signAdmin(asChild, recordingSigner())).rejects.toThrow();

    const asEntry = await adminTx((top) => [entry(invFromArgs(top)), entry(createContractNode(), "8")]);
    await expect(manager().signAdmin(asEntry, recordingSigner())).rejects.toThrow();
  });

  it("still refuses a wallet-admin root on the generic sign() path", async () => {
    const otherArgs = await addSignerArgsFor(OTHER);
    const tx = await adminTx(() => [entry(invFromArgs(otherArgs))]);
    await expect(manager().sign(tx, recordingSigner())).rejects.toThrow();
  });

  it("still refuses a wallet-admin root on the standalone signAuthEntry() path", async () => {
    const otherArgs = await addSignerArgsFor(OTHER);
    await expect(
      manager().signAuthEntry(entry(invFromArgs(otherArgs)), recordingSigner())
    ).rejects.toThrow();
  });

  // The signature is placed over exactly ONE wallet authorization. A hostile
  // simulation that returns a second copy of the admin root (a later-replayable
  // duplicate under a fresh nonce), or no wallet entry at all, is refused
  // before anything is signed.
  it("refuses two duplicate admin roots with distinct nonces, signing neither", async () => {
    const tx = await adminTx((top) => [entry(invFromArgs(top)), entry(invFromArgs(top), "8")]);
    await expect(manager().signAdmin(tx, recordingSigner())).rejects.toThrow();
    expect(authOf(tx).some(isSigned)).toBe(false);
  });

  it("refuses a simulation that returns no wallet entry on the admin path", async () => {
    const tx = await adminTx(() => []);
    await expect(manager().signAdmin(tx, recordingSigner())).rejects.toThrow();
  });

  // `adminEntry` is an internal flag. A caller must not be able to smuggle it
  // through the public options bag to turn off the standalone refusal, nor to
  // force a wallet-admin root through generic sign().
  it("closes the adminEntry bypass through public signAuthEntry()", async () => {
    const otherArgs = await addSignerArgsFor(OTHER);
    await expect(
      manager().signAuthEntry(entry(invFromArgs(otherArgs)), recordingSigner(), {
        adminEntry: true,
      } as never)
    ).rejects.toThrow();
  });

  it("closes the adminEntry switch through public sign()", async () => {
    const otherArgs = await addSignerArgsFor(OTHER);
    const tx = await adminTx(() => [entry(invFromArgs(otherArgs))]);
    await expect(
      manager().sign(tx, recordingSigner(), { adminEntry: true } as never)
    ).rejects.toThrow();
  });

  // A legacy (pre-1.0) wallet administers itself through `update_contract_code`.
  // The standalone path must refuse it exactly like the current admin names,
  // for the cohort whose key also signs for a legacy sibling.
  it("refuses a legacy wallet's update_contract_code on the standalone path", async () => {
    const root = entryForWallet(LEGACY, inv(LEGACY, "update_contract_code"));
    await expect(manager().signAuthEntry(root, recordingSigner())).rejects.toThrow();

    const nested = entryForWallet(
      LEGACY,
      inv(EVIL, "claim", [inv(LEGACY, "update_contract_code")])
    );
    await expect(manager().signAuthEntry(nested, recordingSigner())).rejects.toThrow();
  });

  // The admin signature's lifetime comes from the kit, never from the
  // simulation-supplied entry: a hostile RPC must not choose how long a dropped
  // admin signature stays replayable.
  it("resolves the admin signature lifetime from the kit, ignoring the simulated ledger", async () => {
    const tx = await adminTx((top) => [entryForWallet(WALLET, invFromArgs(top), "7", 0xffffffff)]);
    await manager().signAdmin(tx, recordingSigner());
    const auth = authOf(tx);
    expect(auth).toHaveLength(1);
    expect(isSigned(auth[0]!)).toBe(true);
    expect(expirationOf(auth[0]!)).toBe(EXPIRATION);
  });
});

describe("legacy upgrade signing scope", () => {
  const deps = () => ({
    networkPassphrase: NET,
    spec,
    signerContext: {} as never,
    calculateExpiration: async () => EXPIRATION,
    contractId: WALLET,
  });

  async function legacyTx() {
    return buildLegacyUpgradeTx({ rpcUrl: RPC_URL, networkPassphrase: NET, timeoutInSeconds: 30, spec }, WALLET);
  }

  it("signs the honest legacy upgrade", async () => {
    stubSimulation(honest);
    const tx = await legacyTx();
    await signLegacyUpgradeTx(deps(), tx, recordingSigner());
    expect(authOf(tx).every(isSigned)).toBe(true);
  });

  it("refuses grafted children and detached second entries", async () => {
    const otherArgs = await addSignerArgsFor(OTHER);
    const shapes: ((top: xdr.InvokeContractArgs) => xdr.SorobanAuthorizationEntry[])[] = [
      (top) => [entry(invFromArgs(top, [invFromArgs(otherArgs), transfer(OTHER)]))],
      (top) => [entry(invFromArgs(top)), entry(transfer(OTHER), "8")],
      (top) => [entry(invFromArgs(top)), entry(createContractNode(), "8")],
    ];
    for (const authFor of shapes) {
      stubSimulation(authFor);
      const tx = await legacyTx();
      await expect(signLegacyUpgradeTx(deps(), tx, recordingSigner())).rejects.toThrow();
      vi.restoreAllMocks();
    }
  });

  it("refuses two duplicate upgrade roots with distinct nonces, signing neither", async () => {
    stubSimulation((top) => [entry(invFromArgs(top)), entry(invFromArgs(top), "8")]);
    const tx = await legacyTx();
    await expect(signLegacyUpgradeTx(deps(), tx, recordingSigner())).rejects.toThrow();
    expect(authOf(tx).some(isSigned)).toBe(false);
  });
});
