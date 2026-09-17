/**
 * Legacy (pre-1.0) wallet upgrade helpers.
 *
 * The kit cannot connect to a pre-1.0 wallet (`connectWallet` throws
 * {@link LegacyWalletError}), but it can still craft the one transaction such
 * a wallet needs: an in-place `update_contract_code` to the legacy-line build
 * that reads both pre-1.0 storage layouts, followed for the bare-layout cohort
 * by a `migrate_signers` call. This module builds those transactions from the
 * wallet's actual on-chain state, so an application only has to sign and
 * submit. See docs/legacy-wallet-upgrade.md for the full procedure.
 *
 * @packageDocumentation
 */

import { Address, xdr } from "@stellar/stellar-sdk";
import { AssembledTransaction, type Spec as ContractSpec } from "@stellar/stellar-sdk/contract";
import type { Server } from "@stellar/stellar-sdk/rpc";
import type { Operation } from "@stellar/stellar-sdk";

import {
  KNOWN_VULNERABLE_WALLET_WASM_HASHES,
  LEGACY_UPGRADE_TARGET_WASM_HASH,
  LEGACY_WALLET_UPGRADE_GUIDE_URL,
  LEGACY_WALLET_WASM_HASHES,
} from "../constants.js";
import { PasskeyKitErrorCode, SigningError, ValidationError } from "../errors.js";
import type { SignerKey } from "../types.js";
import type { Signer } from "../signers.js";
import { signerKeyToScVal } from "./auth-payload.js";
import {
  assertAdminRootMatchesHostFunction,
  signAuthEntry,
  type SignAuthEntryDeps,
  type SignOptions,
} from "./tx-ops.js";
import { toContractSignerKey } from "./wallet-ops.js";

/**
 * Pre-1.0 wallets that store signers in the pre-`6a27d48` (2024-12-13)
 * layout. Every later build fails to decode them, which is why only the
 * legacy-line target is a safe upgrade for them and why `migrate_signers`
 * exists.
 */
export const BARE_LAYOUT_WALLET_WASM_HASHES: readonly string[] = [
  "0c0a264d4cc0b3e79b8533e2a2e1f0ed21501a5a3f9f2455d2f18c232940b865",
  "19868df3653d427cafa1c30bdb6cec1ca5c8c815eeabab8a8bae6d83efb1fedd",
];

/** How a wallet's current code relates to this kit. */
export type LegacyCodeStatus =
  /** One of the known-vulnerable pre-fix builds: upgrade or drain now. */
  | "vulnerable"
  /** A patched pre-1.0 build: safe, but only legacy tooling operates it. */
  | "legacy"
  /** One of this kit's accepted hashes: nothing to do. */
  | "current"
  /** Not a hash this kit knows. */
  | "unknown";

/** What {@link inspectLegacyWallet} learned about a wallet. */
export interface LegacyWalletInspection {
  contractId: string;
  /** Current code hash (hex). */
  wasmHash: string;
  status: LegacyCodeStatus;
  /** Storage layout cohort, when the code is a known pre-1.0 build. */
  cohort: "bare" | "wrapped" | null;
  /** The in-place upgrade target for every pre-1.0 wallet. */
  upgradeTarget: string;
  /** True when the wallet should call `update_contract_code(upgradeTarget)`. */
  upgradeRequired: boolean;
  /** True when `migrate_signers` should follow the upgrade (bare cohort). */
  migrateRequired: boolean;
  /**
   * Ledger entries that are archived and must be restored before anything on
   * the wallet can run. `instance` is the wallet instance, `code` its current
   * code, `target` the upgrade target's code.
   */
  archived: { instance: boolean; code: boolean; target: boolean };
  /** Operator guide. */
  guideUrl: string;
  /** One-paragraph instruction for this wallet. */
  recommendation: string;
}

/** Classify a code hash without touching the network. */
export function classifyWasmHash(
  wasmHash: string,
  acceptedWasmHashes: readonly string[]
): { status: LegacyCodeStatus; cohort: "bare" | "wrapped" | null } {
  const hash = wasmHash.toLowerCase();
  if (acceptedWasmHashes.includes(hash)) {
    return { status: "current", cohort: null };
  }
  if (KNOWN_VULNERABLE_WALLET_WASM_HASHES.includes(hash)) {
    return {
      status: "vulnerable",
      cohort: BARE_LAYOUT_WALLET_WASM_HASHES.includes(hash) ? "bare" : "wrapped",
    };
  }
  if (LEGACY_WALLET_WASM_HASHES.includes(hash)) {
    return { status: "legacy", cohort: "wrapped" };
  }
  return { status: "unknown", cohort: null };
}

function instanceLedgerKey(contractId: string): xdr.LedgerKey {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: Address.fromString(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    })
  );
}

function codeLedgerKey(wasmHash: string): xdr.LedgerKey {
  return xdr.LedgerKey.contractCode(
    new xdr.LedgerKeyContractCode({ hash: Buffer.from(wasmHash, "hex") })
  );
}

/** Deps for {@link inspectLegacyWallet}. */
export interface InspectDeps {
  rpc: Server;
  acceptedWasmHashes: readonly string[];
  /** Read the wallet's current code hash (hex). */
  contractWasmHash: (contractId: string) => Promise<string>;
}

/**
 * Read a wallet's code hash and the liveness of the entries an upgrade
 * touches, and say what to do.
 */
export async function inspectLegacyWallet(
  deps: InspectDeps,
  contractId: string
): Promise<LegacyWalletInspection> {
  const wasmHash = (await deps.contractWasmHash(contractId)).toLowerCase();
  const { status, cohort } = classifyWasmHash(wasmHash, deps.acceptedWasmHashes);
  const upgradeTarget = LEGACY_UPGRADE_TARGET_WASM_HASH;

  const keys = [instanceLedgerKey(contractId), codeLedgerKey(wasmHash), codeLedgerKey(upgradeTarget)];
  const response = await deps.rpc.getLedgerEntries(...keys);
  const latest = response.latestLedger;
  const liveByKey = new Map<string, boolean>();
  for (const entry of response.entries) {
    const liveUntil = entry.liveUntilLedgerSeq;
    liveByKey.set(entry.key.toXDR("base64"), liveUntil !== undefined && liveUntil > latest);
  }
  const isLive = (key: xdr.LedgerKey) => liveByKey.get(key.toXDR("base64")) === true;
  const archived = {
    instance: !isLive(keys[0]!),
    code: !isLive(keys[1]!),
    target: !isLive(keys[2]!),
  };

  const upgradeRequired = status === "vulnerable";
  const migrateRequired = cohort === "bare";

  let recommendation: string;
  switch (status) {
    case "vulnerable":
      recommendation =
        `This wallet runs known-vulnerable code ${wasmHash.slice(0, 8)}…; anyone can overwrite ` +
        `its signers. Upgrade it in place now: ` +
        (archived.instance || archived.code || archived.target
          ? `restore the archived entries (${[
              archived.instance && "instance",
              archived.code && "current code",
              archived.target && "target code",
            ]
              .filter(Boolean)
              .join(", ")}), then `
          : "") +
        `call update_contract_code(${upgradeTarget.slice(0, 8)}…) authorized by an existing signer` +
        (migrateRequired
          ? `, then call migrate_signers with every signer key (this wallet stores the pre-6a27d48 layout)`
          : "") +
        `. Or move its funds out. Guide: ${LEGACY_WALLET_UPGRADE_GUIDE_URL}`;
      break;
    case "legacy":
      recommendation =
        `This wallet runs patched pre-1.0 code ${wasmHash.slice(0, 8)}…. It is not vulnerable; ` +
        `operate it with the passkey-kit 0.10.20–0.12.x line. Guide: ${LEGACY_WALLET_UPGRADE_GUIDE_URL}`;
      break;
    case "current":
      recommendation = "This wallet runs accepted current code. No upgrade is needed.";
      break;
    default:
      recommendation =
        `This wallet runs code ${wasmHash.slice(0, 8)}… that this kit does not recognize. ` +
        `Verify its provenance before acting.`;
  }

  return {
    contractId,
    wasmHash,
    status,
    cohort,
    upgradeTarget,
    upgradeRequired,
    migrateRequired,
    archived,
    guideUrl: LEGACY_WALLET_UPGRADE_GUIDE_URL,
    recommendation,
  };
}

/** Deps for the transaction builders. */
export interface LegacyTxDeps {
  rpcUrl: string;
  networkPassphrase: string;
  timeoutInSeconds: number;
  /** The wallet contract spec, used to encode `SignerKey` arguments. */
  spec: ContractSpec;
}

/**
 * Build `wallet.update_contract_code(target)` for a legacy wallet.
 *
 * The transaction's single auth entry is the wallet's own, to be signed by an
 * existing signer through {@link signLegacyUpgradeTx}. The envelope source is
 * the SDK's placeholder account, so submit through `PasskeyServer.send` (a
 * relayer supplies the source and fees) or rebuild with your own funded source.
 */
export function buildLegacyUpgradeTx(
  deps: LegacyTxDeps,
  contractId: string,
  target: string = LEGACY_UPGRADE_TARGET_WASM_HASH
): Promise<AssembledTransaction<null>> {
  if (!/^[0-9a-f]{64}$/i.test(target)) {
    throw new ValidationError(
      "upgrade target must be a 32-byte hex WASM hash",
      PasskeyKitErrorCode.INVALID_INPUT,
      { target }
    );
  }
  return AssembledTransaction.build<null>({
    method: "update_contract_code",
    args: [xdr.ScVal.scvBytes(Buffer.from(target, "hex"))],
    contractId,
    rpcUrl: deps.rpcUrl,
    networkPassphrase: deps.networkPassphrase,
    timeoutInSeconds: deps.timeoutInSeconds,
    parseResultXdr: () => null,
  });
}

/**
 * Build `wallet.migrate_signers(keys)` for a wallet already on the legacy-line
 * target. The call needs no wallet authorization (it is a value-preserving
 * re-encoding), so any funded source can submit it. Returns the number of
 * entries rewritten when simulated or executed.
 *
 * Soroban has no storage iteration, so the caller supplies the keys: the
 * hosted passkey indexer (`MercuryIndexer.getSigners` /
 * `PasskeyServer.getSigners`) lists every signer a wallet has ever held.
 */
export function buildLegacyMigrateTx(
  deps: LegacyTxDeps,
  contractId: string,
  signerKeys: readonly SignerKey[]
): Promise<AssembledTransaction<number>> {
  if (signerKeys.length === 0) {
    throw new ValidationError(
      "migrate_signers needs at least one signer key",
      PasskeyKitErrorCode.INVALID_INPUT,
      { contractId }
    );
  }
  const keys = signerKeys.map((key) =>
    signerKeyToScVal(deps.spec, toContractSignerKey(key))
  );
  return AssembledTransaction.build<number>({
    method: "migrate_signers",
    args: [xdr.ScVal.scvVec(keys)],
    contractId,
    rpcUrl: deps.rpcUrl,
    networkPassphrase: deps.networkPassphrase,
    timeoutInSeconds: deps.timeoutInSeconds,
    parseResultXdr: (value) => value.u32(),
  });
}

/**
 * Sign a legacy wallet's `update_contract_code` auth entry with one of its
 * existing signers, without a connected wallet.
 *
 * Passkey and Ed25519 signature entries encode identically on every pre-1.0
 * build, and the signature covers the V2 address-bound payload the host
 * presents to any custom account, so the kit's normal signers work here. The
 * entry root is pinned to the transaction's own host function, as for every
 * wallet-admin write.
 */
export async function signLegacyUpgradeTx<T>(
  deps: SignAuthEntryDeps & { contractId: string },
  tx: AssembledTransaction<T>,
  signer: Signer,
  options?: Omit<SignOptions, "allowWalletReentry">
): Promise<AssembledTransaction<T>> {
  const built = (tx as { built?: AssembledTransaction<T>["built"] }).built;
  const topOp = built?.operations[0];
  const topFunc =
    topOp?.type === "invokeHostFunction"
      ? (topOp as Operation.InvokeHostFunction).func
      : undefined;
  if (!topFunc) {
    throw new ValidationError(
      "the transaction has no invoke-host-function operation to sign",
      PasskeyKitErrorCode.INVALID_INPUT,
      { contractId: deps.contractId }
    );
  }

  // Resolve the expiration once here (the kit's own ledger-based default) so
  // the SDK does not fetch it, and pass the same value to every entry.
  const expiration = options?.expiration ?? (await deps.calculateExpiration());

  await tx.signAuthEntries({
    address: deps.contractId,
    expiration,
    authorizeEntry: async (entry) => {
      const clone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
      assertRootIsExactlyThisCall(clone, deps.contractId, topFunc);
      assertAdminRootMatchesHostFunction(clone, deps.contractId, topFunc);
      return signAuthEntry(deps, clone, signer, {
        ...options,
        expiration,
        allowWalletReentry: true,
      });
    },
  });

  return tx;
}

/**
 * The legacy upgrade signs exactly one thing: this wallet's own
 * `update_contract_code` (or `migrate_signers`) as the transaction's
 * top-level call, with no sub-invocations. Anything else is refused before
 * hashing, so a hostile transaction cannot borrow this signing path.
 */
function assertRootIsExactlyThisCall(
  entry: xdr.SorobanAuthorizationEntry,
  contractId: string,
  topFunc: xdr.HostFunction
): void {
  const root = entry.rootInvocation();
  const fn = root.function();
  const expected = topFunc.switch().name === "hostFunctionTypeInvokeContract"
    ? topFunc.invokeContract()
    : undefined;
  const actual =
    fn.switch().name === "sorobanAuthorizedFunctionTypeContractFn" ? fn.contractFn() : undefined;
  const ok =
    expected !== undefined &&
    actual !== undefined &&
    root.subInvocations().length === 0 &&
    Address.fromScAddress(actual.contractAddress()).toString() === contractId &&
    actual.toXDR("base64") === expected.toXDR("base64");
  if (!ok) {
    throw new SigningError(
      `Refusing to sign: the auth entry must root at ${contractId}'s own top-level ` +
        `update_contract_code / migrate_signers call with no sub-invocations`,
      PasskeyKitErrorCode.SIGNING_FAILED,
      { contractId }
    );
  }
}
