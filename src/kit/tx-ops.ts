/**
 * Transaction-signing operations: the auth-entry signing pipeline and the
 * `AssembledTransaction` signing entrypoint.
 *
 * Two deliberate changes from the old kit:
 * - `sign` takes a single explicit `AssembledTransaction<T>` instead of the
 *   lossy `AssembledTransaction | Tx | string` tri-input that silently dropped
 *   memo/fee/operations on its fallback path (#599 §6). Callers holding XDR use
 *   `AssembledTransaction.fromXDR` first.
 * - The `Signatures` map is sorted with the host-order `compareScVal`, not the
 *   old `localeCompare` string approximation.
 * - Signing is address-bound only: V1 address credentials are upgraded to
 *   CAP-0071-02 V2 before the payload is hashed (`toAddressBoundCredentials`),
 *   and there is no V1 signing path.
 *
 * @packageDocumentation
 */

import { Address, Operation, TransactionBuilder, xdr } from "@stellar/stellar-sdk";
import type { Keypair } from "@stellar/stellar-sdk";
import type { Server } from "@stellar/stellar-sdk/rpc";
import type {
  AssembledTransaction,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import type { Signer, SignerContext } from "../signers.js";
import {
  buildSignaturePayload,
  getAddressCredentials,
  signatureToScVal,
  signerKeyToScVal,
  toAddressBoundCredentials,
  upsertSignatureEntry,
  usesAddressBoundPayload,
} from "./auth-payload.js";
import { SigningError, PasskeyKitError, PasskeyKitErrorCode } from "../errors.js";
import { isDefaultDeployer } from "../utils.js";

/** Deps for computing a default signature-expiration ledger. */
export interface ExpirationDeps {
  rpc: Server;
  timeoutInSeconds: number;
}

/**
 * Compute a default signature-expiration ledger: the latest ledger plus the
 * timeout window (assuming ~5s ledgers), rounded up.
 */
export async function calculateExpiration(deps: ExpirationDeps): Promise<number> {
  const { sequence } = await deps.rpc.getLatestLedger();
  return Math.ceil(sequence + deps.timeoutInSeconds / 5);
}

/** Deps for signing a single auth entry. */
export interface SignAuthEntryDeps {
  networkPassphrase: string;
  spec: ContractSpec;
  signerContext: SignerContext;
  calculateExpiration: () => Promise<number>;
  /** Connected wallet contract id. Required to refuse nested wallet-admin calls. */
  contractId?: string;
}

/** Per-call signing options. */
export interface SignOptions {
  /** Signature expiration ledger (defaults to the configured window). */
  expiration?: number;
  /**
   * Allow this entry to authorize nested calls back into the connected wallet
   * (e.g. `add_signer`, `update_signer`, `remove_signer`, `upgrade`,
   * `add_secp256r1`). Default `false`. Wallet-admin writes must use the
   * dedicated builders (`addEd25519`, `addSecp256r1`, `addPolicy`, `remove`,
   * `upgrade`), never a generic dApp `sign()` call.
   */
  allowWalletReentry?: boolean;
}

/**
 * Function names that administer the wallet itself. A nested call into the
 * connected wallet carrying one of these names changes who can authorize on
 * behalf of the wallet, so it must never ride inside a generic dApp signature.
 */
const WALLET_ADMIN_FUNCTIONS = new Set([
  "add_signer",
  "add_secp256r1",
  "update_signer",
  "remove_signer",
  "upgrade",
]);

/** Describe one authorized invocation as `CONTRACT.fn` for error context. */
function describeWalletInvocation(inv: xdr.SorobanAuthorizedInvocation): string {
  const fn = inv.function();
  if (fn.switch().name !== "sorobanAuthorizedFunctionTypeContractFn") {
    return fn.switch().name;
  }
  const args = fn.contractFn();
  return `${Address.fromScAddress(args.contractAddress()).toString()}.${args.functionName().toString()}`;
}

/**
 * Refuse any wallet-admin use covered by this signature — the entry root
 * itself or any nested sub-invocation. A signature covers the whole
 * authorization tree, so both shapes are the same grant:
 *
 * - Shape A (graft): dApp root (e.g. `evil.claim`) with a nested
 *   `wallet.add_signer(attacker)` sub-invocation.
 * - Shape B (hostile root): the transaction's top-level call IS
 *   `wallet.add_signer(attacker)` (or `add_secp256r1` / `update_signer` /
 *   `remove_signer` / `upgrade`), built by a hostile dApp and handed to
 *   generic `sign()`. The auth-entry root is the admin call itself, so a
 *   sub-invocation-only check signs it clean.
 *
 * Legit wallet-admin writes build the admin call as the transaction's own
 * host function through the dedicated builders (`addEd25519`,
 * `addSecp256r1`, `addPolicy`, `remove`, `upgrade`). They pass
 * `allowWalletReentry: true` at sign time to declare that intent. A generic
 * dApp `sign()` call must never carry wallet-admin authority, root or nested.
 *
 * @throws {SigningError} If wallet-admin authority is found and not allowed.
 */
export function assertNoWalletAdminReentry(
  entry: xdr.SorobanAuthorizationEntry,
  contractId: string | undefined,
  allowWalletReentry: boolean
): void {
  if (allowWalletReentry) {
    return;
  }
  // The credential address is authoritative for which wallet this signature
  // speaks for; `contractId` is the connected wallet. Check the entry against
  // both so a multi-wallet signer cannot be confused into signing wallet B's
  // admin call while connected to wallet A (or vice versa).
  const walletIds = new Set<string>();
  try {
    const credAddr = Address.fromScAddress(
      getAddressCredentials(entry.credentials()).address()
    ).toString();
    walletIds.add(credAddr);
  } catch {
    // Non-address credentials are rejected by the caller before this runs.
  }
  if (contractId) {
    walletIds.add(contractId);
  }
  const walk = (inv: xdr.SorobanAuthorizedInvocation): void => {
    const fn = inv.function();
    const switchName = fn.switch().name;
    // Wallet credentials must never authorize deploys on the generic path:
    // deploys use the dedicated `signDeploy` flow, and an unlimited signer
    // authorizes `CreateContract*` contexts on-chain.
    if (
      switchName === "sorobanAuthorizedFunctionTypeCreateContractV2HostFn" ||
      switchName === "sorobanAuthorizedFunctionTypeCreateContractHostFn"
    ) {
      throw new SigningError(
        `Refusing to sign contract-deploy authority on the generic sign() path. Deploys must use the dedicated deploy flow.`,
        PasskeyKitErrorCode.SIGNING_FAILED,
        { contractId }
      );
    }
    if (switchName === "sorobanAuthorizedFunctionTypeContractFn") {
      const args = fn.contractFn();
      const target = Address.fromScAddress(args.contractAddress()).toString();
      const name = args.functionName().toString();
      if (walletIds.has(target) && WALLET_ADMIN_FUNCTIONS.has(name)) {
        throw new SigningError(
          `Refusing to sign wallet-admin call on the generic sign() path: ${describeWalletInvocation(inv)}. Wallet-admin writes must use the dedicated builders with allowWalletReentry: true, never a generic dApp sign() call.`,
          PasskeyKitErrorCode.SIGNING_FAILED,
          { contractId: target, function: name }
        );
      }
    }
    for (const sub of inv.subInvocations()) {
      walk(sub);
    }
  };
  // Walk the ROOT as well as every sub-invocation: Shape B roots the entry
  // at the admin call itself.
  walk(entry.rootInvocation());
}

/**
 * Sign a single Soroban authorization entry with a {@link Signer}, merging the
 * resulting `(SignerKey, Signature)` pair into the entry's flat `Signatures`
 * map (host-ordered).
 *
 * Mutates and returns the passed entry.
 */
export async function signAuthEntry(
  deps: SignAuthEntryDeps,
  entry: xdr.SorobanAuthorizationEntry,
  signer: Signer,
  options?: SignOptions
): Promise<xdr.SorobanAuthorizationEntry> {
  if (
    entry.credentials().switch().name === "sorobanCredentialsAddressWithDelegates"
  ) {
    throw new SigningError(
      "ADDRESS_WITH_DELEGATES auth entries are not supported by passkey signing",
      PasskeyKitErrorCode.UNSUPPORTED_CREDENTIALS
    );
  }

  // Address-bound credentials only (CAP-0071-02): a legacy V1 address entry is
  // upgraded to V2 before anything is hashed, so the wallet address is bound
  // into the signed preimage. There is deliberately NO V1 signing path — a V1
  // payload hash is identical across wallets for an address-free invocation,
  // so it does not bind the signature to this wallet.
  entry.credentials(toAddressBoundCredentials(entry.credentials()));
  if (!usesAddressBoundPayload(entry.credentials())) {
    throw new SigningError(
      `Refusing to sign a non-address-bound auth entry: ${entry.credentials().switch().name}`,
      PasskeyKitErrorCode.UNSUPPORTED_CREDENTIALS
    );
  }

  const credentials = getAddressCredentials(entry.credentials());

  // A signature covers the whole authorization tree, not just the root. Refuse
  // wallet-admin authority on the generic signing path before anything is
  // hashed: a hostile contract grafts `add_signer(attacker)` beneath an honest
  // root (Shape A) or roots the entry at the admin call itself (Shape B), and
  // one tap would otherwise install a permanent attacker signer.
  assertNoWalletAdminReentry(entry, deps.contractId, options?.allowWalletReentry ?? false);

  // `== null`, not `!expiration`: an explicit `expiration: 0` is a caller-chosen
  // value, not "unset" — only undefined/null falls through to the entry's
  // existing ledger or a freshly computed default.
  let expiration = options?.expiration;
  if (expiration == null) {
    expiration = credentials.signatureExpirationLedger();
    if (!expiration) {
      expiration = await deps.calculateExpiration();
    }
  }

  // Sets credentials.signatureExpirationLedger(expiration) as a side effect.
  const payload = buildSignaturePayload(deps.networkPassphrase, entry, expiration);

  const prepared = await signer.sign(payload, deps.signerContext);
  const scKey = signerKeyToScVal(deps.spec, prepared.key);
  const scVal = signatureToScVal(deps.spec, prepared.value);
  upsertSignatureEntry(credentials, scKey, scVal);

  return entry;
}

/** Deps for signing an assembled transaction's auth entries. */
export interface SignTxDeps extends SignAuthEntryDeps {
  getContractId: () => string | undefined;
}

/**
 * Pin each wallet-admin entry root to the transaction's own top-level host
 * function. The dedicated builders produce exactly this shape: the transaction
 * invokes `wallet.<admin-fn>` and the single auth entry roots at that same
 * call. A hostile dApp handing over a pre-built admin transaction cannot forge
 * the caller's envelope, so a mismatch is refused even when the caller opted
 * into `allowWalletReentry` (making `signAdmin` self-validating instead of a
 * full bypass on misuse).
 *
 * Non-admin roots (dApp calls such as token transfers) pass through: the
 * per-entry tree check already refused nested wallet-admin authority.
 *
 * @throws {SigningError} If a wallet-admin root does not match the top-level call.
 */
export function assertAdminRootMatchesHostFunction(
  entry: xdr.SorobanAuthorizationEntry,
  contractId: string,
  hostFunc: xdr.HostFunction
): void {
  const rootFn = entry.rootInvocation().function();
  if (rootFn.switch().name !== "sorobanAuthorizedFunctionTypeContractFn") {
    return;
  }
  const args = rootFn.contractFn();
  const target = Address.fromScAddress(args.contractAddress()).toString();
  const name = args.functionName().toString();
  const isWalletAdmin = target === contractId && WALLET_ADMIN_FUNCTIONS.has(name);
  if (!isWalletAdmin) {
    return;
  }
  if (hostFunc.switch().name !== "hostFunctionTypeInvokeContract") {
    throw new SigningError(
      `Refusing wallet-admin entry whose transaction is not an invokeContract call: ${describeWalletInvocation(entry.rootInvocation())}.`,
      PasskeyKitErrorCode.SIGNING_FAILED,
      { contractId, function: name }
    );
  }
  const invoke = hostFunc.invokeContract();
  if (
    Address.fromScAddress(invoke.contractAddress()).toString() !== target ||
    invoke.functionName().toString() !== name ||
    !Buffer.from(args.toXDR()).equals(Buffer.from(invoke.toXDR()))
  ) {
    throw new SigningError(
      `Refusing wallet-admin entry that does not match the transaction's top-level call: ${describeWalletInvocation(entry.rootInvocation())}. Sign wallet-admin transactions only through the dedicated builders.`,
      PasskeyKitErrorCode.SIGNING_FAILED,
      { contractId, function: name }
    );
  }
}

/**
 * Sign every auth entry of an {@link AssembledTransaction} that is authorized by
 * the connected wallet, using `signer`. Returns the same transaction with its
 * auth entries signed.
 *
 * Generic dApp `sign()` calls must never carry wallet-admin authority. Standalone
 * `signAuthEntry()` has no transaction context, so a wallet-admin entry root is
 * necessarily hostile there (dedicated builders are the only legit producers of
 * admin roots, and they sign through this path with `allowWalletReentry: true`).
 * This function additionally pins each wallet-admin entry root to the
 * transaction's own top-level host function: the dedicated builders produce
 * exactly that shape, while a hostile dApp handing over a pre-built admin
 * transaction cannot forge the transaction envelope the caller already holds.
 *
 * @throws {SigningError} If no wallet is connected.
 */
export async function sign<T>(
  deps: SignTxDeps,
  txn: AssembledTransaction<T>,
  signer: Signer,
  options?: SignOptions
): Promise<AssembledTransaction<T>> {
  const contractId = deps.getContractId();
  if (!contractId) {
    throw new SigningError(
      "A wallet must be connected to sign a transaction",
      PasskeyKitErrorCode.SIGNING_FAILED
    );
  }

  const allowWalletReentry = options?.allowWalletReentry ?? false;
  // The wallet-admin pin needs the transaction's own top-level host function.
  // `signAuthEntries` only hands each entry to the callback, so read the
  // envelope here where the full transaction is in hand; entries are matched
  // back to it per-entry below. A missing envelope is left for the SDK's own
  // "not simulated" error inside `signAuthEntries`.
  const built = (txn as { built?: AssembledTransaction<T>["built"] }).built;
  const topOp = built?.operations[0];
  const topFunc =
    topOp?.type === "invokeHostFunction"
      ? (topOp as Operation.InvokeHostFunction).func
      : undefined;

  await txn.signAuthEntries({
    address: contractId,
    authorizeEntry: async (entry) => {
      const clone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
      if (allowWalletReentry && topFunc) {
        assertAdminRootMatchesHostFunction(clone, contractId, topFunc);
      }
      return signAuthEntry(deps, clone, signer, options);
    },
  });

  return txn;
}

/**
 * The `restorePreamble` shape Soroban simulation returns when a transaction
 * touches archived entries (a subset of the SDK's `SimulateTransactionResponse`).
 */
export interface RestorePreamble {
  minResourceFee: string;
  transactionData: { build(): xdr.SorobanTransactionData };
}

/**
 * Restore an archived contract-data footprint reported by simulation, paying
 * with the independently configured restore source.
 *
 * Soroban simulation returns a `restorePreamble` when the transaction touches
 * archived entries; the footprint must be restored (a separate, fee-bearing
 * transaction) before the real transaction can succeed. This source is
 * deliberately separate from the address-derivation deployer identity.
 *
 * Returns the restore transaction hash. This path is exercised live in F2 (it
 * requires archived on-chain state to trigger).
 *
 * @throws {SigningError} On submission/confirmation failure.
 */
export async function restoreFootprint(
  deps: {
    rpc: Server;
    networkPassphrase: string;
    sourceKeypair?: Keypair;
    timeoutInSeconds: number;
  },
  restorePreamble: RestorePreamble
): Promise<string> {
  if (!deps.sourceKeypair) {
    throw new PasskeyKitError(
      `Footprint restoration requires a funded \`restoreSource\` secret. ` +
        `It is intentionally separate from \`deploySource\`, because changing ` +
        `the deployer changes every derived wallet address.`,
      PasskeyKitErrorCode.INVALID_CONFIG
    );
  }
  if (isDefaultDeployer(deps.sourceKeypair.publicKey())) {
    throw new PasskeyKitError(
      "restoreSource must be a separate funded account, not the shared default deployer",
      PasskeyKitErrorCode.INVALID_CONFIG
    );
  }

  const account = await deps.rpc.getAccount(deps.sourceKeypair.publicKey());
  const fee = (Number(restorePreamble.minResourceFee) + 100_000).toString();

  const restoreTx = new TransactionBuilder(account, {
    fee,
    networkPassphrase: deps.networkPassphrase,
  })
    .addOperation(Operation.restoreFootprint({}))
    .setSorobanData(restorePreamble.transactionData.build())
    .setTimeout(deps.timeoutInSeconds)
    .build();

  restoreTx.sign(deps.sourceKeypair);

  const sendResult = await deps.rpc.sendTransaction(restoreTx);
  if (sendResult.status === "ERROR") {
    throw new PasskeyKitError(
      `Footprint restore submission failed: ${sendResult.errorResult?.toXDR("base64") ?? "unknown"}`,
      PasskeyKitErrorCode.RESTORE_REQUIRED,
      { context: { hash: sendResult.hash } }
    );
  }

  const result = await deps.rpc.pollTransaction(sendResult.hash, { attempts: 10 });
  if (result.status !== "SUCCESS") {
    throw new PasskeyKitError(
      `Footprint restore did not confirm (status ${result.status})`,
      PasskeyKitErrorCode.RESTORE_REQUIRED,
      { context: { hash: sendResult.hash } }
    );
  }

  return sendResult.hash;
}
