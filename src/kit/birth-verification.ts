/**
 * Verify a wallet's immutable CreateContractV2 birth transaction.
 *
 * Indexer birth fields are discovery claims. This module treats Stellar RPC
 * as the source of truth and accepts only a successful transaction that
 * directly created the candidate address from an approved WASM hash.
 *
 * @packageDocumentation
 */

import {
  FeeBumpTransaction,
  StrKey,
  TransactionBuilder,
  hash,
  xdr,
} from "@stellar/stellar-sdk";
import { Api, type Server } from "@stellar/stellar-sdk/rpc";
import type { Horizon } from "@stellar/stellar-sdk";
import type { WalletCandidate } from "../indexer/types.js";

/** A verified, immutable wallet-birth fact. */
export interface VerifiedWalletBirth extends WalletCandidate {
  /** The lowercase hash read from the verified CreateContractV2 operation. */
  birthWasmHash: string;
}

/** A named reason why a wallet-birth claim failed verification. */
export type WalletBirthFailure =
  | "invalid_candidate"
  | "transaction_not_found"
  | "transaction_failed"
  | "transaction_hash_mismatch"
  | "ledger_mismatch"
  | "contract_not_created"
  | "ambiguous_creation"
  | "wasm_mismatch"
  | "wasm_not_accepted";

export type WalletBirthResult =
  | { ok: true; birth: VerifiedWalletBirth }
  | { ok: false; reason: WalletBirthFailure; detail: string };

export interface WalletBirthVerificationDeps {
  rpc: Server;
  /** Optional full-history source used after Stellar RPC retention expires. */
  history?: Pick<Horizon.Server, "transactions">;
  networkPassphrase: string;
  acceptedBirthWasmHashes: readonly string[];
}

const HASH_HEX = /^[0-9a-f]{64}$/;

function normalizeHash(value: string): string | undefined {
  const normalized = value.toLowerCase();
  return HASH_HEX.test(normalized) ? normalized : undefined;
}

function fail(reason: WalletBirthFailure, detail: string): WalletBirthResult {
  return { ok: false, reason, detail };
}

/** Derive a contract address from one CreateContractV2 preimage. */
export function contractIdFromCreateV2(
  networkPassphrase: string,
  create: xdr.CreateContractArgsV2
): string | undefined {
  const preimage = create.contractIdPreimage();
  if (preimage.switch().name !== "contractIdPreimageFromAddress") {
    return undefined;
  }

  const hashPreimage = xdr.HashIdPreimage.envelopeTypeContractId(
    new xdr.HashIdPreimageContractId({
      networkId: hash(Buffer.from(networkPassphrase)),
      contractIdPreimage: preimage,
    })
  );
  return StrKey.encodeContract(hash(hashPreimage.toXDR()));
}

/**
 * Verify an indexer-supplied wallet-birth claim against Stellar RPC.
 *
 * The function requires a direct CreateContractV2 operation. This matches the
 * passkey-kit deployment path and excludes unverifiable proxy deployments.
 */
export async function verifyWalletBirth(
  deps: WalletBirthVerificationDeps,
  candidate: WalletCandidate
): Promise<WalletBirthResult> {
  const claimedWasm = normalizeHash(candidate.birthWasmHash);
  const txHash = normalizeHash(candidate.creationTransactionHash);
  const accepted = new Set(
    deps.acceptedBirthWasmHashes.map(normalizeHash).filter((value): value is string => !!value)
  );

  if (!claimedWasm || !txHash || !Number.isSafeInteger(candidate.creationLedger)) {
    return fail("invalid_candidate", "wallet birth metadata is malformed");
  }

  const rpcResponse = await deps.rpc.getTransaction(txHash);
  let ledger: number;
  let envelopeXdr: xdr.TransactionEnvelope | string;

  if (rpcResponse.status === Api.GetTransactionStatus.SUCCESS) {
    ledger = rpcResponse.ledger;
    envelopeXdr = rpcResponse.envelopeXdr;
  } else if (rpcResponse.status === Api.GetTransactionStatus.FAILED) {
    return fail("transaction_failed", "the claimed creation transaction did not succeed");
  } else if (deps.history) {
    try {
      const historyResponse = await deps.history
        .transactions()
        .transaction(txHash)
        .call();
      if (!historyResponse.successful) {
        return fail(
          "transaction_failed",
          "the historical creation transaction did not succeed"
        );
      }
      if (historyResponse.hash.toLowerCase() !== txHash) {
        return fail(
          "transaction_hash_mismatch",
          "the history response returned a different transaction hash"
        );
      }
      ledger = historyResponse.ledger_attr;
      envelopeXdr = historyResponse.envelope_xdr;
    } catch (error) {
      const status =
        typeof error === "object" && error !== null && "response" in error
          ? (error as { response?: { status?: number } }).response?.status
          : undefined;
      if (status !== 404) throw error;
      return fail(
        "transaction_not_found",
        "the creation transaction is unavailable from RPC and history"
      );
    }
  } else {
    return fail(
      "transaction_not_found",
      "the creation transaction is outside RPC retention and no history source is configured"
    );
  }

  if (ledger !== candidate.creationLedger) {
    return fail(
      "ledger_mismatch",
      `creation ledger ${ledger} does not equal claimed ledger ${candidate.creationLedger}`
    );
  }

  const parsed = TransactionBuilder.fromXDR(
    envelopeXdr,
    deps.networkPassphrase
  );
  if (parsed.hash().toString("hex") !== txHash) {
    return fail(
      "transaction_hash_mismatch",
      "the transaction envelope does not match the claimed transaction hash"
    );
  }
  const transaction =
    parsed instanceof FeeBumpTransaction ? parsed.innerTransaction : parsed;

  const matches: xdr.CreateContractArgsV2[] = [];
  for (const operation of transaction.operations) {
    if (
      operation.type !== "invokeHostFunction" ||
      operation.func.switch().name !== "hostFunctionTypeCreateContractV2"
    ) {
      continue;
    }
    const create = operation.func.createContractV2();
    if (contractIdFromCreateV2(deps.networkPassphrase, create) === candidate.contractId) {
      matches.push(create);
    }
  }

  if (matches.length === 0) {
    return fail(
      "contract_not_created",
      "the transaction did not directly create the candidate contract"
    );
  }
  if (matches.length !== 1) {
    return fail(
      "ambiguous_creation",
      "the transaction contains multiple matching CreateContractV2 operations"
    );
  }

  const executable = matches[0]!.executable();
  if (executable.switch().name !== "contractExecutableWasm") {
    return fail("contract_not_created", "the matching creation did not use WASM code");
  }

  const actualWasm = Buffer.from(executable.wasmHash()).toString("hex");
  if (actualWasm !== claimedWasm) {
    return fail(
      "wasm_mismatch",
      `birth WASM ${actualWasm} does not equal claimed WASM ${claimedWasm}`
    );
  }
  if (!accepted.has(actualWasm)) {
    return fail("wasm_not_accepted", `birth WASM ${actualWasm} is not accepted`);
  }

  return {
    ok: true,
    birth: {
      ...candidate,
      birthWasmHash: actualWasm,
      creationTransactionHash: txHash,
    },
  };
}
