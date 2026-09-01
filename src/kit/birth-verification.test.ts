import {
  Account,
  Address,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  hash,
  xdr,
} from "@stellar/stellar-sdk";
import { Api, type Server } from "@stellar/stellar-sdk/rpc";
import { describe, expect, it, vi } from "vitest";
import type { WalletCandidate } from "../indexer/types.js";
import {
  contractIdFromCreateV2,
  verifyWalletBirth,
} from "./birth-verification.js";

const NETWORK = Networks.TESTNET;
const WASM_HASH = "ab".repeat(32);
const OTHER_HASH = "cd".repeat(32);
const LEDGER = 987_654;
const DEPLOYER = Keypair.random();
const SOURCE = Keypair.random();
const SALT = hash(Buffer.from("birth-verification-test"));

function buildCreation(wasmHash = WASM_HASH, salt = SALT) {
  const transaction = new TransactionBuilder(
    new Account(SOURCE.publicKey(), "0"),
    { fee: "100", networkPassphrase: NETWORK }
  )
    .addOperation(
      Operation.createCustomContract({
        address: Address.fromString(DEPLOYER.publicKey()),
        wasmHash: Buffer.from(wasmHash, "hex"),
        salt,
        constructorArgs: [],
      })
    )
    .setTimeout(0)
    .build();

  const operation = transaction.operations[0];
  if (
    operation?.type !== "invokeHostFunction" ||
    operation.func.switch().name !== "hostFunctionTypeCreateContractV2"
  ) {
    throw new Error("test did not build CreateContractV2");
  }
  const contractId = contractIdFromCreateV2(
    NETWORK,
    operation.func.createContractV2()
  );
  if (!contractId) throw new Error("test could not derive contract id");
  return { transaction, contractId, txHash: transaction.hash().toString("hex") };
}

function candidate(contractId: string, txHash: string): WalletCandidate {
  return {
    contractId,
    birthWasmHash: WASM_HASH,
    creationTransactionHash: txHash,
    creationLedger: LEDGER,
  };
}

function rpcFor(
  envelopeXdr: xdr.TransactionEnvelope,
  txHash: string,
  overrides: Record<string, unknown> = {}
): Server {
  return {
    getTransaction: vi.fn(async () => ({
      status: Api.GetTransactionStatus.SUCCESS,
      txHash,
      ledger: LEDGER,
      envelopeXdr,
      ...overrides,
    })),
  } as unknown as Server;
}

describe("verifyWalletBirth", () => {
  it("accepts a matching successful CreateContractV2 transaction", async () => {
    const { transaction, contractId, txHash } = buildCreation();
    const result = await verifyWalletBirth(
      {
        rpc: rpcFor(transaction.toEnvelope(), txHash),
        networkPassphrase: NETWORK,
        acceptedBirthWasmHashes: [WASM_HASH],
      },
      candidate(contractId, txHash)
    );

    expect(result).toEqual({ ok: true, birth: candidate(contractId, txHash) });
  });

  it("accepts the inner creation transaction in a fee bump", async () => {
    const { transaction, contractId } = buildCreation();
    const feeBump = TransactionBuilder.buildFeeBumpTransaction(
      Keypair.random(),
      "100",
      transaction,
      NETWORK
    );
    const txHash = feeBump.hash().toString("hex");

    await expect(
      verifyWalletBirth(
        {
          rpc: rpcFor(feeBump.toEnvelope(), txHash),
          networkPassphrase: NETWORK,
          acceptedBirthWasmHashes: [WASM_HASH],
        },
        candidate(contractId, txHash)
      )
    ).resolves.toMatchObject({ ok: true });
  });

  it("uses full history after the RPC retention window", async () => {
    const { transaction, contractId, txHash } = buildCreation();
    const history = {
      transactions: () => ({
        transaction: (requested: string) => ({
          call: async () => ({
            hash: requested,
            successful: true,
            ledger_attr: LEDGER,
            envelope_xdr: transaction.toXDR(),
          }),
        }),
      }),
    };

    await expect(
      verifyWalletBirth(
        {
          rpc: rpcFor(transaction.toEnvelope(), txHash, {
            status: Api.GetTransactionStatus.NOT_FOUND,
          }),
          history: history as never,
          networkPassphrase: NETWORK,
          acceptedBirthWasmHashes: [WASM_HASH],
        },
        candidate(contractId, txHash)
      )
    ).resolves.toMatchObject({ ok: true });
  });

  it("rejects a transaction that created another address", async () => {
    const first = buildCreation();
    const other = buildCreation(WASM_HASH, hash(Buffer.from("another-wallet")));
    const result = await verifyWalletBirth(
      {
        rpc: rpcFor(first.transaction.toEnvelope(), first.txHash),
        networkPassphrase: NETWORK,
        acceptedBirthWasmHashes: [WASM_HASH],
      },
      candidate(other.contractId, first.txHash)
    );

    expect(result).toMatchObject({ ok: false, reason: "contract_not_created" });
  });

  it("rejects a false birth hash claim", async () => {
    const { transaction, contractId, txHash } = buildCreation();
    const result = await verifyWalletBirth(
      {
        rpc: rpcFor(transaction.toEnvelope(), txHash),
        networkPassphrase: NETWORK,
        acceptedBirthWasmHashes: [WASM_HASH],
      },
      { ...candidate(contractId, txHash), birthWasmHash: OTHER_HASH }
    );

    expect(result).toMatchObject({ ok: false, reason: "wasm_mismatch" });
  });

  it("rejects a verified birth hash outside the accepted set", async () => {
    const { transaction, contractId, txHash } = buildCreation();
    const result = await verifyWalletBirth(
      {
        rpc: rpcFor(transaction.toEnvelope(), txHash),
        networkPassphrase: NETWORK,
        acceptedBirthWasmHashes: [OTHER_HASH],
      },
      candidate(contractId, txHash)
    );

    expect(result).toMatchObject({ ok: false, reason: "wasm_not_accepted" });
  });

  it("rejects failed, missing, and wrong-ledger transactions", async () => {
    const { transaction, contractId, txHash } = buildCreation();
    const base = {
      networkPassphrase: NETWORK,
      acceptedBirthWasmHashes: [WASM_HASH],
    };

    await expect(
      verifyWalletBirth(
        {
          ...base,
          rpc: rpcFor(transaction.toEnvelope(), txHash, {
            status: Api.GetTransactionStatus.NOT_FOUND,
          }),
        },
        candidate(contractId, txHash)
      )
    ).resolves.toMatchObject({ ok: false, reason: "transaction_not_found" });

    await expect(
      verifyWalletBirth(
        {
          ...base,
          rpc: rpcFor(transaction.toEnvelope(), txHash, {
            status: Api.GetTransactionStatus.FAILED,
          }),
        },
        candidate(contractId, txHash)
      )
    ).resolves.toMatchObject({ ok: false, reason: "transaction_failed" });

    await expect(
      verifyWalletBirth(
        {
          ...base,
          rpc: rpcFor(transaction.toEnvelope(), txHash, { ledger: LEDGER + 1 }),
        },
        candidate(contractId, txHash)
      )
    ).resolves.toMatchObject({ ok: false, reason: "ledger_mismatch" });
  });
});
