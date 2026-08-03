import { afterEach, describe, expect, it, vi } from "vitest";
import {
  Account,
  Address,
  Keypair,
  Networks,
  Operation,
  SorobanDataBuilder,
  TransactionBuilder,
  buildAuthorizationEntryPreimage,
  hash,
  xdr,
} from "@stellar/stellar-sdk";
import {
  NULL_ACCOUNT,
  type AssembledTransaction,
} from "@stellar/stellar-sdk/contract";
import type { Server } from "@stellar/stellar-sdk/rpc";
import { Client as PasskeyClient } from "passkey-kit-sdk";
import { PasskeyKit } from "../kit.js";
import { resolveDeployer } from "../kit/deploy-ops.js";
import { PasskeyKitErrorCode } from "../errors.js";
import { RelayerClient } from "../relayer.js";
import { PasskeyServer } from "../server.js";
import { SubmissionManager } from "./submission-manager.js";

const NETWORK = Networks.TESTNET;
const WASM_HASH = "ab".repeat(32);

function manager(
  deployerKeypair = resolveDeployer(),
  options?: { rpc?: Server; restoreKeypair?: Keypair }
): SubmissionManager {
  return new SubmissionManager({
    rpc: options?.rpc ?? ({} as Server),
    rpcUrl: "https://rpc.example",
    networkPassphrase: NETWORK,
    walletWasmHash: WASM_HASH,
    deployerKeypair,
    restoreKeypair: options?.restoreKeypair,
    timeoutInSeconds: 30,
  });
}

function deployTransaction(
  deployer: Keypair,
  source = NULL_ACCOUNT,
  subInvocations: xdr.SorobanAuthorizedInvocation[] = []
): AssembledTransaction<PasskeyClient> {
  const salt = hash(Buffer.from("credential-id"));
  const bareOperation = Operation.createCustomContract({
    address: Address.fromString(deployer.publicKey()),
    wasmHash: Buffer.from(WASM_HASH, "hex"),
    salt,
    constructorArgs: [],
  });
  const bareInvoke = bareOperation.body().invokeHostFunctionOp();

  const invocation = new xdr.SorobanAuthorizedInvocation({
    function:
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractV2HostFn(
        bareInvoke.hostFunction().createContractV2()
      ),
    subInvocations,
  });
  const discovered = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(deployer.publicKey()).toScAddress(),
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 0,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation: invocation,
  });
  const operation = Operation.createCustomContract({
    address: Address.fromString(deployer.publicKey()),
    wasmHash: Buffer.from(WASM_HASH, "hex"),
    salt,
    constructorArgs: [],
    auth: [discovered],
  });
  const built = new TransactionBuilder(new Account(source, "0"), {
    fee: "500",
    networkPassphrase: NETWORK,
  })
    .addOperation(operation)
    .setSorobanData(new SorobanDataBuilder().setResourceFee("321").build())
    .setTimeout(30)
    .build();

  return {
    built,
    simulation: { latestLedger: 1_000 },
  } as unknown as AssembledTransaction<PasskeyClient>;
}

afterEach(() => vi.restoreAllMocks());

describe("SubmissionManager deploy authorization", () => {
  it("builds shared deploys address-only and custom deploys from their account", async () => {
    const deploy = vi
      .spyOn(PasskeyClient, "deploy")
      .mockResolvedValue({} as AssembledTransaction<PasskeyClient>);
    const shared = resolveDeployer();
    const custom = Keypair.random();

    await manager(shared).buildDeployTransaction(Buffer.from("shared"), new Uint8Array(65));
    await manager(custom).buildDeployTransaction(Buffer.from("custom"), new Uint8Array(65));

    expect(deploy.mock.calls[0]![1]).toMatchObject({
      address: shared.publicKey(),
    });
    expect(deploy.mock.calls[0]![1]).not.toHaveProperty("publicKey");
    expect(deploy.mock.calls[1]![1]).toMatchObject({
      publicKey: custom.publicKey(),
    });
    expect(deploy.mock.calls[1]![1]).not.toHaveProperty("address");
  });

  it("signs only the shared deploy auth entry and routes it as Channels func+auth", async () => {
    const deployer = resolveDeployer();
    const carrierXdr = await manager(deployer).signDeploy(
      deployTransaction(deployer)
    );
    const carrier = TransactionBuilder.fromXDR(carrierXdr, NETWORK);

    expect(carrier.source).toBe(NULL_ACCOUNT);
    expect(carrier.source).not.toBe(deployer.publicKey());
    expect(carrier.signatures).toHaveLength(0);
    expect(carrier.operations).toHaveLength(1);
    const operation = carrier.operations[0]!;
    expect(operation.type).toBe("invokeHostFunction");
    if (operation.type !== "invokeHostFunction") throw new Error("bad fixture");
    expect(operation.auth).toHaveLength(1);

    const entry = operation.auth![0]!;
    expect(entry.credentials().switch().name).toBe("sorobanCredentialsAddress");
    const credentials = entry.credentials().address();
    expect(Address.fromScAddress(credentials.address()).toString()).toBe(
      deployer.publicKey()
    );
    const preimage = buildAuthorizationEntryPreimage(
      entry,
      credentials.signatureExpirationLedger(),
      NETWORK
    );
    expect(preimage.switch().name).toBe("envelopeTypeSorobanAuthorization");
    const signatureMap = credentials.signature().vec()![0]!.map()!;
    const signature = signatureMap.find(
      (item) => item.key().sym().toString() === "signature"
    )!.val().bytes();
    expect(deployer.verify(hash(preimage.toXDR()), Buffer.from(signature))).toBe(true);

    const send = vi
      .spyOn(RelayerClient.prototype, "send")
      .mockResolvedValue({ success: true, hash: "hash" });
    const sendTransaction = vi.spyOn(RelayerClient.prototype, "sendTransaction");
    const server = new PasskeyServer({
      networkPassphrase: NETWORK,
      relayer: { baseUrl: "https://relayer.example", apiKey: "test" },
    });
    await server.send(carrierXdr);

    expect(send).toHaveBeenCalledWith(
      operation.func.toXDR("base64"),
      [entry.toXDR("base64")],
      undefined
    );
    expect(sendTransaction).not.toHaveBeenCalled();
  });

  it("refuses to sign a shared deploy auth entry carrying sub-invocations", async () => {
    // A hostile simulation RPC returns the correct create-contract root with an
    // extra child. The deployer signs the whole tree, so the child would be
    // authorized under its address credentials too.
    const child = new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
          ).toScAddress(),
          functionName: "transfer",
          args: [],
        })
      ),
      subInvocations: [],
    });
    const shared = resolveDeployer();

    await expect(
      manager(shared).signDeploy(deployTransaction(shared, NULL_ACCOUNT, [child]))
    ).rejects.toThrow(/matching address authorization/);
  });

  it("keeps custom deploySource on the signed self-source envelope path", async () => {
    const custom = Keypair.random();
    const signedXdr = await manager(custom).signDeploy(
      deployTransaction(custom, custom.publicKey())
    );
    const signed = TransactionBuilder.fromXDR(signedXdr, NETWORK);

    expect(signed.source).toBe(custom.publicKey());
    expect(signed.signatures).toHaveLength(1);
    expect(Buffer.from(signed.signatures[0]!.hint())).toEqual(custom.signatureHint());
    expect(signed.fee).toBe("321");
  });
});

describe("restoreSource", () => {
  it("rejects a missing restoreSource before reading any account sequence", async () => {
    const getAccount = vi.fn();
    const rpc = { getAccount } as unknown as Server;

    await expect(
      manager(resolveDeployer(), { rpc }).restoreFootprint({
        minResourceFee: "1",
        transactionData: new SorobanDataBuilder(),
      })
    ).rejects.toMatchObject({
      code: PasskeyKitErrorCode.INVALID_CONFIG,
      message: expect.stringContaining("restoreSource"),
    });
    expect(getAccount).not.toHaveBeenCalled();
  });

  it("refuses the shared deployer as restoreSource before reading its sequence", async () => {
    const getAccount = vi.fn();
    const shared = resolveDeployer();

    await expect(
      manager(shared, {
        rpc: { getAccount } as unknown as Server,
        restoreKeypair: shared,
      }).restoreFootprint({
        minResourceFee: "1",
        transactionData: new SorobanDataBuilder(),
      })
    ).rejects.toMatchObject({
      code: PasskeyKitErrorCode.INVALID_CONFIG,
      message: expect.stringContaining("separate funded account"),
    });
    expect(getAccount).not.toHaveBeenCalled();
  });

  it("sequences and signs restores only with the decoupled restoreSource", async () => {
    const restore = Keypair.random();
    const deployer = resolveDeployer();
    const getAccount = vi.fn(async () => new Account(restore.publicKey(), "7"));
    const sendTransaction = vi.fn(async (transaction: ReturnType<typeof TransactionBuilder.fromXDR>) => {
      expect(transaction.source).toBe(restore.publicKey());
      expect(transaction.source).not.toBe(deployer.publicKey());
      expect(transaction.operations[0]?.type).toBe("restoreFootprint");
      expect(Buffer.from(transaction.signatures[0]!.hint())).toEqual(
        restore.signatureHint()
      );
      return { status: "PENDING", hash: "restore-hash" };
    });
    const pollTransaction = vi.fn(async () => ({ status: "SUCCESS" }));
    const rpc = {
      getAccount,
      sendTransaction,
      pollTransaction,
    } as unknown as Server;

    const hashValue = await manager(deployer, {
      rpc,
      restoreKeypair: restore,
    }).restoreFootprint({
      minResourceFee: "1",
      transactionData: new SorobanDataBuilder(),
    });

    expect(hashValue).toBe("restore-hash");
    expect(getAccount).toHaveBeenCalledWith(restore.publicKey());
  });

  it("validates restoreSource without changing the deployer identity", () => {
    expect(
      () =>
        new PasskeyKit({
          rpcUrl: "https://rpc.example",
          networkPassphrase: NETWORK,
          walletWasmHash: WASM_HASH,
          restoreSource: "not-a-secret",
        })
    ).toThrow("restoreSource must be a valid Stellar secret key");

    const restore = Keypair.random();
    const kit = new PasskeyKit({
      rpcUrl: "https://rpc.example",
      networkPassphrase: NETWORK,
      walletWasmHash: WASM_HASH,
      restoreSource: restore.secret(),
    });
    expect(kit.deployerPublicKey).toBe(resolveDeployer().publicKey());
  });
});
