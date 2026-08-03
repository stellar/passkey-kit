/**
 * Submission manager: builds and authorizes deploys, derives deterministic
 * wallet addresses, and drives the footprint-restore flow.
 *
 * Network submission itself is the server's job (`PasskeyServer` / relayer); this
 * manager owns the deployer identity and its deploy authorization signature.
 *
 * @packageDocumentation
 */

import { Address, TransactionBuilder, xdr } from "@stellar/stellar-sdk";
import type { Keypair, Transaction } from "@stellar/stellar-sdk";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import type { Server } from "@stellar/stellar-sdk/rpc";
import type { Client as PasskeyClient } from "passkey-kit-sdk";
import {
  buildDeployTransaction as buildDeployTransactionOp,
  deriveWalletAddress as deriveWalletAddressOp,
} from "../kit/deploy-ops.js";
import {
  restoreFootprint as restoreFootprintOp,
  type RestorePreamble,
} from "../kit/tx-ops.js";
import { buildSignaturePayload } from "../kit/auth-payload.js";
import { isDefaultDeployer } from "../utils.js";

const DEPLOY_AUTH_LIFETIME_LEDGERS = 720;

export interface SubmissionManagerDeps {
  rpc: Server;
  rpcUrl: string;
  networkPassphrase: string;
  walletWasmHash: string;
  deployerKeypair: Keypair;
  restoreKeypair?: Keypair;
  timeoutInSeconds: number;
}

export class SubmissionManager {
  constructor(private readonly deps: SubmissionManagerDeps) {}

  /** The deployer's `G…` public key (address-derivation identity). */
  get deployerPublicKey(): string {
    return this.deps.deployerKeypair.publicKey();
  }

  /** Deterministically derive the wallet address for a passkey credential. */
  deriveWalletAddress(keyId: Buffer): string {
    return deriveWalletAddressOp(
      {
        networkPassphrase: this.deps.networkPassphrase,
        deployerPublicKey: this.deployerPublicKey,
      },
      keyId
    );
  }

  /** Build the wallet deploy transaction (initial Secp256r1 signer). */
  buildDeployTransaction(
    keyId: Buffer,
    publicKey: Uint8Array
  ): Promise<AssembledTransaction<PasskeyClient>> {
    return buildDeployTransactionOp(
      {
        rpcUrl: this.deps.rpcUrl,
        networkPassphrase: this.deps.networkPassphrase,
        walletWasmHash: this.deps.walletWasmHash,
        deployerPublicKey: this.deployerPublicKey,
        usingSharedDeployer: isDefaultDeployer(this.deployerPublicKey),
        timeoutInSeconds: this.deps.timeoutInSeconds,
      },
      keyId,
      publicKey
    );
  }

  /**
   * Authorize a deploy and return its carrier transaction XDR.
   *
   * The shared deployer signs one address auth entry; the carrier has no usable
   * source or envelope signature and `PasskeyServer` submits its `{func,auth}`.
   * A custom deployer keeps the legacy self-source envelope path. Its inner fee
   * must equal the resource fee before signing because the fee bump supplies the
   * inclusion fee. `TransactionBuilder.cloneFrom` drops Soroban data, so that
   * fee field is changed directly on the envelope.
   */
  async signDeploy(tx: AssembledTransaction<PasskeyClient>): Promise<string> {
    if (!tx.built) {
      throw new Error("deploy transaction has not been built/simulated");
    }

    if (isDefaultDeployer(this.deployerPublicKey)) {
      const operation = tx.built.operations[0];
      const auth = operation?.type === "invokeHostFunction" ? operation.auth ?? [] : [];
      const latestLedger = tx.simulation?.latestLedger;
      const authorizedFunction = auth[0]?.rootInvocation().function();
      const authorizedCreate =
        authorizedFunction?.switch().name ===
        "sorobanAuthorizedFunctionTypeCreateContractV2HostFn"
          ? authorizedFunction.createContractV2HostFn()
          : undefined;
      const operationCreate =
        operation?.type === "invokeHostFunction" &&
        operation.func.switch().name === "hostFunctionTypeCreateContractV2"
          ? operation.func.createContractV2()
          : undefined;
      const fromAddress = authorizedCreate?.contractIdPreimage().fromAddress();

      if (
        tx.built.operations.length !== 1 ||
        tx.built.source === this.deployerPublicKey ||
        tx.built.signatures.length !== 0 ||
        auth.length !== 1 ||
        latestLedger === undefined ||
        !authorizedCreate ||
        !operationCreate ||
        !Buffer.from(authorizedCreate.toXDR()).equals(operationCreate.toXDR()) ||
        !fromAddress ||
        Address.fromScAddress(fromAddress.address()).toString() !==
          this.deployerPublicKey ||
        // The deployer signs the whole tree, so anything hanging off the root
        // would be authorized too. A deployment needs no sub-invocations.
        auth[0].rootInvocation().subInvocations().length !== 0
      ) {
        throw new Error(
          "shared deploy simulation did not return one matching address authorization"
        );
      }

      const nonceBytes = crypto.getRandomValues(new Uint8Array(8));
      const expirationLedger = latestLedger + DEPLOY_AUTH_LIFETIME_LEDGERS;
      const credentials = new xdr.SorobanAddressCredentials({
        address: Address.fromString(this.deployerPublicKey).toScAddress(),
        nonce: xdr.Int64.fromString(
          Buffer.from(nonceBytes).readBigInt64BE().toString()
        ),
        signatureExpirationLedger: expirationLedger,
        signature: xdr.ScVal.scvVoid(),
      });
      const signedEntry = new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(credentials),
        rootInvocation: auth[0]!.rootInvocation(),
      });
      credentials.signature(
        xdr.ScVal.scvVec([
          xdr.ScVal.scvMap([
            new xdr.ScMapEntry({
              key: xdr.ScVal.scvSymbol("public_key"),
              val: xdr.ScVal.scvBytes(this.deps.deployerKeypair.rawPublicKey()),
            }),
            new xdr.ScMapEntry({
              key: xdr.ScVal.scvSymbol("signature"),
              val: xdr.ScVal.scvBytes(
                this.deps.deployerKeypair.sign(
                  buildSignaturePayload(
                    this.deps.networkPassphrase,
                    signedEntry,
                    expirationLedger
                  )
                )
              ),
            }),
          ]),
        ])
      );

      const envelope = tx.built.toEnvelope();
      envelope.v1().tx().operations()[0]!.body().invokeHostFunctionOp().auth([
        signedEntry,
      ]);
      return envelope.toXDR("base64");
    }

    const envelope = tx.built.toEnvelope();
    const inner = envelope.v1().tx();
    const resourceFee = inner.ext().sorobanData().resourceFee().toString();
    inner.fee(Number(resourceFee));

    const feeAdjusted = TransactionBuilder.fromXDR(
      envelope.toXDR("base64"),
      this.deps.networkPassphrase
    ) as Transaction;
    feeAdjusted.sign(this.deps.deployerKeypair);
    return feeAdjusted.toXDR();
  }

  /** Restore an archived footprint reported by simulation. */
  restoreFootprint(restorePreamble: RestorePreamble): Promise<string> {
    return restoreFootprintOp(
      {
        rpc: this.deps.rpc,
        networkPassphrase: this.deps.networkPassphrase,
        sourceKeypair: this.deps.restoreKeypair,
        timeoutInSeconds: this.deps.timeoutInSeconds,
      },
      restorePreamble
    );
  }
}
