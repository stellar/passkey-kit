/**
 * `PasskeyKit` — the browser-side facade for creating and using smart-wallet
 * accounts with WebAuthn passkeys.
 *
 * This is a ground-up rewrite of the old monolithic `kit.ts`. The signing
 * pipeline, WebAuthn ceremonies, deploy path, and signer writes now live in
 * dependency-injected managers ({@link CredentialManager}, {@link SignerManager},
 * {@link SubmissionManager}) wired here with late-bound closures. All Protocol-27
 * probe shims and dead commented experiments are gone. The kit targets
 * stellar-sdk >= 16 and the current wallet.
 *
 * @packageDocumentation
 */

import { Horizon, Keypair, Networks, xdr } from "@stellar/stellar-sdk";
import { Api, Server } from "@stellar/stellar-sdk/rpc";
import {
  startAuthentication,
  startRegistration,
  type AuthenticationResponseJSON,
  type AuthenticatorSelectionCriteria,
} from "@simplewebauthn/browser";
import type {
  AssembledTransaction,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import {
  Client as PasskeyClient,
  type BindingPurpose,
  type Secp256r1Signature,
  type Signer as ContractSigner,
  type SignerVal,
} from "passkey-kit-sdk";
import base64url from "./base64url.js";
import {
  SignerKey,
  SignerStore,
  type ConnectWalletResult,
  type CreateWalletResult,
  type SignerLimits,
  type StorageAdapter,
} from "./types.js";
import {
  ConfigurationError,
  PasskeyKitError,
  PasskeyKitErrorCode,
  WalletNotConnectedError,
  WalletOwnershipError,
  WalletAmbiguousError,
} from "./errors.js";
import { PasskeyEventEmitter } from "./events.js";
import { isDefaultDeployer } from "./utils.js";
import { DEFAULT_TIMEOUT_SECONDS } from "./constants.js";
import { PasskeySigner, type Signer, type SignerContext } from "./signers.js";
import type { WebAuthnClient } from "./kit/webauthn-ops.js";
import type { CreatedPasskey } from "./kit/webauthn-ops.js";
import type { SignOptions } from "./kit/tx-ops.js";
import { calculateExpiration } from "./kit/tx-ops.js";
import {
  CredentialManager,
  SignerManager,
  SubmissionManager,
} from "./managers/index.js";
import { resolveDeployer } from "./kit/deploy-ops.js";
import {
  buildSecp256r1Signer,
  type PolicySignerTxOptions,
  type WalletTx,
} from "./kit/wallet-ops.js";
import type {
  WalletCandidate,
  WalletCandidateLookup,
} from "./indexer/types.js";
import {
  verifyWalletBirth,
  type VerifiedWalletBirth,
} from "./kit/birth-verification.js";
import {
  bindingChallenge,
  verifyBindingRecord,
  verifyFreshAssertion,
  verifyStoredProof,
} from "./kit/webauthn-verify.js";

/** Extract the generated contract spec from a wallet client. */
function specOf(wallet: PasskeyClient): ContractSpec {
  return (wallet as unknown as { spec: ContractSpec }).spec;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a).equals(Buffer.from(b));
}

/** Configuration for a {@link PasskeyKit} client. */
export interface PasskeyKitConfig {
  /** Stellar RPC URL. */
  rpcUrl: string;
  /** Network passphrase. */
  networkPassphrase: string;
  /** Smart-wallet WASM hash (hex) used to deploy new wallets. */
  walletWasmHash: string;
  /**
   * Current code identities accepted during every wallet connection.
   * Defaults to `[walletWasmHash]`.
   *
   * This is a list rather than a single value because a legitimately upgraded
   * wallet runs different code. Add each accepted hash during an upgrade.
   * See `docs/security-deterministic-deployer.md`.
   */
  acceptedWasmHashes?: string[];
  /**
   * Immutable birth WASM hashes accepted during wallet discovery.
   * Defaults to `[walletWasmHash]`. This list is separate from current code
   * identities because a valid wallet can upgrade after its secure birth.
   */
  acceptedBirthWasmHashes?: string[];
  /**
   * Full-history Horizon URL for creation transactions outside RPC retention.
   * Public and test networks use the official Horizon endpoints by default.
   */
  horizonUrl?: string;
  /** WebAuthn Relying Party id (domain); defaults to the current origin. */
  rpId?: string;
  /** Accepted WebAuthn origins. Defaults to the browser origin. Required outside a browser. */
  allowedOrigins?: readonly string[];
  /** Require the WebAuthn User Verified flag. User Presence is always required. */
  requireUserVerification?: boolean;
  /**
   * Secret key (`S…`) for the address-derivation deployer. Defaults to the
   * canonical shared sign-only deployer (see {@link resolveDeployer});
   * overriding it changes derived wallet addresses.
   */
  deploySource?: string;
  /** Funded secret key used only to source footprint-restoration transactions. */
  restoreSource?: string;
  /** Transaction timeout, in seconds (default 30). */
  timeoutInSeconds?: number;
  /** Optional passkey-record storage adapter (see `passkey-kit/storage`). */
  storage?: StorageAdapter;
  /** Custom WebAuthn implementation (for testing). */
  WebAuthn?: WebAuthnClient;
}

/** Options for {@link PasskeyKit.createKey}/{@link PasskeyKit.createWallet}. */
export interface CreateOptions {
  authenticatorSelection?: AuthenticatorSelectionCriteria;
}

/** Options for {@link PasskeyKit.connectWallet}. */
export interface ConnectOptions {
  /** A specific keyId to connect. Untrusted discovery still requires a proof ceremony. */
  keyId?: string | Uint8Array;
  /**
   * Complete indexer-backed keyId lookup with immutable birth claims.
   * The kit verifies every claim through Stellar RPC before use.
   */
  getWalletCandidates?: (keyId: string) => Promise<WalletCandidateLookup>;
}

export class PasskeyKit {
  readonly rpc: Server;
  readonly rpcUrl: string;
  readonly networkPassphrase: string;
  readonly walletWasmHash: string;
  /** Accepted code identities, lowercase hex. Never empty. */
  readonly acceptedWasmHashes: readonly string[];
  /** Accepted immutable birth code identities, lowercase hex. Never empty. */
  readonly acceptedBirthWasmHashes: readonly string[];
  /** Full-history source for immutable wallet-birth verification. */
  readonly history?: Horizon.Server;
  readonly rpId?: string;

  /** Lifecycle event emitter (walletCreated, walletConnected, …). */
  readonly events = new PasskeyEventEmitter();

  private readonly timeoutInSeconds: number;
  private readonly webAuthn: WebAuthnClient;
  private readonly allowedOrigins?: readonly string[];
  private readonly requireUserVerification: boolean;

  private readonly credentialManager: CredentialManager;
  private readonly signerManager: SignerManager;
  private readonly submissionManager: SubmissionManager;

  /** The connected passkey's base64url keyId, if any. */
  keyId: string | undefined;
  /** The connected wallet client, if any. */
  wallet: PasskeyClient | undefined;

  constructor(config: PasskeyKitConfig) {
    if (!config.rpcUrl) {
      throw new ConfigurationError(
        "rpcUrl is required",
        PasskeyKitErrorCode.MISSING_CONFIG
      );
    }
    if (!config.networkPassphrase) {
      throw new ConfigurationError(
        "networkPassphrase is required",
        PasskeyKitErrorCode.MISSING_CONFIG
      );
    }
    if (!config.walletWasmHash) {
      throw new ConfigurationError(
        "walletWasmHash is required",
        PasskeyKitErrorCode.MISSING_CONFIG
      );
    }

    this.rpc = new Server(config.rpcUrl);
    this.rpcUrl = config.rpcUrl;
    this.networkPassphrase = config.networkPassphrase;
    this.walletWasmHash = config.walletWasmHash;
    // Seeded from the deploy hash so the common case is zero-config; an empty
    // array would silently accept nothing, so treat it as "not supplied".
    this.acceptedWasmHashes = (
      config.acceptedWasmHashes?.length
        ? config.acceptedWasmHashes
        : [config.walletWasmHash]
    ).map((h) => h.toLowerCase());
    this.acceptedBirthWasmHashes = (
      config.acceptedBirthWasmHashes?.length
        ? config.acceptedBirthWasmHashes
        : [config.walletWasmHash]
    ).map((h) => h.toLowerCase());
    const horizonUrl =
      config.horizonUrl ??
      (config.networkPassphrase === Networks.PUBLIC
        ? "https://horizon.stellar.org"
        : config.networkPassphrase === Networks.TESTNET
          ? "https://horizon-testnet.stellar.org"
          : undefined);
    this.history = horizonUrl ? new Horizon.Server(horizonUrl) : undefined;
    const browserLocation =
      typeof globalThis.location === "object" ? globalThis.location : undefined;
    this.rpId = config.rpId ?? browserLocation?.hostname;
    this.allowedOrigins =
      config.allowedOrigins ??
      (browserLocation?.origin ? [browserLocation.origin] : undefined);
    this.requireUserVerification = config.requireUserVerification ?? false;
    this.timeoutInSeconds = config.timeoutInSeconds ?? DEFAULT_TIMEOUT_SECONDS;
    this.webAuthn =
      config.WebAuthn ?? ({ startRegistration, startAuthentication } as WebAuthnClient);

    const deployerKeypair = resolveDeployer(config.deploySource);
    let restoreKeypair: Keypair | undefined;
    if (config.restoreSource) {
      try {
        restoreKeypair = Keypair.fromSecret(config.restoreSource);
      } catch {
        throw new ConfigurationError(
          "restoreSource must be a valid Stellar secret key (S…)",
          PasskeyKitErrorCode.INVALID_CONFIG
        );
      }
    } else if (!isDefaultDeployer(deployerKeypair.publicKey())) {
      // No dedicated restoreSource, but the integrator supplied their OWN funded
      // deploySource: keep the pre-existing behaviour and let it source restores.
      // Address derivation is unaffected (their deployer identity is unchanged),
      // so this stays address-preserving. Only the SHARED default deployer is
      // refused — it must never source or fund a transaction.
      restoreKeypair = deployerKeypair;
    }

    this.credentialManager = new CredentialManager({
      rpId: this.rpId,
      webAuthn: this.webAuthn,
      storage: config.storage,
    });

    this.signerManager = new SignerManager({
      networkPassphrase: this.networkPassphrase,
      timeoutInSeconds: this.timeoutInSeconds,
      rpc: this.rpc,
      getWallet: () => this.wallet,
      getContractId: () => this.wallet?.options.contractId,
      getSignerContext: () => this.signerContext(),
      calculateExpiration: () =>
        calculateExpiration({ rpc: this.rpc, timeoutInSeconds: this.timeoutInSeconds }),
    });

    this.submissionManager = new SubmissionManager({
      rpc: this.rpc,
      rpcUrl: config.rpcUrl,
      networkPassphrase: this.networkPassphrase,
      walletWasmHash: this.walletWasmHash,
      deployerKeypair,
      restoreKeypair,
      timeoutInSeconds: this.timeoutInSeconds,
    });
  }

  /** The connected wallet's contract id, if any. */
  get contractId(): string | undefined {
    return this.wallet?.options.contractId;
  }

  /** The address-derivation deployer's `G…` public key. */
  get deployerPublicKey(): string {
    return this.submissionManager.deployerPublicKey;
  }

  private signerContext(): SignerContext {
    return { rpId: this.rpId, webAuthn: this.webAuthn, defaultKeyId: this.keyId };
  }

  // -- Passkey / wallet lifecycle ---------------------------------------------

  /** Run a passkey registration ceremony without deploying a wallet. */
  createKey(
    appName: string,
    userName: string,
    options?: CreateOptions
  ): Promise<CreatedPasskey> {
    return this.credentialManager.createKey(
      appName,
      userName,
      options?.authenticatorSelection
    );
  }

  /**
   * Register a passkey and build a smart-wallet deployment initialized with it
   * as the first signer. The kit remains disconnected until the caller confirms
   * submission and calls `connectWallet`.
   */
  async createWallet(
    appName: string,
    userName: string,
    options?: CreateOptions
  ): Promise<CreateWalletResult> {
    const created = await this.createKey(appName, userName, options);
    const contractId = this.submissionManager.deriveWalletAddress(created.keyIdBuffer);
    const signer = buildSecp256r1Signer(
      created.keyIdBuffer,
      created.publicKey,
      undefined,
      SignerStore.Persistent
    );
    const proof = await this.createBindingProof(
      contractId,
      signer,
      "Genesis"
    );

    const deployTx = await this.submissionManager.buildDeployTransaction(
      created.keyIdBuffer,
      created.publicKey,
      proof
    );
    if (deployTx.result.options.contractId !== contractId) {
      throw new WalletOwnershipError(
        "Wallet deployment returned an unexpected address",
        { expected: contractId, actual: deployTx.result.options.contractId }
      );
    }
    const signedTx = await this.submissionManager.signDeploy(deployTx);

    return {
      rawResponse: created.rawResponse,
      keyId: created.keyIdBuffer,
      keyIdBase64: created.keyId,
      publicKey: created.publicKey,
      contractId,
      signedTx,
    };
  }

  /**
   * Verify a successful wallet deployment and persist its immutable birth data.
   * Call this only after the relayer returns a successful transaction hash.
   */
  async confirmWalletCreation(
    created: CreateWalletResult,
    creationTransactionHash: string
  ): Promise<VerifiedWalletBirth> {
    const txHash = creationTransactionHash.toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(txHash)) {
      throw new WalletOwnershipError(
        "The wallet creation transaction hash is malformed",
        { contractId: created.contractId }
      );
    }
    const response = await this.rpc.getTransaction(txHash);
    let creationLedger: number | undefined;
    if (response.status === Api.GetTransactionStatus.SUCCESS) {
      creationLedger = response.ledger;
    } else if (response.status === Api.GetTransactionStatus.NOT_FOUND && this.history) {
      const historical = await this.history
        .transactions()
        .transaction(txHash)
        .call();
      if (historical.successful) creationLedger = historical.ledger_attr;
    }
    if (creationLedger === undefined) {
      throw new WalletOwnershipError(
        "The wallet creation transaction is not available as a successful history transaction",
        { contractId: created.contractId, creationTransactionHash: txHash }
      );
    }

    const candidate: WalletCandidate = {
      contractId: created.contractId,
      birthWasmHash: this.walletWasmHash,
      creationTransactionHash: txHash,
      creationLedger,
    };
    const verified = await verifyWalletBirth(
      {
        rpc: this.rpc,
        history: this.history,
        networkPassphrase: this.networkPassphrase,
        acceptedBirthWasmHashes: this.acceptedBirthWasmHashes,
      },
      candidate
    );
    if (!verified.ok) {
      throw new WalletOwnershipError(
        `Wallet birth verification failed: ${verified.detail}`,
        { contractId: created.contractId, reason: verified.reason }
      );
    }

    await this.credentialManager.rememberPasskey({
      keyId: created.keyIdBase64,
      publicKey: created.publicKey,
      ...verified.birth,
      createdAt: Date.now(),
    });
    this.events.emit("walletCreated", {
      contractId: created.contractId,
      keyId: created.keyIdBase64,
    });
    return verified.birth;
  }

  /**
   * Connect an existing wallet from a passkey.
   *
   * Resolves wallet candidates from verified local storage or one complete
   * indexer response. Every candidate must prove its immutable birth, current
   * code, signer binding, and fresh passkey possession. The method connects
   * only when one candidate passes every check.
   *
   * @throws {WalletOwnershipError} If the keyId is not a signer on the wallet.
   */
  async connectWallet(options?: ConnectOptions): Promise<ConnectWalletResult> {
    let rawResponse: AuthenticationResponseJSON | undefined;
    let authenticationChallenge: Buffer | undefined;
    let keyId = options?.keyId;

    if (!keyId) {
      const auth = await this.credentialManager.authenticate(keyId);
      keyId = auth.keyId;
      rawResponse = auth.rawResponse;
      authenticationChallenge = auth.challenge;
    }

    const keyIdBase64 =
      keyId instanceof Uint8Array ? base64url(Buffer.from(keyId)) : keyId;
    const keyIdBuffer =
      keyId instanceof Uint8Array ? Buffer.from(keyId) : base64url.toBuffer(keyId);

    const storedPasskey = await this.credentialManager.getPasskey(keyIdBase64);
    const storedCandidate: WalletCandidate | undefined =
      storedPasskey?.contractId &&
      storedPasskey.birthWasmHash &&
      storedPasskey.creationTransactionHash &&
      Number.isSafeInteger(storedPasskey.creationLedger)
        ? {
            contractId: storedPasskey.contractId,
            birthWasmHash: storedPasskey.birthWasmHash,
            creationTransactionHash: storedPasskey.creationTransactionHash,
            creationLedger: storedPasskey.creationLedger,
          }
        : undefined;

    let candidates: readonly WalletCandidate[] = storedCandidate
      ? [storedCandidate]
      : [];
    if (!storedCandidate && options?.getWalletCandidates) {
      const lookupFloor = (await this.rpc.getLatestLedger()).sequence;
      const lookup = await options.getWalletCandidates(keyIdBase64);
      if (
        !lookup.complete ||
        lookup.schema !== 2 ||
        lookup.indexedThroughLedger < lookupFloor
      ) {
        throw new WalletOwnershipError(
          "The wallet lookup is incomplete or stale and cannot prove unique ownership",
          {
            keyId: keyIdBase64,
            indexedThroughLedger: lookup.indexedThroughLedger,
            requiredLedger: lookupFloor,
          }
        );
      }
      candidates = lookup.candidates;
    }

    if (candidates.length === 0) {
      throw new PasskeyKitError(
        "Could not resolve a wallet for the given passkey",
        PasskeyKitErrorCode.WALLET_NOT_FOUND,
        { context: { keyId: keyIdBase64 } }
      );
    }

    if (!rawResponse || !authenticationChallenge) {
      const auth = await this.credentialManager.authenticate(keyIdBase64);
      if (auth.keyId !== keyIdBase64) {
        throw new WalletOwnershipError(
          "The passkey returned a different credential during ownership proof",
          { expected: keyIdBase64, actual: auth.keyId }
        );
      }
      rawResponse = auth.rawResponse;
      authenticationChallenge = auth.challenge;
    }

    const verified = new Map<
      string,
      {
        wallet: PasskeyClient;
        birth: VerifiedWalletBirth;
        signer: Extract<SignerVal, { tag: "Secp256r1" }>;
      }
    >();
    // The last definitive rejection, rethrown verbatim when nothing verifies so
    // its context (e.g. the rejected wasm hash) is not replaced by a summary.
    let lastMismatch: WalletOwnershipError | undefined;

    for (const candidate of candidates) {
      const wallet = new PasskeyClient({
        contractId: candidate.contractId,
        rpcUrl: this.rpcUrl,
        networkPassphrase: this.networkPassphrase,
      });
      this.wallet = wallet;
      this.keyId = keyIdBase64;

      try {
        const birth = await verifyWalletBirth(
          {
            rpc: this.rpc,
            history: this.history,
            networkPassphrase: this.networkPassphrase,
            acceptedBirthWasmHashes: this.acceptedBirthWasmHashes,
          },
          candidate
        );
        if (!birth.ok) {
          lastMismatch = new WalletOwnershipError(
            `Wallet birth verification failed: ${birth.detail}`,
            { contractId: candidate.contractId, reason: birth.reason }
          );
          continue;
        }

        await this.assertWalletWasmHash(candidate.contractId);
        const signerVal = await this.signerManager.getSigner(
          SignerKey.Secp256r1(keyIdBase64)
        );
        if (!signerVal || signerVal.tag !== "Secp256r1") {
          lastMismatch = new WalletOwnershipError(
            "The passkey is not a live signer on the candidate wallet",
            { contractId: candidate.contractId, keyId: keyIdBase64 }
          );
          continue;
        }
        if (!rawResponse || !authenticationChallenge) {
          throw new Error("signer provenance requires a fresh WebAuthn assertion");
        }
        await this.assertSignerProvenance(
          wallet,
          candidate.contractId,
          keyIdBuffer,
          signerVal,
          rawResponse,
          authenticationChallenge
        );
        verified.set(candidate.contractId, {
          wallet,
          birth: birth.birth,
          signer: signerVal,
        });
      } catch (err) {
        this.wallet = undefined;
        this.keyId = undefined;
        if (err instanceof WalletOwnershipError) {
          lastMismatch = err;
          continue;
        }
        throw err;
      }
    }

    this.wallet = undefined;
    this.keyId = undefined;

    if (verified.size === 0) {
      throw (
        lastMismatch ??
        new WalletOwnershipError(
          "The passkey is not a signer on any resolved wallet",
          {
            candidates: candidates.map(({ contractId }) => contractId),
            keyId: keyIdBase64,
          }
        )
      );
    }
    if (verified.size > 1) {
      throw new WalletAmbiguousError([...verified.keys()]);
    }

    const [[contractId, match]] = [...verified.entries()];
    const { wallet, birth, signer } = match!;
    this.wallet = wallet;
    this.keyId = keyIdBase64;

    await this.credentialManager.rememberPasskey({
      keyId: keyIdBase64,
      publicKey: signer.values[0],
      ...birth,
      createdAt: storedPasskey?.createdAt ?? Date.now(),
      ...(storedPasskey?.nickname ? { nickname: storedPasskey.nickname } : {}),
      lastUsedAt: Date.now(),
    });

    this.events.emit("walletConnected", { contractId, keyId: keyIdBase64 });

    return { rawResponse, keyId: keyIdBuffer, keyIdBase64, contractId };
  }

  private async assertWalletWasmHash(contractId: string): Promise<void> {
    const wasmHash = await this.contractWasmHash(contractId);
    if (!this.acceptedWasmHashes.includes(wasmHash)) {
      throw new WalletOwnershipError("Wallet code identity is not accepted", {
        contractId,
        accepted: this.acceptedWasmHashes,
        actual: wasmHash,
      });
    }
  }

  private async contractWasmHash(contractId: string): Promise<string> {
    const instance = await this.rpc.getContractData(
      contractId,
      xdr.ScVal.scvLedgerKeyContractInstance()
    );
    const executable = instance.val
      .contractData()
      .val()
      .instance()
      .executable();
    if (executable.switch().name !== "contractExecutableWasm") {
      throw new WalletOwnershipError("Wallet is not a WASM contract", {
        contractId,
      });
    }
    return executable.wasmHash().toString("hex");
  }

  /** Create the address-bound proof required for a Secp256r1 signer write. */
  private async createBindingProof(
    contractId: string,
    signer: ContractSigner,
    purpose: BindingPurpose["tag"]
  ): Promise<Secp256r1Signature> {
    this.assertWebAuthnVerificationConfig();
    if (signer.tag !== "Secp256r1") {
      throw new TypeError("binding signer must be Secp256r1");
    }
    const [keyId, publicKey] = signer.values;

    const wallet = new PasskeyClient({
      contractId,
      rpcUrl: this.rpcUrl,
      networkPassphrase: this.networkPassphrase,
    });
    const challenge = bindingChallenge({
      spec: specOf(wallet),
      networkPassphrase: this.networkPassphrase,
      contractId,
      purpose,
      signer,
    });
    const prepared = await new PasskeySigner(keyId).sign(
      Buffer.from(challenge),
      this.signerContext()
    );
    if (
      prepared.key.tag !== "Secp256r1" ||
      prepared.value?.tag !== "Secp256r1" ||
      !bytesEqual(prepared.key.values[0], keyId)
    ) {
      throw new WalletOwnershipError(
        "The passkey returned a different credential for the binding proof",
        { contractId }
      );
    }

    const proof = prepared.value.values[0];
    const verified = await verifyStoredProof(
      {
        authenticatorData: proof.authenticator_data,
        clientDataJSON: proof.client_data_json,
        signature: proof.signature,
      },
      {
        expectedChallenge: challenge,
        rpId: this.rpId!,
        publicKey,
        allowedOrigins: this.allowedOrigins,
        requireUserVerification: this.requireUserVerification,
      }
    );
    if (!verified.ok) {
      throw new WalletOwnershipError(
        "The passkey binding proof failed local verification",
        { contractId, reason: verified.reason, detail: verified.detail }
      );
    }
    return proof;
  }

  /** Verify stored address consent and fresh passkey possession. */
  private async assertSignerProvenance(
    wallet: PasskeyClient,
    contractId: string,
    keyId: Buffer,
    signerVal: Extract<SignerVal, { tag: "Secp256r1" }>,
    freshResponse: AuthenticationResponseJSON,
    freshChallenge: Buffer
  ): Promise<void> {
    this.assertWebAuthnVerificationConfig();

    const record = (
      await wallet.get_secp256r1_binding({ key_id: keyId })
    ).result;
    if (!record) {
      throw new WalletOwnershipError(
        "Wallet has no signer binding record for the passkey",
        { contractId, keyId: base64url(keyId) }
      );
    }

    const publicKey = signerVal.values[0];
    const binding = await verifyBindingRecord(
      record,
      { keyId, publicKey },
      {
        spec: specOf(wallet),
        networkPassphrase: this.networkPassphrase,
        contractId,
        rpId: this.rpId!,
        allowedOrigins: this.allowedOrigins,
        requireUserVerification: this.requireUserVerification,
      }
    );
    if (!binding.ok) {
      throw new WalletOwnershipError(
        "Wallet signer binding record is invalid",
        { contractId, reason: binding.reason, detail: binding.detail }
      );
    }

    await this.assertFreshAssertion(
      contractId,
      keyId,
      signerVal,
      freshResponse,
      freshChallenge
    );
  }

  /** Verify one fresh WebAuthn assertion against the live signer key. */
  private async assertFreshAssertion(
    contractId: string,
    keyId: Buffer,
    signerVal: Extract<SignerVal, { tag: "Secp256r1" }>,
    freshResponse: AuthenticationResponseJSON,
    freshChallenge: Buffer
  ): Promise<void> {
    this.assertWebAuthnVerificationConfig();

    const publicKey = signerVal.values[0];
    const fresh = await verifyFreshAssertion(freshResponse, {
      expectedChallenge: freshChallenge,
      expectedKeyId: keyId,
      rpId: this.rpId!,
      publicKey,
      allowedOrigins: this.allowedOrigins,
      requireUserVerification: this.requireUserVerification,
    });
    if (!fresh.ok) {
      throw new WalletOwnershipError(
        "Fresh passkey assertion is invalid",
        { contractId, reason: fresh.reason, detail: fresh.detail }
      );
    }
  }

  private assertWebAuthnVerificationConfig(): void {
    if (!this.rpId) {
      throw new ConfigurationError(
        "rpId is required to verify signer provenance outside a browser",
        PasskeyKitErrorCode.INVALID_CONFIG
      );
    }
    if (!this.allowedOrigins?.length) {
      throw new ConfigurationError(
        "allowedOrigins is required to verify signer provenance outside a browser",
        PasskeyKitErrorCode.INVALID_CONFIG
      );
    }
  }

  /** Disconnect the current wallet. */
  disconnect(): void {
    const contractId = this.contractId;
    this.wallet = undefined;
    this.keyId = undefined;
    if (contractId) {
      this.events.emit("walletDisconnected", { contractId });
    }
  }

  // -- Signing -----------------------------------------------------------------

  /** Sign a single auth entry (defaults to the connected passkey signer). */
  signAuthEntry(
    entry: xdr.SorobanAuthorizationEntry,
    signer?: Signer,
    options?: SignOptions
  ): Promise<xdr.SorobanAuthorizationEntry> {
    return this.signerManager.signAuthEntry(entry, signer, options);
  }

  /** Sign an assembled transaction's wallet auth entries. */
  sign<T>(
    txn: AssembledTransaction<T>,
    signer?: Signer,
    options?: SignOptions
  ): Promise<AssembledTransaction<T>> {
    return this.signerManager.sign(txn, signer, options);
  }

  /**
   * Sign a wallet-admin transaction produced by the dedicated builders
   * (`addSecp256r1`, `addEd25519`, `addPolicy`, `update*`, `remove`,
   * `upgrade`). Declares the wallet-reentry intent the generic `sign()` path
   * refuses by default.
   */
  signAdmin<T>(
    txn: AssembledTransaction<T>,
    signer?: Signer,
    options?: Omit<SignOptions, "allowWalletReentry">
  ): Promise<AssembledTransaction<T>> {
    return this.signerManager.signAdmin(txn, signer, options);
  }

  // -- Signer management -------------------------------------------------------

  async addSecp256r1(
    keyId: string | Uint8Array,
    publicKey: string | Uint8Array,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number
  ): Promise<WalletTx> {
    const contractId = this.contractId;
    if (!contractId) {
      throw new WalletNotConnectedError("add a Secp256r1 signer");
    }
    const publicKeyBytes =
      publicKey instanceof Uint8Array
        ? publicKey
        : base64url.toBuffer(publicKey);
    const contractSigner = buildSecp256r1Signer(
      keyId,
      publicKeyBytes,
      limits,
      store,
      expiration
    );
    const proof = await this.createBindingProof(
      contractId,
      contractSigner,
      "Add"
    );
    const tx = await this.signerManager.addSecp256r1(
      keyId,
      publicKey,
      limits,
      store,
      proof,
      expiration
    );

    const connectedRecord = this.keyId
      ? await this.credentialManager.getPasskey(this.keyId)
      : null;
    if (!connectedRecord) {
      throw new WalletOwnershipError(
        "The connected wallet has no verified birth record",
        { contractId }
      );
    }

    // The new signer uses the already verified immutable birth record. This
    // optimistic association remains safe because connectWallet still requires
    // a live signer, its ADD proof, and fresh passkey possession.
    await this.credentialManager.rememberPasskey({
      keyId: keyId instanceof Uint8Array ? base64url(Buffer.from(keyId)) : keyId,
      publicKey: publicKeyBytes,
      contractId,
      birthWasmHash: connectedRecord.birthWasmHash,
      creationTransactionHash: connectedRecord.creationTransactionHash,
      creationLedger: connectedRecord.creationLedger,
      createdAt: Date.now(),
    });

    return tx;
  }

  /**
   * Update a passkey signer's limits/storage/expiration. The public key is
   * re-read from the ledger — never caller- or indexer-supplied.
   */
  updateSecp256r1(
    keyId: string | Uint8Array,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number
  ): Promise<WalletTx> {
    return this.signerManager.updateSecp256r1(keyId, limits, store, expiration);
  }
  addEd25519(
    publicKey: string,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number
  ): Promise<WalletTx> {
    return this.signerManager.addEd25519(publicKey, limits, store, expiration);
  }
  updateEd25519(
    publicKey: string,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number
  ): Promise<WalletTx> {
    return this.signerManager.updateEd25519(publicKey, limits, store, expiration);
  }
  /**
   * Add a policy signer. Throws a `ValidationError` if the policy's `install`
   * hook adds wallet-authorized sub-invocations to the auth entry, unless
   * `options.allowInstallSubInvocations` is set.
   */
  addPolicy(
    policy: string,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number,
    options?: PolicySignerTxOptions
  ): Promise<WalletTx> {
    return this.signerManager.addPolicy(policy, limits, store, expiration, options);
  }
  updatePolicy(
    policy: string,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number
  ): Promise<WalletTx> {
    return this.signerManager.updatePolicy(policy, limits, store, expiration);
  }
  remove(signerKey: SignerKey): Promise<WalletTx> {
    return this.signerManager.remove(signerKey);
  }

  /** Build an `upgrade(new_wasm_hash)` transaction for the connected wallet. */
  upgrade(newWasmHash: Buffer | Uint8Array): Promise<WalletTx> {
    return this.signerManager.upgrade(newWasmHash);
  }

  /** Read a signer entry from the ledger (temporary before persistent). */
  getSigner(signerKey: SignerKey) {
    return this.signerManager.getSigner(signerKey);
  }

  /** Require a connected wallet, or throw. */
  requireWallet(): PasskeyClient {
    if (!this.wallet) {
      throw new WalletNotConnectedError();
    }
    return this.wallet;
  }
}
