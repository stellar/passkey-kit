/**
 * `PasskeyKit` — the browser-side facade for creating and using smart-wallet
 * accounts with WebAuthn passkeys.
 *
 * This is a ground-up rewrite of the old monolithic `kit.ts`. The signing
 * pipeline, WebAuthn ceremonies, deploy path, and signer writes now live in
 * dependency-injected managers ({@link CredentialManager}, {@link SignerManager},
 * {@link SubmissionManager}) wired here with late-bound closures. All Protocol-27
 * probe shims, dead commented experiments, and the legacy factory-address
 * fallback are gone — the kit targets stellar-sdk >= 16 and the current wallet.
 *
 * @packageDocumentation
 */

import { Keypair, xdr } from "@stellar/stellar-sdk";
import { Server } from "@stellar/stellar-sdk/rpc";
import {
  startAuthentication,
  startRegistration,
  type AuthenticationResponseJSON,
  type AuthenticatorSelectionCriteria,
} from "@simplewebauthn/browser";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import { Client as PasskeyClient } from "passkey-kit-sdk";
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
import { contractInstanceExists } from "./rpc-data.js";
import type { WalletTx } from "./kit/wallet-ops.js";

/** Configuration for a {@link PasskeyKit} client. */
export interface PasskeyKitConfig {
  /** Stellar RPC URL. */
  rpcUrl: string;
  /** Network passphrase. */
  networkPassphrase: string;
  /** Smart-wallet WASM hash (hex) used to deploy new wallets. */
  walletWasmHash: string;
  /**
   * Code identities (hex WASM hashes) accepted when connecting to a wallet whose
   * address came from an untrusted source — an indexer lookup or address
   * derivation. Defaults to `[walletWasmHash]`.
   *
   * Binding code identity is what makes a wallet's signer state meaningful: under
   * accepted code, a signer entry can only have been produced by logic that
   * required wallet authorization. Arbitrary code can write whatever signer entry
   * a client expects, so without this check a reverse lookup proves nothing.
   *
   * This is a list rather than a single value because a legitimately upgraded
   * wallet runs different code. Add each accepted hash as you roll upgrades out;
   * a wallet running code that is not listed will not connect from an untrusted
   * path. See `docs/security-deterministic-deployer.md`.
   */
  acceptedWasmHashes?: string[];
  /** WebAuthn Relying Party id (domain); defaults to the current origin. */
  rpId?: string;
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
  /** A specific keyId to connect (skips the discovery ceremony). */
  keyId?: string | Uint8Array;
  /** Indexer-backed keyId → contract lookup, used when derivation misses. */
  getContractId?: (keyId: string) => Promise<string | undefined>;
  /**
   * Override the code-identity check against {@link PasskeyKitConfig.acceptedWasmHashes}.
   *
   * Defaults to ON whenever the address was resolved from an untrusted source
   * (indexer lookup or derivation) and OFF when it came from trusted local
   * storage, where a legitimately upgraded wallet would otherwise be locked out.
   *
   * Set `true` to check even a storage-resolved address; set `false` to skip the
   * check entirely. Disabling it means a reverse lookup can resolve to a contract
   * that merely claims this credential — only do so if you bind code identity
   * yourself.
   */
  verifyWasmHash?: boolean;
}

export class PasskeyKit {
  readonly rpc: Server;
  readonly rpcUrl: string;
  readonly networkPassphrase: string;
  readonly walletWasmHash: string;
  /** Accepted code identities, lowercase hex. Never empty. */
  readonly acceptedWasmHashes: readonly string[];
  readonly rpId?: string;

  /** Lifecycle event emitter (walletCreated, walletConnected, …). */
  readonly events = new PasskeyEventEmitter();

  private readonly timeoutInSeconds: number;
  private readonly webAuthn: WebAuthnClient;

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
    this.rpId = config.rpId;
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
   * Register a passkey and deploy a smart wallet initialized with it as the
   * first signer. Returns the authorized deploy carrier (submit it via
   * `PasskeyServer`).
   */
  async createWallet(
    appName: string,
    userName: string,
    options?: CreateOptions
  ): Promise<CreateWalletResult> {
    const created = await this.createKey(appName, userName, options);

    const deployTx = await this.submissionManager.buildDeployTransaction(
      created.keyIdBuffer,
      created.publicKey
    );
    const contractId = deployTx.result.options.contractId;

    this.wallet = new PasskeyClient({
      contractId,
      rpcUrl: this.rpcUrl,
      networkPassphrase: this.networkPassphrase,
    });
    this.keyId = created.keyId;

    const signedTx = await this.submissionManager.signDeploy(deployTx);

    await this.credentialManager.rememberPasskey({
      keyId: created.keyId,
      publicKey: created.publicKey,
      contractId,
      createdAt: Date.now(),
    });

    this.events.emit("walletCreated", { contractId, keyId: created.keyId });

    return {
      rawResponse: created.rawResponse,
      keyId: created.keyIdBuffer,
      keyIdBase64: created.keyId,
      contractId,
      signedTx,
    };
  }

  /**
   * Connect an existing wallet from a passkey.
   *
   * Resolves the wallet address by (1) local storage, (2) an injected indexer
   * lookup, then (3) deterministic derivation from the keyId — and then VERIFIES
   * ownership: the keyId must resolve to a live signer on the wallet (#601 F7).
   * This closes the unverified reverse-lookup hole (#598 F3) at the SDK layer.
   * Derivation is deliberately last: it is only correct for a wallet's first
   * credential and is the one path a squatted contract can hijack.
   *
   * @throws {WalletOwnershipError} If the keyId is not a signer on the wallet.
   */
  async connectWallet(options?: ConnectOptions): Promise<ConnectWalletResult> {
    let rawResponse: AuthenticationResponseJSON | undefined;
    let keyId = options?.keyId;

    if (!keyId) {
      const auth = await this.credentialManager.authenticate();
      keyId = auth.keyId;
      rawResponse = auth.rawResponse;
    }

    const keyIdBase64 =
      keyId instanceof Uint8Array ? base64url(Buffer.from(keyId)) : keyId;
    const keyIdBuffer =
      keyId instanceof Uint8Array ? Buffer.from(keyId) : base64url.toBuffer(keyId);

    // Resolve the wallet address. Deterministic derivation is authoritative
    // ONLY for a wallet's first credential (the one whose keyId salted the
    // deploy); for every later signer `derive(keyId)` points at an address that
    // is never legitimately deployed, and is the one resolution path an attacker
    // can poison by squatting code at that derived address. So trusted state
    // wins and derivation is a last-resort hint, confirmed by an on-chain read:
    //   1) local storage, 2) injected indexer lookup, 3) derivation.
    // The keyId is still verified as a live signer below (F7), so a stale hint
    // can never connect to a wallet the passkey does not actually control.
    let contractId = await this.credentialManager.lookupContractId(keyIdBase64);
    // Whether the address came from trusted local state. An indexer row or a
    // derived address is a CLAIM by an untrusted party: any contract can emit
    // the signer events an indexer keys on, and any contract can write the
    // signer ledger entry we read back. Both are checked against accepted code
    // identity below; trusted state is not, so an upgraded wallet still opens.
    const fromTrustedState = contractId !== undefined;
    if (!contractId && options?.getContractId) {
      contractId = await options.getContractId(keyIdBase64);
    }
    if (!contractId) {
      // Transport errors (429/5xx/timeout) propagate — only an authoritative
      // not-found leaves the derived address unresolved.
      const derived = this.submissionManager.deriveWalletAddress(keyIdBuffer);
      if (await contractInstanceExists(this.rpc, derived)) {
        contractId = derived;
      }
    }

    if (!contractId) {
      throw new PasskeyKitError(
        "Could not resolve a wallet for the given passkey",
        PasskeyKitErrorCode.WALLET_NOT_FOUND,
        { context: { keyId: keyIdBase64 } }
      );
    }

    this.wallet = new PasskeyClient({
      contractId,
      rpcUrl: this.rpcUrl,
      networkPassphrase: this.networkPassphrase,
    });
    this.keyId = keyIdBase64;

    // 3) Code identity FIRST, then signer state — the ordering matters. A signer
    // entry only means "this passkey was authorized onto this wallet" if the code
    // that wrote it enforced authorization; under arbitrary code it means nothing.
    // So bind accepted code before reading any signer state from the contract.
    if (options?.verifyWasmHash ?? !fromTrustedState) {
      try {
        await this.assertWalletWasmHash(contractId);
      } catch (err) {
        this.wallet = undefined;
        this.keyId = undefined;
        throw err;
      }
    }

    // 4) Ownership verification (F7): the keyId must be a live signer.
    // A thrown error here is a transport failure, not proof of non-ownership —
    // surface it as-is (a valid passkey must not read as an ownership mismatch
    // because the RPC hiccuped); only a definitive not-found (`null`) does.
    let signerVal;
    try {
      signerVal = await this.signerManager.getSigner(
        SignerKey.Secp256r1(keyIdBase64)
      );
    } catch (err) {
      this.wallet = undefined;
      this.keyId = undefined;
      throw err;
    }
    if (!signerVal) {
      this.wallet = undefined;
      this.keyId = undefined;
      throw new WalletOwnershipError(
        "The passkey is not a signer on the resolved wallet",
        { contractId, keyId: keyIdBase64 }
      );
    }

    this.events.emit("walletConnected", { contractId, keyId: keyIdBase64 });

    return { rawResponse, keyId: keyIdBuffer, keyIdBase64, contractId };
  }

  private async assertWalletWasmHash(contractId: string): Promise<void> {
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
    const wasmHash = executable.wasmHash().toString("hex");
    if (!this.acceptedWasmHashes.includes(wasmHash)) {
      throw new WalletOwnershipError("Wallet code identity is not accepted", {
        contractId,
        accepted: this.acceptedWasmHashes,
        actual: wasmHash,
      });
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

  // -- Signer management -------------------------------------------------------

  async addSecp256r1(
    keyId: string | Uint8Array,
    publicKey: string | Uint8Array,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number
  ): Promise<WalletTx> {
    const tx = await this.signerManager.addSecp256r1(
      keyId,
      publicKey,
      limits,
      store,
      expiration
    );

    // Persist the keyId → wallet mapping so a later connectWallet(keyId) resolves
    // this wallet from trusted storage instead of derivation (derive(keyId) of a
    // secondary passkey is a squattable address). Without this record a pure-SDK
    // consumer has nothing but derivation to fall back on for a second signer.
    // ponytail: optimistic — written at build time, before the caller submits.
    // If the add tx never lands the keyId is not a signer anywhere, so the F7
    // ownership check in connectWallet rejects the stale hint rather than
    // mis-binding. Requires a connected wallet (add_signer is wallet-authorized).
    const contractId = this.contractId;
    if (contractId) {
      await this.credentialManager.rememberPasskey({
        keyId: keyId instanceof Uint8Array ? base64url(Buffer.from(keyId)) : keyId,
        publicKey:
          publicKey instanceof Uint8Array
            ? publicKey
            : base64url.toBuffer(publicKey),
        contractId,
        createdAt: Date.now(),
      });
    }

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
  addPolicy(
    policy: string,
    limits: SignerLimits,
    store: SignerStore,
    expiration?: number
  ): Promise<WalletTx> {
    return this.signerManager.addPolicy(policy, limits, store, expiration);
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
