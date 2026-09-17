/**
 * Typed error model for the Passkey Kit SDK.
 *
 * Every error the kit throws is a {@link PasskeyKitError} (or subclass) carrying
 * a numeric {@link PasskeyKitErrorCode}, optional structured `context`, and an
 * optional `cause`. Callers branch on `error.code` (or `instanceof`) instead of
 * matching on message strings.
 *
 * Submission methods are the one exception to "throw on failure": they return a
 * discriminated {@link import("./types.js").TransactionResult} whose failure arm
 * carries one of these typed errors (see `contract-errors.ts`).
 *
 * @packageDocumentation
 */

/**
 * Error codes for Passkey Kit operations, grouped by concern.
 *
 * Ranges (per SDK architecture spec #599 §5, extended with validation/storage):
 * - 1xxx configuration
 * - 2xxx wallet state
 * - 3xxx WebAuthn
 * - 4xxx signing
 * - 5xxx transaction (simulation/submission)
 * - 6xxx indexer
 * - 7xxx relayer
 * - 8xxx validation
 * - 9xxx storage
 * - 10000 contract-level failure decoded from on-chain diagnostics (the raw
 *   contract code 1-9 is carried separately on {@link ContractError}).
 */
export enum PasskeyKitErrorCode {
  // Configuration (1xxx)
  INVALID_CONFIG = 1001,
  MISSING_CONFIG = 1002,

  // Wallet state (2xxx)
  WALLET_NOT_CONNECTED = 2001,
  WALLET_ALREADY_EXISTS = 2002,
  WALLET_NOT_FOUND = 2003,
  WALLET_OWNERSHIP_MISMATCH = 2004,
  WALLET_AMBIGUOUS = 2005,
  /** The wallet runs pre-1.0 contract code; see {@link LegacyWalletError}. */
  WALLET_LEGACY_CODE = 2006,

  // WebAuthn (3xxx)
  WEBAUTHN_REGISTRATION_FAILED = 3001,
  WEBAUTHN_AUTHENTICATION_FAILED = 3002,
  WEBAUTHN_NOT_SUPPORTED = 3003,
  WEBAUTHN_CANCELLED = 3004,
  PUBLIC_KEY_EXTRACTION_FAILED = 3005,

  // Signing (4xxx)
  SIGNING_FAILED = 4001,
  SIGNER_NOT_FOUND = 4002,
  INVALID_SIGNER = 4003,
  INVALID_SIGNATURE_EXPIRATION = 4004,
  UNSUPPORTED_CREDENTIALS = 4005,

  // Transaction (5xxx)
  SIMULATION_FAILED = 5001,
  SUBMISSION_FAILED = 5002,
  TRANSACTION_TIMEOUT = 5003,
  RESTORE_REQUIRED = 5004,

  // Indexer (6xxx)
  INDEXER_NOT_CONFIGURED = 6001,
  INDEXER_REQUEST_FAILED = 6002,

  // Relayer (7xxx)
  RELAYER_NOT_CONFIGURED = 7001,
  RELAYER_REQUEST_FAILED = 7002,
  /** Submitted but not yet in a terminal state — keep polling getTransaction. */
  RELAYER_PENDING = 7003,

  // Validation (8xxx)
  INVALID_ADDRESS = 8001,
  INVALID_AMOUNT = 8002,
  INVALID_INPUT = 8003,
  INVALID_PUBLIC_KEY = 8004,

  // Storage (9xxx)
  STORAGE_READ_FAILED = 9001,
  STORAGE_WRITE_FAILED = 9002,

  // Contract-level failure decoded from on-chain diagnostics (10xxx).
  // The raw contract code (1-9) is carried separately on ContractError so the
  // SDK code space never collides with the contract's own small code range.
  CONTRACT_ERROR = 10000,
}

/**
 * Base error class for all Passkey Kit errors.
 */
export class PasskeyKitError extends Error {
  /** Error code for programmatic handling. */
  readonly code: PasskeyKitErrorCode;

  /** Structured context about the error. */
  readonly context?: Record<string, unknown>;

  /** The underlying error that caused this one, if any. */
  readonly cause?: Error;

  constructor(
    message: string,
    code: PasskeyKitErrorCode,
    options?: {
      context?: Record<string, unknown>;
      cause?: Error;
    }
  ) {
    super(message);
    this.name = "PasskeyKitError";
    this.code = code;
    this.context = options?.context;
    this.cause = options?.cause;

    // Maintain a proper stack trace in V8 environments.
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PasskeyKitError);
    }
  }

  /** Format the error with its code, context, and cause for logging. */
  toDetailedString(): string {
    let msg = `[${this.code}] ${this.message}`;
    if (this.context) {
      msg += `\nContext: ${JSON.stringify(this.context, null, 2)}`;
    }
    if (this.cause) {
      msg += `\nCaused by: ${this.cause.message}`;
    }
    return msg;
  }
}

/** Thrown when the client is misconfigured. */
export class ConfigurationError extends PasskeyKitError {
  constructor(
    message: string,
    code:
      | PasskeyKitErrorCode.INVALID_CONFIG
      | PasskeyKitErrorCode.MISSING_CONFIG = PasskeyKitErrorCode.INVALID_CONFIG,
    context?: Record<string, unknown>
  ) {
    super(message, code, { context });
    this.name = "ConfigurationError";
  }
}

/** Thrown when an operation requires a connected wallet but none is connected. */
export class WalletNotConnectedError extends PasskeyKitError {
  constructor(operation?: string) {
    super(
      operation
        ? `A connected wallet is required to ${operation}`
        : "Wallet not connected",
      PasskeyKitErrorCode.WALLET_NOT_CONNECTED,
      { context: operation ? { operation } : undefined }
    );
    this.name = "WalletNotConnectedError";
  }
}

/**
 * Thrown when a connected wallet does not actually own the credential used to
 * connect (connectWallet ownership verification, #601 F7).
 */
export class WalletOwnershipError extends PasskeyKitError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, PasskeyKitErrorCode.WALLET_OWNERSHIP_MISMATCH, { context });
    this.name = "WalletOwnershipError";
  }
}

/**
 * Thrown when a wallet runs pre-1.0 (legacy) contract code, which this kit
 * cannot operate. Two cases, distinguished by {@link LegacyWalletError.vulnerable}:
 *
 * - `vulnerable: true` — the code is one of the known-vulnerable builds whose
 *   `update_signer` has no authorization check. Anyone can take the wallet
 *   over. It must be upgraded in place to {@link upgradeTarget} (or drained)
 *   using the 0.10.20–0.12.x kit line; see {@link guideUrl}.
 * - `vulnerable: false` — the code is a patched legacy build. The wallet is
 *   safe but only the 0.10.20–0.12.x kit line can connect to it.
 */
export class LegacyWalletError extends PasskeyKitError {
  /** The wallet's current code hash (hex). */
  readonly wasmHash: string;
  /** Whether the code has the unauthenticated `update_signer` defect. */
  readonly vulnerable: boolean;
  /** WASM hash to upgrade to in place (safe for every legacy layout). */
  readonly upgradeTarget: string;
  /** Operator guide for the upgrade. */
  readonly guideUrl: string;

  constructor(options: {
    contractId: string;
    wasmHash: string;
    vulnerable: boolean;
    upgradeTarget: string;
    guideUrl: string;
  }) {
    const { contractId, wasmHash, vulnerable, upgradeTarget, guideUrl } = options;
    const message = vulnerable
      ? `Wallet ${contractId} runs known-vulnerable legacy code ${wasmHash.slice(0, 8)}…: ` +
        `its update_signer has no authorization check, so anyone can take the wallet over. ` +
        `Upgrade it in place to ${upgradeTarget}: this kit builds and signs that call ` +
        `(kit.buildLegacyUpgradeTx, kit.signLegacyUpgradeTx, then kit.buildLegacyMigrateTx ` +
        `for the oldest layout), or use the passkey-kit 0.10.20–0.12.x line; or move its ` +
        `funds out. This kit version cannot connect to it. Guide: ${guideUrl}`
      : `Wallet ${contractId} runs patched legacy code ${wasmHash.slice(0, 8)}…, ` +
        `which this kit version cannot connect to. Operate it with the passkey-kit ` +
        `0.10.20–0.12.x line (kit.inspectLegacyWallet describes its state). Guide: ${guideUrl}`;
    super(message, PasskeyKitErrorCode.WALLET_LEGACY_CODE, {
      context: { contractId, wasmHash, vulnerable, upgradeTarget, guideUrl },
    });
    this.name = "LegacyWalletError";
    this.wasmHash = wasmHash;
    this.vulnerable = vulnerable;
    this.upgradeTarget = upgradeTarget;
    this.guideUrl = guideUrl;
  }
}

/** Thrown when more than one verified wallet contains the connecting passkey. */
export class WalletAmbiguousError extends PasskeyKitError {
  /** Every candidate that passed the configured wallet checks. */
  readonly candidates: readonly string[];

  constructor(candidates: readonly string[]) {
    super(
      "More than one verified wallet contains the given passkey",
      PasskeyKitErrorCode.WALLET_AMBIGUOUS,
      { context: { candidates: [...candidates] } }
    );
    this.name = "WalletAmbiguousError";
    this.candidates = [...candidates];
  }
}

/** Thrown when a WebAuthn ceremony fails. */
export class WebAuthnError extends PasskeyKitError {
  constructor(
    message: string,
    code:
      | PasskeyKitErrorCode.WEBAUTHN_REGISTRATION_FAILED
      | PasskeyKitErrorCode.WEBAUTHN_AUTHENTICATION_FAILED
      | PasskeyKitErrorCode.WEBAUTHN_NOT_SUPPORTED
      | PasskeyKitErrorCode.WEBAUTHN_CANCELLED
      | PasskeyKitErrorCode.PUBLIC_KEY_EXTRACTION_FAILED,
    cause?: Error
  ) {
    super(message, code, { cause });
    this.name = "WebAuthnError";
  }
}

/** Thrown when signing an authorization entry fails. */
export class SigningError extends PasskeyKitError {
  constructor(
    message: string,
    code:
      | PasskeyKitErrorCode.SIGNING_FAILED
      | PasskeyKitErrorCode.INVALID_SIGNER
      | PasskeyKitErrorCode.INVALID_SIGNATURE_EXPIRATION
      | PasskeyKitErrorCode.UNSUPPORTED_CREDENTIALS = PasskeyKitErrorCode.SIGNING_FAILED,
    context?: Record<string, unknown>
  ) {
    super(message, code, { context });
    this.name = "SigningError";
  }
}

/** Thrown when a requested signer cannot be found. */
export class SignerNotFoundError extends PasskeyKitError {
  constructor(identifier: string, hint?: string) {
    super(
      hint
        ? `No signer found for: ${identifier}. ${hint}`
        : `No signer found for: ${identifier}`,
      PasskeyKitErrorCode.SIGNER_NOT_FOUND,
      { context: { identifier } }
    );
    this.name = "SignerNotFoundError";
  }
}

/** Thrown when transaction simulation fails. */
export class SimulationError extends PasskeyKitError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, PasskeyKitErrorCode.SIMULATION_FAILED, { context });
    this.name = "SimulationError";
  }
}

/** Thrown when transaction submission fails. */
export class SubmissionError extends PasskeyKitError {
  constructor(message: string, hash?: string, context?: Record<string, unknown>) {
    super(message, PasskeyKitErrorCode.SUBMISSION_FAILED, {
      context: { hash, ...context },
    });
    this.name = "SubmissionError";
  }
}

/** Thrown when input validation fails. */
export class ValidationError extends PasskeyKitError {
  constructor(
    message: string,
    code:
      | PasskeyKitErrorCode.INVALID_ADDRESS
      | PasskeyKitErrorCode.INVALID_AMOUNT
      | PasskeyKitErrorCode.INVALID_INPUT
      | PasskeyKitErrorCode.INVALID_PUBLIC_KEY = PasskeyKitErrorCode.INVALID_INPUT,
    context?: Record<string, unknown>
  ) {
    super(message, code, { context });
    this.name = "ValidationError";
  }
}

/** Thrown when an indexer request fails or the indexer is not configured. */
export class IndexerError extends PasskeyKitError {
  constructor(
    message: string,
    code:
      | PasskeyKitErrorCode.INDEXER_NOT_CONFIGURED
      | PasskeyKitErrorCode.INDEXER_REQUEST_FAILED = PasskeyKitErrorCode.INDEXER_REQUEST_FAILED,
    context?: Record<string, unknown>,
    cause?: Error
  ) {
    super(message, code, { context, cause });
    this.name = "IndexerError";
  }
}

/** Thrown when a relayer request fails or the relayer is not configured. */
export class RelayerError extends PasskeyKitError {
  constructor(
    message: string,
    code:
      | PasskeyKitErrorCode.RELAYER_NOT_CONFIGURED
      | PasskeyKitErrorCode.RELAYER_REQUEST_FAILED
      | PasskeyKitErrorCode.RELAYER_PENDING = PasskeyKitErrorCode.RELAYER_REQUEST_FAILED,
    context?: Record<string, unknown>,
    cause?: Error
  ) {
    super(message, code, { context, cause });
    this.name = "RelayerError";
  }
}

/**
 * Error decoded from an on-chain smart-wallet failure code.
 *
 * Produced by `decodeContractError` when a simulation/submission diagnostic
 * reports an `Error(Contract, #N)`. Carries the raw contract code and its enum
 * variant name so callers can branch on the exact failure.
 *
 * @example
 * ```typescript
 * const result = await server.send(tx);
 * if (!result.success && result.error instanceof ContractError) {
 *   if (result.error.contractErrorName === "SignerExpired") { ... }
 * }
 * ```
 */
export class ContractError extends PasskeyKitError {
  /** Raw contract error code (e.g. 4). */
  readonly contractCode: number;

  /** Enum variant name from the contract (e.g. "SignerExpired"). */
  readonly contractErrorName: string;

  /** Contract family the code belongs to (e.g. "SmartWallet"). */
  readonly family: string;

  constructor(
    contractCode: number,
    contractErrorName: string,
    family: string,
    message: string,
    options?: {
      context?: Record<string, unknown>;
      cause?: Error;
    }
  ) {
    super(message, PasskeyKitErrorCode.CONTRACT_ERROR, {
      context: { contractCode, contractErrorName, family, ...options?.context },
      cause: options?.cause,
    });
    this.name = "ContractError";
    this.contractCode = contractCode;
    this.contractErrorName = contractErrorName;
    this.family = family;
  }
}

/**
 * Wrap an unknown thrown value in a {@link PasskeyKitError}.
 *
 * Passes through values that are already {@link PasskeyKitError}s.
 */
export function wrapError(
  err: unknown,
  defaultCode: PasskeyKitErrorCode = PasskeyKitErrorCode.INVALID_INPUT
): PasskeyKitError {
  if (err instanceof PasskeyKitError) {
    return err;
  }

  const message = err instanceof Error ? err.message : String(err);
  const cause = err instanceof Error ? err : undefined;

  return new PasskeyKitError(message, defaultCode, { cause });
}
