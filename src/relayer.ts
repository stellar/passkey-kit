/**
 * Server-side relayer client.
 *
 * A thin, typed wrapper over the OpenZeppelin Channels HTTP API for
 * fee-sponsored submission.
 * It holds the relayer API key, so it MUST run server-side only (it is reached
 * through `PasskeyServer`, exported from the `passkey-kit/server` subpath).
 *
 * Two submission modes:
 * - {@link RelayerClient.send} — `{ func, auth }` for invokeHostFunction flows
 *   (the preferred Soroban path; the relayer builds the envelope + pays fees).
 * - {@link RelayerClient.sendTransaction} — `{ xdr }` for a signed envelope
 *   (e.g. a custom-deployer transaction that needs a fee bump).
 *
 * Every method returns a discriminated {@link TransactionResult} and NEVER
 * throws for expected relayer/on-chain failures — a `PluginClientError` is
 * mapped to a typed {@link RelayerError} (or a {@link ContractError} when a
 * contract code can be decoded from its details).
 *
 * @packageDocumentation
 */

import type { TransactionResult, TransactionFailure } from "./types.js";
import { RelayerError, PasskeyKitErrorCode } from "./errors.js";
import {
  decodeContractError,
  failedTransaction,
} from "./contract-errors.js";
import { DEFAULT_RELAYER_TIMEOUT_MS } from "./constants.js";

/** Configuration for a {@link RelayerClient}. */
export interface RelayerClientConfig {
  /** Base URL of the Channels relayer service. */
  baseUrl: string;
  /** API key for the relayer service (server-side secret). */
  apiKey: string;
  /** Optional admin secret for management operations. */
  adminSecret?: string;
  /** Request timeout in ms (default {@link DEFAULT_RELAYER_TIMEOUT_MS}). */
  timeout?: number;
}

/** Per-submission relayer options. */
export interface RelayerSubmitOptions {
  /** Return immediately after submission; poll {@link RelayerClient.getTransaction}. */
  skipWait?: boolean;
  /** Alternative fund-relayer id for the fee bump (must be allow-listed). */
  fundRelayerId?: string;
}

/**
 * Terminal-success statuses (ALLOWLIST). Only a status that positively confirms
 * on-chain inclusion counts as success — anything else is failure or still
 * pending. An allowlist (not a failure denylist) is deliberate: an unrecognized
 * or non-terminal status must never be mistaken for a confirmed transaction.
 * Word-bounded so negated forms ("unsuccessful", "unconfirmed") and
 * non-terminal forms ("confirming") never match. Keep identical to
 * relayer-proxy/src/constants.ts.
 */
const SUCCESS_STATUS = /\b(?:confirm(?:ed)?|success(?:ful)?)\b/i;

/** Terminal-failure statuses. */
const FAILURE_STATUS = /fail|error|revert|reject/i;

interface ChannelsTransactionResponse {
  transactionId: string | null;
  hash: string | null;
  status: string | null;
}

type ChannelsRequest =
  | {
      xdr: string;
      skipWait?: boolean;
      fundRelayerId?: string;
    }
  | {
      func: string;
      auth: string[];
      skipWait?: boolean;
      fundRelayerId?: string;
    }
  | { getTransaction: { transactionId: string } };

interface ChannelsResponse {
  success: boolean;
  data?: unknown;
  error?: unknown;
  metadata?: unknown;
}

class ChannelsClientError extends Error {
  constructor(
    message: string,
    readonly category: "transport" | "execution" | "client",
    readonly errorDetails?: unknown,
    cause?: unknown
  ) {
    super(message, cause instanceof Error ? { cause } : undefined);
    this.name = "ChannelsClientError";
  }
}

/** Direct client for the managed Channels HTTP endpoint. */
class ChannelsClient {
  private readonly endpoint: string;
  private readonly apiKey: string;
  private readonly timeout: number;

  constructor(config: RelayerClientConfig) {
    let endpointEnd = config.baseUrl.length;
    while (endpointEnd > 0 && config.baseUrl[endpointEnd - 1] === "/") {
      endpointEnd -= 1;
    }
    this.endpoint = `${config.baseUrl.slice(0, endpointEnd)}/`;
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? DEFAULT_RELAYER_TIMEOUT_MS;
  }

  submitSorobanTransaction(
    request: Extract<ChannelsRequest, { func: string }>
  ): Promise<ChannelsTransactionResponse> {
    return this.call(request);
  }

  submitTransaction(
    request: Extract<ChannelsRequest, { xdr: string }>
  ): Promise<ChannelsTransactionResponse> {
    return this.call(request);
  }

  getTransaction(request: {
    transactionId: string;
  }): Promise<ChannelsTransactionResponse> {
    return this.call({ getTransaction: request });
  }

  private async call(
    params: ChannelsRequest
  ): Promise<ChannelsTransactionResponse> {
    let response: Response;
    try {
      response = await fetch(this.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({ params }),
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (error) {
      throw new ChannelsClientError(
        `Network error: ${error instanceof Error ? error.message : String(error)}`,
        "transport",
        undefined,
        error
      );
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (error) {
      const category = error instanceof SyntaxError ? "client" : "transport";
      throw new ChannelsClientError(
        category === "client"
          ? `Malformed response from relayer (HTTP ${response.status})`
          : `Network error while reading relayer response: ${
              error instanceof Error ? error.message : String(error)
            }`,
        category,
        undefined,
        error
      );
    }

    if (
      !body ||
      typeof body !== "object" ||
      !("success" in body) ||
      typeof (body as { success?: unknown }).success !== "boolean"
    ) {
      throw new ChannelsClientError(
        `Malformed response from relayer (HTTP ${response.status})`,
        "client",
        body
      );
    }

    const result = body as ChannelsResponse;
    if (!result.success) {
      const details = result.metadata
        ? {
            ...(result.data && typeof result.data === "object"
              ? result.data
              : {}),
            metadata: result.metadata,
          }
        : result.data;
      throw new ChannelsClientError(
        typeof result.error === "string" && result.error.trim()
          ? result.error
          : "Relayer execution failed",
        "execution",
        details
      );
    }

    if (!result.data || typeof result.data !== "object") {
      throw new ChannelsClientError(
        "Malformed response from relayer: missing data",
        "client",
        body
      );
    }

    return result.data as ChannelsTransactionResponse;
  }
}

export class RelayerClient {
  private readonly channels: ChannelsClient;

  constructor(config: RelayerClientConfig) {
    if (!config.baseUrl || !config.apiKey) {
      throw new RelayerError(
        "RelayerClient requires both baseUrl and apiKey",
        PasskeyKitErrorCode.RELAYER_NOT_CONFIGURED
      );
    }
    this.channels = new ChannelsClient({
      baseUrl: config.baseUrl,
      apiKey: config.apiKey,
      adminSecret: config.adminSecret,
      timeout: config.timeout ?? DEFAULT_RELAYER_TIMEOUT_MS,
    });
  }

  /**
   * Submit an invokeHostFunction via `{ func, auth }` (the preferred Soroban
   * path). The relayer builds the transaction envelope with a channel account
   * and pays the fees.
   */
  async send(
    func: string,
    auth: string[],
    options?: RelayerSubmitOptions
  ): Promise<TransactionResult> {
    return this.run(() =>
      this.channels.submitSorobanTransaction({
        func,
        auth,
        skipWait: options?.skipWait,
        fundRelayerId: options?.fundRelayerId,
      })
    );
  }

  /**
   * Submit a signed transaction envelope via `{ xdr }` for a fee bump (preserves
   * the inner signature; use for custom-source / source-account-auth flows).
   */
  async sendTransaction(
    xdr: string,
    options?: RelayerSubmitOptions
  ): Promise<TransactionResult> {
    return this.run(() =>
      this.channels.submitTransaction({
        xdr,
        skipWait: options?.skipWait,
        fundRelayerId: options?.fundRelayerId,
      })
    );
  }

  /** Poll a previously-submitted (`skipWait`) transaction by its relayer id. */
  async getTransaction(transactionId: string): Promise<TransactionResult> {
    return this.run(() => this.channels.getTransaction({ transactionId }));
  }

  private async run(
    fn: () => Promise<ChannelsTransactionResponse>
  ): Promise<TransactionResult> {
    try {
      return this.toResult(await fn());
    } catch (err) {
      return this.mapError(err);
    }
  }

  private toResult(res: ChannelsTransactionResponse): TransactionResult {
    const status = res.status ?? "";

    if (SUCCESS_STATUS.test(status)) {
      return {
        success: true,
        hash: res.hash ?? "",
        ...(res.transactionId ? { transactionId: res.transactionId } : {}),
      };
    }

    if (FAILURE_STATUS.test(status)) {
      return failedTransaction(
        new RelayerError(
          `Relayer reported status "${res.status}"`,
          PasskeyKitErrorCode.RELAYER_REQUEST_FAILED,
          { status: res.status, transactionId: res.transactionId }
        ),
        res.hash ?? undefined
      );
    }

    // Neither terminal-success nor terminal-failure: the transaction is still
    // pending (e.g. a `skipWait` submit not yet polled to confirmation). Surface
    // it as a distinct, NON-success result carrying RELAYER_PENDING — never as
    // `success: true` — so a poll loop keeps polling instead of treating an
    // unconfirmed (or later-reverted) transaction as done.
    return failedTransaction(
      new RelayerError(
        `Relayer status "${res.status ?? "unknown"}" is not terminal (pending)`,
        PasskeyKitErrorCode.RELAYER_PENDING,
        { status: res.status, transactionId: res.transactionId, pending: true }
      ),
      res.hash ?? undefined
    );
  }

  private mapError(err: unknown): TransactionFailure {
    // Prefer a decoded contract error when the relayer surfaced one.
    const details =
      err instanceof ChannelsClientError ? err.errorDetails : undefined;
    const contractError =
      (err instanceof Error && decodeContractError(err.message)) ||
      decodeContractError(details);
    if (contractError) {
      return failedTransaction(contractError);
    }

    if (err instanceof ChannelsClientError) {
      return failedTransaction(
        new RelayerError(
          err.message,
          PasskeyKitErrorCode.RELAYER_REQUEST_FAILED,
          { category: err.category, details },
          err
        )
      );
    }

    return failedTransaction(
      new RelayerError(
        err instanceof Error ? err.message : String(err),
        PasskeyKitErrorCode.RELAYER_REQUEST_FAILED,
        undefined,
        err instanceof Error ? err : undefined
      )
    );
  }
}
