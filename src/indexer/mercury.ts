/**
 * Mercury hosted passkey-indexer backend.
 *
 * Queries Mercury's public, **keyless** passkey-indexer REST API — no JWT, no
 * API key — which indexes passkey-kit smart-wallet signers on both networks with
 * full history across both signer generations (legacy `("sw_v1", …)` tuple
 * events and the v1 typed `#[contractevent]`s). The endpoint returns fully
 * decoded signer rows, so this backend maps JSON straight onto {@link WalletSigner}
 * with no XDR round-trip.
 *
 * Base URLs (see {@link mercuryPasskeyIndexerUrl}):
 *   `https://{testnet,mainnet}.mercurydata.app/rest/passkey-indexer`
 *     GET /                              -> `{ service, status }` health
 *     GET /api/wallet/:contractId        -> signers (this backend's getSigners)
 *     GET /api/lookup/:credentialId      -> wallets by passkey keyId (hex)
 *     GET /api/lookup/address/:address   -> wallets by ed25519 (G…) / policy (C…)
 *     GET /api/stats                     -> indexer statistics
 *
 * Docs: https://docs.mercurydata.app/smart-wallet-indexers/introduction-1
 *
 * @packageDocumentation
 */

import { Networks } from "@stellar/stellar-sdk";
import { Durability, type Server } from "@stellar/stellar-sdk/rpc";
import { SignerKey, type SignerLimits } from "../types.js";
import { IndexerError, PasskeyKitErrorCode } from "../errors.js";
import {
  DEFAULT_INDEXER_TIMEOUT_MS,
  MERCURY_PASSKEY_INDEXER_URLS,
} from "../constants.js";
import { getSigner } from "../kit/wallet-ops.js";
import { contractDataExists } from "../rpc-data.js";
import base64url from "../base64url.js";
import type {
  FindWalletsHardeningDeps,
  IncompleteWalletCandidate,
  IndexerHealth,
  SignerIndexer,
  WalletCandidate,
  WalletCandidateLookup,
  WalletSigner,
} from "./types.js";
import { signerKeyToContractScVal, walletSpec } from "./codec.js";

/**
 * Resolve the hosted passkey-indexer base URL for a network. Mercury indexes
 * both testnet and mainnet; any other network returns `undefined` (no hosted
 * endpoint — pass an explicit `url` to point at a self-hosted instance).
 */
export function mercuryPasskeyIndexerUrl(
  networkPassphrase: string
): string | undefined {
  if (networkPassphrase === Networks.PUBLIC)
    return MERCURY_PASSKEY_INDEXER_URLS.mainnet;
  if (networkPassphrase === Networks.TESTNET)
    return MERCURY_PASSKEY_INDEXER_URLS.testnet;
  return undefined;
}

/** A signer key as rendered by the passkey-indexer JSON. */
interface PasskeyIndexerKeyJson {
  type: "secp256r1" | "ed25519" | "policy";
  /**
   * Lowercase hex credential id (secp256r1), `G…` strkey (ed25519), or `C…`
   * strkey (policy).
   */
  value: string;
}

/** A signer row from `GET /api/wallet/:contractId`. */
interface PasskeyIndexerSignerJson {
  key: PasskeyIndexerKeyJson;
  /** 65-byte SEC-1 uncompressed secp256r1 pubkey, lowercase hex (secp only). */
  publicKey?: string;
  /** Raw on-chain expiration; unit per `expiration_unit`. Absent = never. */
  expiration?: number;
  /** `"unix"` (v1, seconds) or `"ledger"` (legacy, ledger sequence). */
  expiration_unit?: "unix" | "ledger";
  /**
   * Per-contract limits. Absent = unlimited (contract `None`); `{}` = deny-all
   * (contract `Some(empty)`); `{ "C…": null }` = any key on that contract;
   * `{ "C…": [key, …] }` = scoped to those keys.
   */
  limits?: Record<string, PasskeyIndexerKeyJson[] | null>;
  storage: "persistent" | "temporary";
  status: "live" | "expired" | "removed";
}

/** Response from `GET /api/wallet/:contractId`. */
interface PasskeyIndexerWalletResponse {
  contractId: string;
  generation: "legacy" | "v1";
  signers: PasskeyIndexerSignerJson[];
}

export interface MercuryIndexerConfig {
  /**
   * Hosted passkey-indexer base URL, e.g.
   * `https://testnet.mercurydata.app/rest/passkey-indexer`. Keyless (public
   * REST). Prefer {@link MercuryIndexer.forNetwork} to resolve this per network.
   */
  url: string;
  /**
   * RPC server — enables the temporary-signer eviction probe and lets
   * `findWallets` confirm reverse-lookup candidates on-chain.
   */
  rpc?: Server;
  /**
   * @deprecated Derivation no longer confirms wallet ownership. Configure `rpc`.
   */
  hardening?: FindWalletsHardeningDeps;
  /** Injectable fetch (tests / non-global runtimes). Defaults to global `fetch`. */
  fetch?: typeof fetch;
}

export class MercuryIndexer implements SignerIndexer {
  constructor(private readonly config: MercuryIndexerConfig) {
    if (!config.url) {
      throw new IndexerError(
        "MercuryIndexer requires a url",
        PasskeyKitErrorCode.INDEXER_NOT_CONFIGURED
      );
    }
  }

  /**
   * Null-tolerant factory: resolve the hosted base URL for `networkPassphrase`
   * (unless `url` is given), returning `null` when the network has no hosted
   * endpoint and no explicit `url` — callers treat `null` as "discovery
   * disabled".
   */
  static forNetwork(
    config: Omit<MercuryIndexerConfig, "url"> & { url?: string },
    networkPassphrase: string
  ): MercuryIndexer | null {
    const url = config.url ?? mercuryPasskeyIndexerUrl(networkPassphrase);
    if (!url) return null;
    return new MercuryIndexer({ ...config, url });
  }

  /**
   * GET a passkey-indexer route. Returns the parsed JSON, or `null` on a `404`
   * (a genuine "not found" is an answer, not a failure). Any other non-2xx, a
   * timeout, or a transport error throws an {@link IndexerError}.
   */
  private async get<T>(path: string): Promise<T | null> {
    const doFetch = this.config.fetch ?? fetch;
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      DEFAULT_INDEXER_TIMEOUT_MS
    );
    try {
      const response = await doFetch(`${this.config.url}${path}`, {
        signal: controller.signal,
      });
      if (response.status === 404) return null;
      if (!response.ok) {
        const body = await response.text().catch(() => "");
        throw new IndexerError(
          `Mercury passkey-indexer GET ${path} failed (${response.status}): ${body.slice(0, 200)}`,
          PasskeyKitErrorCode.INDEXER_REQUEST_FAILED,
          { path, status: response.status }
        );
      }
      return (await response.json()) as T;
    } catch (err) {
      if (err instanceof IndexerError) throw err;
      const aborted = err instanceof Error && err.name === "AbortError";
      throw new IndexerError(
        aborted
          ? `Mercury passkey-indexer GET ${path} timed out`
          : String(err),
        PasskeyKitErrorCode.INDEXER_REQUEST_FAILED,
        { path },
        err instanceof Error ? err : undefined
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  async getSigners(wallet: string): Promise<WalletSigner[]> {
    const res = await this.get<PasskeyIndexerWalletResponse>(
      `/api/wallet/${wallet}`
    );
    if (!res) return []; // 404: the wallet has no indexed signers

    const signers = res.signers.map(jsonToWalletSigner);

    // Eviction probe: the indexer derives `status` from signer add/update/remove
    // events and cannot observe temporary-entry TTL eviction, so confirm each
    // live temporary signer still exists on-chain (#598 F6 / audit H2). A genuine
    // not-found => evicted; a transport error leaves the reported status intact.
    if (this.config.rpc) {
      for (const signer of signers) {
        if (signer.storage === "temporary" && signer.status === "live") {
          try {
            if (!(await this.entryExists(wallet, signer.key))) {
              signer.status = "evicted";
            }
          } catch {
            // Transport error (429/5xx/timeout): eviction undeterminable — keep
            // the row as the indexer reported it rather than false-evicting.
          }
        }
      }
    }

    return signers;
  }

  /**
   * Whether the signer's temporary ledger entry still exists on-chain. Probes by
   * the `SignerKey` ScVal — the exact key the contract stores the entry under
   * (`storage().temporary().set::<SignerKey, SignerVal>`) — so it actually
   * matches. Throws on a transport error (caller decides eviction only from a
   * genuine not-found).
   */
  private async entryExists(wallet: string, key: SignerKey): Promise<boolean> {
    return contractDataExists(
      this.config.rpc!,
      wallet,
      signerKeyToContractScVal(key),
      Durability.Temporary
    );
  }

  async findWallets(key: SignerKey): Promise<WalletCandidateLookup> {
    // Secp256r1 keys are looked up by hex credential id; ed25519/policy keys by
    // their strkey address. The SDK carries the Secp256r1 keyId as base64url, so
    // convert to the hex the credential-id route expects.
    const path =
      key.key === "Secp256r1"
        ? `/api/lookup/${base64url.toBuffer(key.value).toString("hex")}`
        : `/api/lookup/address/${key.value}`;
    const res = await this.get<unknown>(path);
    return this.confirmCandidates(parseLookupResponse(res), key);
  }

  /**
   * Keep a candidate only when it still holds the signer entry on-chain.
   * Live-signer presence is not birth verification; birth fields pass through
   * unchanged for the kit to check against the creating transaction.
   *
   * Fail-CLOSED: when candidates exist without `rpc`, this throws instead of
   * returning unconfirmed rows.
   */
  private async confirmCandidates(
    lookup: WalletCandidateLookup,
    key: SignerKey
  ): Promise<WalletCandidateLookup> {
    const { rpc } = this.config;

    if (!lookup.complete) return lookup;

    if (lookup.candidates.length > 0 && !rpc) {
      throw new IndexerError(
        "Cannot confirm reverse-lookup candidates: configure `rpc`; " +
          "unconfirmed indexer rows are never returned",
        PasskeyKitErrorCode.INDEXER_NOT_CONFIGURED,
        { key: key.key, candidates: lookup.candidates.length }
      );
    }

    if (!rpc || lookup.candidates.length === 0) {
      return lookup;
    }

    const confirmed: WalletCandidate[] = [];
    for (const candidate of lookup.candidates) {
      const signer = await getSigner(
        { rpc, spec: walletSpec() },
        candidate.contractId,
        key
      );
      if (signer) confirmed.push(candidate);
    }
    return { ...lookup, candidates: confirmed };
  }

  async health(): Promise<IndexerHealth> {
    try {
      const res = await this.get<{ status?: string; service?: string }>("/");
      if (res?.status === "ok") return { ok: true, backend: "mercury" };
      return {
        ok: false,
        backend: "mercury",
        detail: `unexpected health payload: ${JSON.stringify(res)}`,
      };
    } catch (err) {
      return {
        ok: false,
        backend: "mercury",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
  }
}

/** Map a passkey-indexer JSON signer key onto the SDK-side {@link SignerKey}. */
function keyFromJson(k: PasskeyIndexerKeyJson): SignerKey {
  switch (k.type) {
    case "secp256r1":
      // The indexer renders the credential id as lowercase hex; the SDK carries
      // it as base64url (matches StoredPasskey.keyId and the contract SignerKey).
      return SignerKey.Secp256r1(base64url(Buffer.from(k.value, "hex")));
    case "ed25519":
      return SignerKey.Ed25519(k.value); // already a `G…` strkey
    case "policy":
      return SignerKey.Policy(k.value); // already a `C…` strkey
  }
}

/** Decode the JSON limits object into the SDK's {@link SignerLimits}. */
function limitsFromJson(
  limits: PasskeyIndexerSignerJson["limits"]
): SignerLimits {
  if (limits === undefined) return undefined; // unlimited (contract `None`)
  // `{}` -> an empty Map: a scoped-but-empty limit set = deny-all, matching the
  // contract's fail-closed `Some(empty)` semantics.
  const out: SignerLimits = new Map();
  for (const [contract, keys] of Object.entries(limits)) {
    out.set(contract, keys === null ? undefined : keys.map(keyFromJson));
  }
  return out;
}

const HEX_64 = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(
  record: Record<string, unknown>,
  keys: readonly string[]
): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim() !== "") return value.trim();
  }
  return undefined;
}

function parseHex64(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const hex = value.toLowerCase().replace(/^0x/, "");
  return HEX_64.test(hex) ? hex : undefined;
}

function parseLedger(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value) && value >= 1) {
    return value;
  }
  if (typeof value === "string" && /^(?:0|[1-9]\d*)$/.test(value)) {
    const ledger = Number(value);
    return ledger >= 1 ? ledger : undefined;
  }
  return undefined;
}

function parseWalletRef(value: unknown): IncompleteWalletCandidate | undefined {
  if (!isRecord(value)) return undefined;
  const contractId = readString(value, ["contract_id", "contractId"]);
  if (!contractId || !contractId.startsWith("C")) return undefined;

  const candidate: IncompleteWalletCandidate = { contractId };
  const birthWasmHash = parseHex64(
    readString(value, ["birth_wasm_hash", "birthWasmHash"])
  );
  const creationTransactionHash = parseHex64(
    readString(value, [
      "creation_transaction_hash",
      "creationTransactionHash",
      "creation_tx",
    ])
  );
  const creationLedger = parseLedger(
    value.creation_ledger ?? value.creationLedger
  );
  if (birthWasmHash) candidate.birthWasmHash = birthWasmHash;
  if (creationTransactionHash) {
    candidate.creationTransactionHash = creationTransactionHash;
  }
  if (creationLedger !== undefined) candidate.creationLedger = creationLedger;
  return candidate;
}

function candidateHasBirth(
  candidate: IncompleteWalletCandidate
): candidate is WalletCandidate {
  return (
    parseHex64(candidate.birthWasmHash) !== undefined &&
    parseHex64(candidate.creationTransactionHash) !== undefined &&
    candidate.creationLedger !== undefined
  );
}

/** Map a lookup JSON body onto {@link WalletCandidateLookup} without inventing birth data. */
function parseLookupResponse(res: unknown): WalletCandidateLookup {
  if (!isRecord(res)) {
    return { complete: false, candidates: [] };
  }

  const rows = Array.isArray(res.wallets)
    ? res.wallets
    : Array.isArray(res.candidates)
      ? res.candidates
      : [];
  const candidates: IncompleteWalletCandidate[] = rows
    .map(parseWalletRef)
    .filter(
      (candidate): candidate is IncompleteWalletCandidate =>
        candidate !== undefined
    );

  const indexedThroughLedger = parseLedger(
    res.indexed_through_ledger ?? res.indexedThroughLedger
  );
  const claimedComplete = res.complete === true;
  const complete =
    res.schema === 2 &&
    claimedComplete &&
    indexedThroughLedger !== undefined &&
    candidates.every(candidateHasBirth);

  if (complete) {
    return {
      complete: true,
      schema: 2,
      indexedThroughLedger,
      candidates: candidates.filter(candidateHasBirth),
    };
  }
  return {
    complete: false,
    ...(typeof res.schema === "number" ? { schema: res.schema } : {}),
    ...(indexedThroughLedger !== undefined ? { indexedThroughLedger } : {}),
    candidates,
  };
}

/** Map a fully-decoded passkey-indexer signer row onto a {@link WalletSigner}. */
function jsonToWalletSigner(json: PasskeyIndexerSignerJson): WalletSigner {
  const publicKey = json.publicKey
    ? new Uint8Array(Buffer.from(json.publicKey, "hex"))
    : undefined;

  // WalletSigner.expiration is contract-typed as UNIX seconds. Only carry it
  // when the indexer reports the `unix` (v1) unit; a legacy `ledger`-sequence
  // expiration is conveyed through the indexer-derived `status`, never smuggled
  // into the seconds field where a consumer would misread it as a timestamp.
  const expiration =
    json.expiration != null && json.expiration_unit !== "ledger"
      ? json.expiration
      : undefined;

  return {
    key: keyFromJson(json.key),
    ...(publicKey ? { publicKey } : {}),
    ...(expiration != null ? { expiration } : {}),
    limits: limitsFromJson(json.limits),
    storage: json.storage,
    status: json.status,
  };
}
