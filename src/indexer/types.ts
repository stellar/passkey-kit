/**
 * Indexer abstraction: one {@link SignerIndexer} interface, resolved by the
 * keyless {@link MercuryIndexer} backend into the {@link WalletSigner} shape so a
 * signer added through the demo is discoverable and asserted in the browser e2e.
 *
 * @packageDocumentation
 */

import type { SignerKey, SignerLimits } from "../types.js";

/** Storage durability of a signer's ledger entry. */
export type SignerStorageClass = "persistent" | "temporary";

/**
 * Lifecycle status of a signer, derived from the entry + expiration:
 * - `live` — present and not expired.
 * - `expired` — present but past its expiration timestamp.
 * - `evicted` — a temporary entry whose ledger state was evicted (TTL).
 * - `removed` — tombstoned (remove_signer), no live counterpart in either
 *   durability.
 */
export type SignerStatus = "live" | "expired" | "evicted" | "removed";

/** A signer as resolved by an indexer backend. */
export interface WalletSigner {
  /** The signer's key (kind + value). */
  key: SignerKey;
  /** 65-byte secp256r1 public key, for Secp256r1 signers. */
  publicKey?: Uint8Array;
  /**
   * Expiration as a UNIX timestamp in seconds (inclusive), if set. The reworked
   * contract stores expiration as a timestamp, not a ledger sequence (#602).
   */
  expiration?: number;
  /** Per-contract limits (`undefined` = unlimited). */
  limits?: SignerLimits;
  /** Storage durability of the entry. */
  storage: SignerStorageClass;
  /** Derived lifecycle status. */
  status: SignerStatus;
}

/** Health of an indexer backend. */
export interface IndexerHealth {
  /** Whether the backend answered a health probe. */
  ok: boolean;
  /** Backend identifier (e.g. "mercury"). */
  backend: string;
  /** Optional human-readable detail. */
  detail?: string;
}

/**
 * One reverse-lookup wallet, including birth metadata when the indexer
 * actually supplied it. Missing birth fields stay absent; callers must not
 * treat a live signer as proof of birth.
 */
export interface WalletCandidate {
  /** Wallet contract id (`C…`). */
  contractId: string;
  /** WASM hash from the creating transaction, lowercase hex. */
  birthWasmHash: string;
  /** Creating transaction hash, lowercase hex. */
  creationTransactionHash: string;
  /** Ledger that created the contract. */
  creationLedger: number;
}

/** An incomplete row retained only for diagnostics. It is never connectable. */
export type IncompleteWalletCandidate = Partial<WalletCandidate> & {
  contractId: string;
};

/**
 * Reverse-lookup result. `complete` is true only when the indexer claimed a
 * finished scan and every candidate carries complete birth claims. A 404,
 * an old payload, or a missing field is `complete: false`.
 */
export type WalletCandidateLookup =
  | {
      schema: 2;
      complete: true;
      indexedThroughLedger: number;
      /** Live-signer-confirmed candidates with complete birth metadata. */
      candidates: WalletCandidate[];
    }
  | {
      schema?: number;
      complete: false;
      indexedThroughLedger?: number;
      /** Diagnostic rows only. Callers must reject the full response. */
      candidates: IncompleteWalletCandidate[];
    };

/**
 * A pluggable signer indexer.
 *
 * Null-tolerant seam (per SAK): a backend that is *not configured* is
 * represented as `null` at the call site (see `forNetwork`); a backend that is
 * configured but *fails* throws; a health/404 degrades to `{ ok: false }`
 * rather than throwing.
 */
export interface SignerIndexer {
  /** Enumerate all signers currently indexed for a wallet. */
  getSigners(wallet: string): Promise<WalletSigner[]>;
  /** Reverse lookup: wallets a signer key belongs to, with birth metadata. */
  findWallets(key: SignerKey): Promise<WalletCandidateLookup>;
  /** Probe backend health (degrades to `{ ok: false }` rather than throwing). */
  health(): Promise<IndexerHealth>;
}

/**
 * @deprecated Retained for source compatibility. Derivation does not confirm
 * wallet ownership, so Mercury ignores these values and requires RPC.
 */
export interface FindWalletsHardeningDeps {
  networkPassphrase: string;
  /** The canonical deployer `G…` public key used for derivation. */
  deployerPublicKey: string;
}
