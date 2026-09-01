/**
 * `PasskeyServer` reverse-lookup surface:
 *
 * - `getWalletCandidates` returns the full lookup, including completeness and
 *   birth metadata. It never picks one address.
 * - Input validation ("exactly one of keyId, publicKey, policy") is preserved.
 */

import { describe, expect, it, vi } from "vitest";
import { Networks } from "@stellar/stellar-sdk";
import { PasskeyServer } from "./server.js";
import { IndexerError } from "./errors.js";
import type { WalletCandidateLookup } from "./indexer/types.js";

const WALLET = "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ";
const OTHER_WALLET = "CBQU3NIOXC3IDGERJWV3YVMSQSIOU2S6NSMH35OS3GPG6XARZFAAT2NL";
const BIRTH_HASH = "ab".repeat(32);
const OTHER_BIRTH_HASH = "ef".repeat(32);
const TX_HASH = "cd".repeat(32);
const OTHER_TX_HASH = "11".repeat(32);

function completeLookup(): WalletCandidateLookup {
  return {
    schema: 2,
    complete: true,
    indexedThroughLedger: 4_226_310,
    candidates: [
      {
        contractId: WALLET,
        birthWasmHash: BIRTH_HASH,
        creationTransactionHash: TX_HASH,
        creationLedger: 4_226_310,
      },
      {
        contractId: OTHER_WALLET,
        birthWasmHash: OTHER_BIRTH_HASH,
        creationTransactionHash: OTHER_TX_HASH,
        creationLedger: 4_226_311,
      },
    ],
  };
}

function makeServer(): PasskeyServer {
  return new PasskeyServer({ networkPassphrase: Networks.TESTNET, mercury: {} });
}

function stubFindWallets(
  server: PasskeyServer,
  impl: () => Promise<WalletCandidateLookup>
) {
  const mercury = (
    server as unknown as {
      mercury: {
        findWallets: (...args: unknown[]) => Promise<WalletCandidateLookup>;
      };
    }
  ).mercury;
  if (!mercury) throw new Error("MercuryIndexer was not constructed");
  return vi.spyOn(mercury, "findWallets").mockImplementation(impl);
}

describe("PasskeyServer.getWalletCandidates", () => {
  it("returns a complete lookup without selecting a wallet", async () => {
    const server = makeServer();
    const lookup = completeLookup();
    const findWallets = stubFindWallets(server, async () => lookup);

    await expect(server.getWalletCandidates({ keyId: "key" })).resolves.toEqual(
      lookup
    );
    expect(findWallets).toHaveBeenCalledTimes(1);
    expect((findWallets.mock.calls[0]![0] as { key: string }).key).toBe(
      "Secp256r1"
    );
  });

  it("preserves ambiguity and birth metadata for two live wallets", async () => {
    const server = makeServer();
    const lookup = completeLookup();
    stubFindWallets(server, async () => lookup);

    const result = await server.getWalletCandidates({ keyId: "key" });
    expect(result.complete).toBe(true);
    expect(result.candidates).toHaveLength(2);
    expect(result.candidates[0]?.birthWasmHash).toBe(BIRTH_HASH);
    expect(result.candidates[1]?.creationTransactionHash).toBe(OTHER_TX_HASH);
  });

  it("returns an incomplete empty lookup when the indexer has no candidates", async () => {
    const server = makeServer();
    stubFindWallets(server, async () => ({ complete: false, candidates: [] }));
    await expect(server.getWalletCandidates({ keyId: "key" })).resolves.toEqual({
      complete: false,
      candidates: [],
    });
  });

  it("passes through incomplete lookups that omit birth fields", async () => {
    const server = makeServer();
    stubFindWallets(server, async () => ({
      complete: false,
      indexedThroughLedger: 10,
      candidates: [{ contractId: WALLET }],
    }));

    await expect(server.getWalletCandidates({ keyId: "key" })).resolves.toEqual({
      complete: false,
      indexedThroughLedger: 10,
      candidates: [{ contractId: WALLET }],
    });
  });

  it("propagates indexer transport failures", async () => {
    const server = makeServer();
    stubFindWallets(server, async () => {
      throw new IndexerError("503 upstream");
    });
    await expect(
      server.getWalletCandidates({ keyId: "key" })
    ).rejects.toThrow("503");
  });

  it("requires exactly one of keyId, publicKey, or policy", async () => {
    const server = makeServer();
    await expect(server.getWalletCandidates({})).rejects.toThrow("exactly one");
    await expect(
      server.getWalletCandidates({ keyId: "k", policy: OTHER_WALLET })
    ).rejects.toThrow("exactly one");
  });

  it("looks up Ed25519 and policy keys", async () => {
    const server = makeServer();
    const findWallets = stubFindWallets(server, async () => ({
      complete: false,
      candidates: [],
    }));

    await server.getWalletCandidates({ publicKey: "GAAA" });
    expect((findWallets.mock.calls[0]![0] as { key: string }).key).toBe(
      "Ed25519"
    );

    await server.getWalletCandidates({ policy: OTHER_WALLET });
    expect((findWallets.mock.calls[1]![0] as { key: string }).key).toBe(
      "Policy"
    );
  });
});
