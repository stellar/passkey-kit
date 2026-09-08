import { afterEach, describe, expect, it, vi } from "vitest";
import { Buffer as BrowserBuffer } from "buffer/index.js";
import { Keypair, Networks, xdr } from "@stellar/stellar-sdk";
import base64url from "../base64url.js";
import { SignerKey } from "../types.js";
import { IndexerError } from "../errors.js";
import { deriveContractAddress } from "../utils.js";
import {
  MercuryIndexer,
  mercuryPasskeyIndexerUrl,
} from "./mercury.js";
import { signerKeyToContractScVal, walletSpec } from "./codec.js";
import { SIGNER_VAL_UDT } from "../kit/auth-payload.js";

const TESTNET = Networks.TESTNET;
const DEPLOYER = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 9)).publicKey();
const BASE = "https://testnet.mercurydata.app/rest/passkey-indexer";
const WALLET = "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ";
const OTHER_WALLET = "CBQU3NIOXC3IDGERJWV3YVMSQSIOU2S6NSMH35OS3GPG6XARZFAAT2NL";
const ED25519 = "GA5A447HNYRI52DHWLH2SCSQLNG2KHXP6ZY4RNFT63SVAQRO4VNQPDAI";
const CRED_HEX = "cc".repeat(32);
const PUBKEY_HEX = "04" + "ab".repeat(64);

/**
 * Stub the global fetch with a handler that returns a JSON body (and optional
 * status) per requested URL. Mirrors the passkey-indexer's `Response` surface.
 */
function stubFetch(
  handler: (url: string) => { status?: number; body?: unknown }
) {
  const mock = vi.fn(async (url: string | URL) => {
    const { status = 200, body } = handler(String(url));
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () =>
        typeof body === "string" ? body : JSON.stringify(body ?? ""),
    } as unknown as Response;
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

function fakeRpc(getLedgerEntries: ReturnType<typeof vi.fn>) {
  return { getLedgerEntries } as never;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("mercuryPasskeyIndexerUrl", () => {
  it("resolves the hosted base per network, undefined otherwise", () => {
    expect(mercuryPasskeyIndexerUrl(Networks.TESTNET)).toBe(BASE);
    expect(mercuryPasskeyIndexerUrl(Networks.PUBLIC)).toBe(
      "https://mainnet.mercurydata.app/rest/passkey-indexer"
    );
    expect(mercuryPasskeyIndexerUrl(Networks.FUTURENET)).toBeUndefined();
  });

  it("forNetwork returns null on an unsupported network with no explicit url", () => {
    expect(MercuryIndexer.forNetwork({}, Networks.FUTURENET)).toBeNull();
    expect(
      MercuryIndexer.forNetwork({ url: "https://self.host" }, Networks.FUTURENET)
    ).toBeInstanceOf(MercuryIndexer);
  });
});

describe("MercuryIndexer.getSigners", () => {
  it("decodes a Secp256r1 key with the browser Buffer polyfill", async () => {
    vi.stubGlobal("Buffer", BrowserBuffer);
    stubFetch(() => ({
      body: {
        contractId: WALLET,
        generation: "v1",
        signers: [
          {
            key: { type: "secp256r1", value: CRED_HEX },
            storage: "persistent",
            status: "live",
          },
        ],
      },
    }));

    const [signer] = await new MercuryIndexer({ url: BASE }).getSigners(WALLET);

    expect(signer!.key.value).toBe("zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw");
  });

  it("maps decoded JSON rows to WalletSigners", async () => {
    stubFetch(() => ({
      body: {
        contractId: WALLET,
        generation: "v1",
        signers: [
          {
            key: { type: "secp256r1", value: CRED_HEX },
            publicKey: PUBKEY_HEX,
            storage: "persistent",
            status: "live",
          },
          {
            key: { type: "ed25519", value: ED25519 },
            expiration: 1786422535,
            expiration_unit: "unix",
            limits: {},
            storage: "temporary",
            status: "live",
          },
        ],
      },
    }));

    const indexer = new MercuryIndexer({ url: BASE });
    const signers = await indexer.getSigners(WALLET);

    expect(signers).toHaveLength(2);

    const secp = signers[0]!;
    expect(secp.key.key).toBe("Secp256r1");
    // hex credential id decodes to the SDK's base64url keyId
    expect(secp.key.value).toBe(Buffer.from(CRED_HEX, "hex").toString("base64url"));
    expect(secp.publicKey).toHaveLength(65);
    expect(secp.expiration).toBeUndefined(); // never expires
    expect(secp.limits).toBeUndefined(); // absent limits => unlimited
    expect(secp.storage).toBe("persistent");
    expect(secp.status).toBe("live");

    const ed = signers[1]!;
    expect(ed.key.key).toBe("Ed25519");
    expect(ed.key.value).toBe(ED25519);
    expect(ed.expiration).toBe(1786422535);
    expect(ed.limits).toBeInstanceOf(Map);
    expect(ed.limits!.size).toBe(0); // `{}` => deny-all (empty Map)
    expect(ed.storage).toBe("temporary");
  });

  it("decodes scoped/any-key limits", async () => {
    stubFetch(() => ({
      body: {
        contractId: WALLET,
        generation: "v1",
        signers: [
          {
            key: { type: "policy", value: OTHER_WALLET },
            limits: {
              [OTHER_WALLET]: null,
              [WALLET]: [{ type: "ed25519", value: ED25519 }],
            },
            storage: "persistent",
            status: "live",
          },
        ],
      },
    }));

    const [signer] = await new MercuryIndexer({ url: BASE }).getSigners(WALLET);
    expect(signer!.key.key).toBe("Policy");
    expect(signer!.limits!.get(OTHER_WALLET)).toBeUndefined(); // null => any key
    const scoped = signer!.limits!.get(WALLET)!;
    expect(scoped).toHaveLength(1);
    expect(scoped[0]!.key).toBe("Ed25519");
    expect(scoped[0]!.value).toBe(ED25519);
  });

  it("carries no unix expiration for a legacy ledger-sequence signer", async () => {
    stubFetch(() => ({
      body: {
        contractId: WALLET,
        generation: "legacy",
        signers: [
          {
            key: { type: "secp256r1", value: CRED_HEX },
            publicKey: PUBKEY_HEX,
            expiration: 54309985,
            expiration_unit: "ledger",
            storage: "persistent",
            status: "expired",
          },
        ],
      },
    }));

    const [signer] = await new MercuryIndexer({ url: BASE }).getSigners(WALLET);
    expect(signer!.expiration).toBeUndefined(); // ledger seq is not a unix time
    expect(signer!.status).toBe("expired"); // lifecycle preserved via status
  });

  it("returns [] on a 404 (wallet has no indexed signers)", async () => {
    stubFetch(() => ({ status: 404, body: { error: "Wallet not found" } }));
    const signers = await new MercuryIndexer({ url: BASE }).getSigners(WALLET);
    expect(signers).toEqual([]);
  });

  it("throws an IndexerError on a non-404 failure", async () => {
    stubFetch(() => ({ status: 500, body: "boom" }));
    await expect(
      new MercuryIndexer({ url: BASE }).getSigners(WALLET)
    ).rejects.toBeInstanceOf(IndexerError);
  });
});

describe("MercuryIndexer eviction probe (audit H2)", () => {
  function tempLiveBody() {
    return {
      contractId: WALLET,
      generation: "v1",
      signers: [
        {
          key: { type: "secp256r1", value: CRED_HEX },
          publicKey: PUBKEY_HEX,
          storage: "temporary",
          status: "live",
        },
      ],
    };
  }

  it("probes by the SignerKey ScVal and keeps a still-present temporary signer", async () => {
    stubFetch(() => ({ body: tempLiveBody() }));
    const present = { contractData: () => ({ val: () => xdr.ScVal.scvVoid() }) };
    const getLedgerEntries = vi.fn(async () => ({ entries: [{ val: present }] }));
    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(getLedgerEntries),
    });

    const [signer] = await indexer.getSigners(WALLET);
    expect(signer!.status).toBe("live");
    expect(getLedgerEntries).toHaveBeenCalledTimes(1);

    const ledgerKey = getLedgerEntries.mock.calls[0]![0] as xdr.LedgerKey;
    const probedKey = ledgerKey.contractData().key();
    expect(probedKey.toXDR("base64")).toBe(
      signerKeyToContractScVal(
        SignerKey.Secp256r1(Buffer.from(CRED_HEX, "hex").toString("base64url"))
      ).toXDR("base64")
    );
    expect(probedKey.switch().name).toBe("scvVec");
  });

  it("marks a temporary signer evicted on a genuine not-found", async () => {
    stubFetch(() => ({ body: tempLiveBody() }));
    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [] }))),
    });
    const [signer] = await indexer.getSigners(WALLET);
    expect(signer!.status).toBe("evicted");
  });

  it("does NOT evict on a transport error during the probe", async () => {
    stubFetch(() => ({ body: tempLiveBody() }));
    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(
        vi.fn(async () => {
          throw new Error("429 too many requests");
        })
      ),
    });
    const [signer] = await indexer.getSigners(WALLET);
    expect(signer!.status).toBe("live"); // left as reported, not false-evicted
  });
});

const BIRTH_HASH = "ab".repeat(32);
const OTHER_BIRTH_HASH = "ef".repeat(32);
const TX_HASH = "cd".repeat(32);
const OTHER_TX_HASH = "11".repeat(32);
const CREATION_LEDGER = 4_226_310;

function birthFields(overrides?: {
  contractId?: string;
  birthWasmHash?: string;
  creationTransactionHash?: string;
  creationLedger?: number;
}) {
  return {
    contract_id: overrides?.contractId ?? WALLET,
    birth_wasm_hash: overrides?.birthWasmHash ?? BIRTH_HASH,
    creation_transaction_hash: overrides?.creationTransactionHash ?? TX_HASH,
    creation_ledger: overrides?.creationLedger ?? CREATION_LEDGER,
  };
}

function v2Candidate(
  overrides?: {
    contractId?: string;
    birthWasmHash?: string;
    creationTransactionHash?: string;
    creationLedger?: number;
    derivedAddress?: boolean;
    collision?: boolean;
  }
) {
  return {
    contractId: overrides?.contractId ?? WALLET,
    birthWasmHash: overrides?.birthWasmHash ?? BIRTH_HASH,
    creationTransactionHash: overrides?.creationTransactionHash ?? TX_HASH,
    creationLedger: overrides?.creationLedger ?? CREATION_LEDGER,
    currentWasmHash: overrides?.birthWasmHash ?? BIRTH_HASH,
    generation: "legacy",
    derivedAddress: overrides?.derivedAddress ?? false,
    collision: overrides?.collision ?? false,
    incomplete: false,
    signer: {
      publicKey: PUBKEY_HEX,
      expiration: null,
      expiration_unit: null,
      storage: "persistent",
      status: "live",
      rpcConfirmed: true,
    },
  };
}

function v2Lookup(
  keyId: string,
  candidates: ReturnType<typeof v2Candidate>[],
  overrides: Record<string, unknown> = {}
) {
  return {
    schema: 2,
    credentialId: base64url.toBuffer(keyId).toString("hex"),
    network: "testnet",
    complete: true,
    indexedThroughLedger: CREATION_LEDGER,
    rpcCheckedAtLedger: CREATION_LEDGER,
    candidates,
    count: candidates.length,
    ambiguous: candidates.length > 1,
    ...overrides,
  };
}

function secpPresent() {
  const signerVal = walletSpec().nativeToScVal(
    {
      tag: "Secp256r1",
      values: [Buffer.alloc(65), [undefined], [undefined]],
    },
    SIGNER_VAL_UDT
  );
  return { contractData: () => ({ val: () => signerVal }) };
}

function ed25519Present() {
  const signerVal = walletSpec().nativeToScVal(
    { tag: "Ed25519", values: [[undefined], [undefined]] },
    SIGNER_VAL_UDT
  );
  return { contractData: () => ({ val: () => signerVal }) };
}

describe("MercuryIndexer.findWallets", () => {
  it("returns a complete lookup with birth metadata after live confirmation", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 7));
    const derived = deriveContractAddress(
      base64url.toBuffer(keyId),
      DEPLOYER,
      TESTNET
    );
    const mock = stubFetch((url) => {
      expect(url).toContain(
        `/api/v2/lookup/${base64url.toBuffer(keyId).toString("hex")}`
      );
      return {
        body: v2Lookup(
          keyId,
          [
            v2Candidate({ contractId: derived }),
            v2Candidate({
              contractId: OTHER_WALLET,
              birthWasmHash: OTHER_BIRTH_HASH,
              creationTransactionHash: OTHER_TX_HASH,
              creationLedger: CREATION_LEDGER + 1,
            }),
          ],
          {
            indexedThroughLedger: CREATION_LEDGER + 1,
            rpcCheckedAtLedger: CREATION_LEDGER + 1,
          }
        ),
      };
    });

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(true);
    expect(lookup.indexedThroughLedger).toBe(CREATION_LEDGER + 1);
    expect(lookup.candidates).toEqual([
      {
        contractId: derived,
        birthWasmHash: BIRTH_HASH,
        creationTransactionHash: TX_HASH,
        creationLedger: CREATION_LEDGER,
      },
      {
        contractId: OTHER_WALLET,
        birthWasmHash: OTHER_BIRTH_HASH,
        creationTransactionHash: OTHER_TX_HASH,
        creationLedger: CREATION_LEDGER + 1,
      },
    ]);
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it("keeps both live candidates and their birth fields when the lookup is ambiguous", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 3));
    stubFetch(() => ({
      body: v2Lookup(keyId, [
        v2Candidate({ contractId: WALLET }),
        v2Candidate({
          contractId: OTHER_WALLET,
          birthWasmHash: OTHER_BIRTH_HASH,
          creationTransactionHash: OTHER_TX_HASH,
        }),
      ]),
    }));

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(true);
    expect(lookup.candidates.map((c) => c.contractId)).toEqual([
      WALLET,
      OTHER_WALLET,
    ]);
    expect(lookup.candidates[0]?.birthWasmHash).toBe(BIRTH_HASH);
    expect(lookup.candidates[1]?.birthWasmHash).toBe(OTHER_BIRTH_HASH);
  });

  it("accepts collision flags only when derived and non-derived candidates coexist", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 4));
    stubFetch(() => ({
      body: v2Lookup(keyId, [
        v2Candidate({ contractId: WALLET, collision: true }),
        v2Candidate({
          contractId: OTHER_WALLET,
          birthWasmHash: OTHER_BIRTH_HASH,
          creationTransactionHash: OTHER_TX_HASH,
          derivedAddress: true,
          collision: true,
        }),
      ]),
    }));

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(true);
    expect(lookup.candidates).toHaveLength(2);
  });

  it("rejects collision flags when no derived candidate exists", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(keyId, [v2Candidate({ collision: true })]),
    }));

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(false);
  });

  it.each([
    ["count", { count: 2 }],
    ["ambiguity", { ambiguous: true }],
    ["creation ledger", { indexedThroughLedger: CREATION_LEDGER - 1 }],
  ])("rejects a %s mismatch", async (_name, overrides) => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(keyId, [v2Candidate()], overrides),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it("rejects false collision flags for derived and non-derived candidates", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(keyId, [
        v2Candidate({ derivedAddress: true }),
        v2Candidate({ contractId: OTHER_WALLET }),
      ]),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it("rejects complete when the index is behind the RPC check ledger", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(keyId, [v2Candidate()], {
        indexedThroughLedger: CREATION_LEDGER,
        rpcCheckedAtLedger: CREATION_LEDGER + 1,
      }),
    }));

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(false);
  });

  it("accepts a complete empty response after signer expiration", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({ body: v2Lookup(keyId, []) }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup).toEqual({
      schema: 2,
      complete: true,
      indexedThroughLedger: CREATION_LEDGER,
      candidates: [],
    });
  });

  it.each([
    "schema",
    "credentialId",
    "network",
    "complete",
    "indexedThroughLedger",
    "rpcCheckedAtLedger",
    "candidates",
    "count",
    "ambiguous",
  ])("rejects a v2 response without %s", async (field) => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    const body: Record<string, unknown> = v2Lookup(keyId, [v2Candidate()]);
    delete body[field];
    stubFetch(() => ({ body }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it.each([
    "contractId",
    "birthWasmHash",
    "creationTransactionHash",
    "creationLedger",
    "currentWasmHash",
    "generation",
    "derivedAddress",
    "collision",
    "incomplete",
    "signer",
  ])("rejects a complete v2 candidate without %s", async (field) => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    const candidate: Record<string, unknown> = v2Candidate();
    delete candidate[field];
    stubFetch(() => ({
      body: v2Lookup(
        keyId,
        [candidate as ReturnType<typeof v2Candidate>]
      ),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it.each([
    "publicKey",
    "expiration",
    "expiration_unit",
    "storage",
    "status",
    "rpcConfirmed",
  ])("rejects a complete v2 signer without %s", async (field) => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    const candidate = v2Candidate();
    const signer: Record<string, unknown> = { ...candidate.signer };
    delete signer[field];
    stubFetch(() => ({
      body: v2Lookup(keyId, [
        {
          ...candidate,
          signer: signer as typeof candidate.signer,
        },
      ]),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it.each([
    ["an invalid contract ID", { contractId: "Cnot-valid" }],
    ["an unknown network", {}, { network: "futurenet" }],
  ])("rejects %s", async (_name, candidateOverrides, responseOverrides = {}) => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(
        keyId,
        [v2Candidate(candidateOverrides)],
        responseOverrides
      ),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it("rejects a valid network label that conflicts with forNetwork", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(keyId, [v2Candidate()], { network: "mainnet" }),
    }));
    const indexer = MercuryIndexer.forNetwork(
      { rpc: fakeRpc(vi.fn(async () => ({ entries: [] }))) },
      TESTNET
    )!;

    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(false);
  });

  it("keeps custom-url v2 lookup incomplete without a network binding", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({ body: v2Lookup(keyId, []) }));
    const indexer = new MercuryIndexer({ url: "https://custom.example" });

    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(false);
  });

  it("rejects duplicate candidate contract IDs", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(keyId, [v2Candidate(), v2Candidate()]),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it.each([
    ["empty candidates and a nonempty legacy set", [], [{ contract_id: WALLET }]],
    [
      "different nonempty candidate sets",
      [v2Candidate()],
      [{ contract_id: OTHER_WALLET }],
    ],
  ])("rejects %s", async (_name, candidates, wallets) => {
    const keyId = base64url.encode(Buffer.alloc(16, 5));
    stubFetch(() => ({
      body: v2Lookup(keyId, candidates, { wallets }),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.complete).toBe(false);
  });

  it("rejects incompleteReasons on a claimed-complete candidate", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 6));
    const candidate = {
      ...v2Candidate({ contractId: WALLET }),
      incompleteReasons: ["missing_birth"],
    };
    stubFetch(() => ({
      body: v2Lookup(keyId, [candidate]),
    }));

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(false);
  });

  it("preserves closed candidate and response incomplete reasons", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 10));
    const candidate = {
      ...v2Candidate(),
      incomplete: true,
      incompleteReasons: ["rpc_unchecked"],
    };
    stubFetch(() => ({
      body: v2Lookup(keyId, [candidate], {
        complete: false,
        incompleteReasons: ["index_behind"],
      }),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup).toMatchObject({
      schema: 2,
      complete: false,
      incompleteReasons: ["index_behind"],
      candidates: [
        {
          contractId: WALLET,
          incompleteReasons: ["rpc_unchecked"],
        },
      ],
    });
  });

  it.each([
    "missing_birth",
    "rpc_unchecked",
    "signer_unconfirmed",
    "instance_missing",
    "wasm_unresolved",
    "inconsistent_creation_ledger",
  ])("preserves the candidate reason %s", async (reason) => {
    const keyId = base64url.encode(Buffer.alloc(16, 10));
    stubFetch(() => ({
      body: v2Lookup(
        keyId,
        [
          {
            ...v2Candidate(),
            incomplete: true,
            incompleteReasons: [reason],
          },
        ],
        { complete: false }
      ),
    }));

    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Secp256r1(keyId)
    );

    expect(lookup.candidates[0]).toMatchObject({
      incompleteReasons: [reason],
    });
  });

  it.each(["reducer_errors", "index_behind"])(
    "preserves the response reason %s",
    async (reason) => {
      const keyId = base64url.encode(Buffer.alloc(16, 10));
      stubFetch(() => ({
        body: v2Lookup(keyId, [], {
          complete: false,
          incompleteReasons: [reason],
        }),
      }));

      const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
        SignerKey.Secp256r1(keyId)
      );

      expect(lookup).toMatchObject({ incompleteReasons: [reason] });
    }
  );

  it.each([[], ["unknown_reason"]])(
    "does not expose an invalid response reason list %j",
    async (incompleteReasons) => {
      const keyId = base64url.encode(Buffer.alloc(16, 10));
      stubFetch(() => ({
        body: v2Lookup(keyId, [], {
          complete: false,
          incompleteReasons,
        }),
      }));

      const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
        SignerKey.Secp256r1(keyId)
      );

      expect(lookup.complete).toBe(false);
      expect(lookup.incompleteReasons).toBeUndefined();
    }
  );

  it.each([[], ["unknown_reason"]])(
    "does not expose an invalid candidate reason list %j",
    async (incompleteReasons) => {
      const keyId = base64url.encode(Buffer.alloc(16, 10));
      stubFetch(() => ({
        body: v2Lookup(
          keyId,
          [
            {
              ...v2Candidate(),
              incomplete: true,
              incompleteReasons,
            },
          ],
          { complete: false }
        ),
      }));

      const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
        SignerKey.Secp256r1(keyId)
      );

      expect(lookup.complete).toBe(false);
      expect(lookup.candidates[0]?.incompleteReasons).toBeUndefined();
    }
  );

  it("marks old lookup shapes incomplete and does not invent birth data", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 7));
    stubFetch(() => ({
      body: {
        credentialId: base64url.toBuffer(keyId).toString("hex"),
        wallets: [
          { contract_id: WALLET, generation: "v1", signer_count: 1 },
          { contract_id: OTHER_WALLET, generation: "v1", signer_count: 1 },
        ],
        count: 2,
      },
    }));

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(false);
    expect(lookup.indexedThroughLedger).toBeUndefined();
    expect(lookup.candidates).toEqual([
      { contractId: WALLET },
      { contractId: OTHER_WALLET },
    ]);
  });

  it("marks a claimed-complete lookup incomplete when a birth field is missing", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 1));
    const missingBirth = v2Candidate({ contractId: OTHER_WALLET });
    delete (missingBirth as { creationTransactionHash?: string })
      .creationTransactionHash;
    stubFetch(() => ({
      body: v2Lookup(keyId, [v2Candidate(), missingBirth]),
    }));

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: secpPresent() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(false);
    expect(lookup.indexedThroughLedger).toBe(CREATION_LEDGER);
    expect(lookup.candidates[1]).toEqual({
      contractId: OTHER_WALLET,
      birthWasmHash: BIRTH_HASH,
      creationLedger: CREATION_LEDGER,
    });
    expect(lookup.candidates[1]?.creationTransactionHash).toBeUndefined();
  });

  it("drops a candidate that fails live confirmation and keeps birth metadata on the rest", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 2));
    stubFetch(() => ({
      body: v2Lookup(keyId, [
        v2Candidate({ contractId: WALLET }),
        v2Candidate({
          contractId: OTHER_WALLET,
          birthWasmHash: OTHER_BIRTH_HASH,
          creationTransactionHash: OTHER_TX_HASH,
        }),
      ]),
    }));

    let calls = 0;
    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(
        vi.fn(async () => {
          calls += 1;
          return {
            entries: calls === 1 ? [{ val: secpPresent() }] : [],
          };
        })
      ),
    });

    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));

    expect(lookup.complete).toBe(true);
    expect(lookup.candidates).toEqual([
      {
        contractId: WALLET,
        birthWasmHash: BIRTH_HASH,
        creationTransactionHash: TX_HASH,
        creationLedger: CREATION_LEDGER,
      },
    ]);
  });

  it("rpc-confirms the DERIVED candidate instead of trusting the match", async () => {
    const keyId = base64url.encode(Buffer.alloc(16, 9));
    const derived = deriveContractAddress(
      base64url.toBuffer(keyId),
      DEPLOYER,
      TESTNET
    );
    stubFetch(() => ({
      body: v2Lookup(keyId, [
        v2Candidate({ contractId: derived, derivedAddress: true }),
      ]),
    }));

    const getLedgerEntries = vi.fn(async () => ({ entries: [] }));
    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(getLedgerEntries),
      hardening: { networkPassphrase: TESTNET, deployerPublicKey: DEPLOYER },
    });

    const lookup = await indexer.findWallets(SignerKey.Secp256r1(keyId));
    expect(lookup.complete).toBe(true);
    expect(lookup.candidates).toEqual([]);
    expect(getLedgerEntries).toHaveBeenCalled();
  });

  it("looks up an Ed25519 key by its strkey address, confirmed on-chain", async () => {
    const mock = stubFetch((url) => {
      expect(url).toContain(`/api/lookup/address/${ED25519}`);
      return {
        body: {
          schema: 2,
          complete: true,
          indexed_through_ledger: CREATION_LEDGER,
          wallets: [birthFields({ contractId: OTHER_WALLET })],
        },
      };
    });

    const indexer = new MercuryIndexer({
      url: BASE,
      rpc: fakeRpc(vi.fn(async () => ({ entries: [{ val: ed25519Present() }] }))),
    });
    const lookup = await indexer.findWallets(SignerKey.Ed25519(ED25519));
    expect(lookup.complete).toBe(true);
    expect(lookup.candidates).toEqual([
      {
        contractId: OTHER_WALLET,
        birthWasmHash: BIRTH_HASH,
        creationTransactionHash: TX_HASH,
        creationLedger: CREATION_LEDGER,
      },
    ]);
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it("fails CLOSED when candidates exist but no confirmation route does", async () => {
    stubFetch(() => ({
      body: {
        schema: 2,
        complete: true,
        indexed_through_ledger: CREATION_LEDGER,
        wallets: [birthFields({ contractId: OTHER_WALLET })],
      },
    }));

    await expect(
      new MercuryIndexer({ url: BASE }).findWallets(SignerKey.Ed25519(ED25519))
    ).rejects.toBeInstanceOf(IndexerError);

    await expect(
      new MercuryIndexer({
        url: BASE,
        hardening: { networkPassphrase: TESTNET, deployerPublicKey: DEPLOYER },
      }).findWallets(SignerKey.Ed25519(ED25519))
    ).rejects.toBeInstanceOf(IndexerError);
  });

  it("returns an incomplete empty lookup when there are no candidates", async () => {
    stubFetch(() => ({ body: { wallets: [], count: 0 } }));
    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Ed25519(ED25519)
    );
    expect(lookup).toEqual({ complete: false, candidates: [] });
  });

  it("returns an incomplete empty lookup on a 404", async () => {
    stubFetch(() => ({ status: 404, body: { error: "not found" } }));
    const lookup = await new MercuryIndexer({ url: BASE }).findWallets(
      SignerKey.Policy(OTHER_WALLET)
    );
    expect(lookup).toEqual({ complete: false, candidates: [] });
  });

  it("propagates transport errors", async () => {
    stubFetch(() => ({ status: 503, body: "upstream" }));
    await expect(
      new MercuryIndexer({ url: BASE }).findWallets(SignerKey.Ed25519(ED25519))
    ).rejects.toBeInstanceOf(IndexerError);
  });
});

describe("MercuryIndexer.health", () => {
  it("reports ok on a healthy root response", async () => {
    stubFetch(() => ({ body: { service: "passkey-indexer", status: "ok" } }));
    expect(await new MercuryIndexer({ url: BASE }).health()).toEqual({
      ok: true,
      backend: "mercury",
    });
  });

  it("reports ok:false on a transport failure", async () => {
    stubFetch(() => ({ status: 503, body: "down" }));
    const h = await new MercuryIndexer({ url: BASE }).health();
    expect(h.ok).toBe(false);
    expect(h.backend).toBe("mercury");
    expect(h.detail).toBeTruthy();
  });
});
