use soroban_sdk::{contracterror, contracttype, Address, Bytes, BytesN, Map, Symbol, Vec};

/// Contract errors.
///
/// Deliberately renumbered for the v1 interface so the error space is disjoint
/// from the legacy (pre-1.0) contract's 1-9 range. A client decoding an error
/// code < 100 is talking to a legacy wallet.
///
/// Ranges:
/// - 100-109: signer storage / management
/// - 110-119: auth (`__check_auth`)
/// - 120-129: WebAuthn (secp256r1) verification
/// - 130-139: Secp256r1 signer binding
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// The requested signer does not exist on this smart wallet.
    SignerNotFound = 100,
    /// `add_signer` was called with a signer key that already exists.
    SignerAlreadyExists = 101,
    /// The signer's expiration timestamp is in the past.
    SignerExpired = 102,
    /// The operation would remove — or demote via `update_signer` — the
    /// wallet's LAST durable admin signer: a signer stored `Persistent`,
    /// non-expiring (`SignerExpiration(None)`), and independently
    /// admin-capable — either unlimited (`SignerLimits(None)`) or holding a
    /// limits entry for the wallet's own address with no required co-signers
    /// (`None` or an empty list). With zero such signers no `add_signer` or
    /// `upgrade` could ever be authorized again, permanently locking the
    /// wallet on an immutable network, so the transition is rejected.
    /// To retire the last admin signer, add (or promote) a replacement
    /// durable admin signer first.
    ///
    /// Case this guard CANNOT catch (statically undecidable): a POLICY
    /// signer with an admin-shaped grant counts as an admin even if its
    /// `policy__` rejects every request. If such a policy is your only
    /// remaining admin, the wallet's admin surface is unrecoverable even
    /// though the signer still exists. Keep a non-policy admin (or a second
    /// admin) at all times.
    LastAdminSigner = 103,
    /// The operation would leave the wallet without any DURABLE signer — one
    /// stored `Persistent` with `SignerExpiration(None)`, any limits. Fired
    /// by `remove_signer` (removing the last durable signer), `update_signer`
    /// (demoting it to `Temporary` storage or to an expiring value), and
    /// `__constructor` (the wallet's first signer must be durable).
    /// Non-durable signers can evict or expire with NO contract
    /// call, so only a durable signer guarantees the wallet always keeps at
    /// least one live signer; with zero live signers nothing — not even
    /// `add_signer` — can ever be authorized again. This is the
    /// classification-independent backstop beneath `LastAdminSigner`. To
    /// retire the last durable signer, add a durable replacement first.
    LastSigner = 104,

    /// No signer in the signatures map is permitted to authorize one of the
    /// requested auth contexts.
    MissingContext = 110,
    /// A signature's variant does not match the stored signer it claims to be
    /// for (e.g. an Ed25519 signature submitted for a Policy signer key).
    SignatureKeyValueMismatch = 111,

    /// clientDataJSON exceeds the 1024 byte parse buffer.
    ClientDataJsonTooLarge = 120,
    /// clientDataJSON is not parseable JSON (or is missing required fields).
    ClientDataJsonParseError = 121,
    /// The challenge in clientDataJSON does not match the base64url-encoded
    /// signature payload. This binds the WebAuthn assertion to the Soroban
    /// authorization entry and MUST NOT be weakened.
    ClientDataJsonChallengeIncorrect = 122,
    /// clientDataJSON `type` is not "webauthn.get".
    InvalidWebAuthnType = 123,
    /// authenticatorData is shorter than the WebAuthn minimum of 37 bytes
    /// (rpIdHash 32 + flags 1 + signCount 4).
    InvalidAuthenticatorData = 124,
    /// The authenticator did not set the User Present (UP) flag.
    ///
    /// UP-only is the deliberate default. Requiring UP keeps
    /// silent, non-interactive assertions out while staying compatible with
    /// authenticators that cannot do User Verification (UV — biometric/PIN).
    /// UV is therefore NOT required by this contract. A deployment that wants
    /// UV-required assertions should enforce it at the client/relayer layer,
    /// or via a future per-signer flag (which would be a signer-model change,
    /// not a change to this check); the contract cannot upgrade UP-only
    /// signers to UV-required retroactively without such a flag.
    UserPresenceRequired = 125,
    /// authenticatorData exceeds the 1024 byte cap (symmetric with
    /// `ClientDataJsonTooLarge`). Real assertions are ~37 bytes; the cap
    /// rejects oversized input BEFORE it is hashed, since this path is
    /// reachable without a valid signature.
    AuthenticatorDataTooLarge = 126,

    /// A Secp256r1 signer was supplied without its binding proof. Passkeys
    /// enter a wallet only through `__constructor` (GENESIS proof) or
    /// `add_secp256r1` (ADD proof) — never through the generic `add_signer`.
    BindingProofRequired = 130,
    /// A binding proof was supplied for a signer that is not Secp256r1.
    BindingProofUnexpected = 131,
    /// `update_signer` may not change a Secp256r1 signer's public key: the
    /// binding proof commits to it. Remove the signer and re-add it with a
    /// fresh proof through `add_secp256r1` instead.
    ///
    /// Code 132 is retired with `bind_secp256r1`; 134 with its
    /// already-bound guard. Neither is reused.
    BindingPublicKeyImmutable = 133,
}

/// Optional expiration for a signer as a UNIX timestamp in seconds, INCLUSIVE:
/// the signer is valid while `ledger timestamp <= expiration` and expired once
/// `ledger timestamp > expiration`. `None` never expires.
///
/// v1 breaking change: this was a ledger sequence number pre-1.0. Timestamps
/// don't drift with changes to ledger close time (e.g. CAP-0070 dynamic
/// timing), which ledger-sequence expirations did.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerExpiration(pub Option<u64>);

/// Authorization limits for a signer.
///
/// - `None`: unlimited.
/// - `Some(empty map)`: no independent authority.
/// - `Some({address -> None})`: any invocation of `address`.
/// - `Some({address -> Some([keys])})`: any invocation of `address` only when
///   every listed key also approves.
///
/// A required key approves independently of its own limits. A required
/// non-policy key must appear in the signatures map and pass full verification.
/// A required policy need not appear there, but it must remain stored and
/// unexpired. It must also approve through `policy__`. Removing it revokes all
/// dependent signers.
///
/// Limited signers cannot authorize `CreateContract*`. A limited cryptographic
/// signer can remove itself without satisfying its limits. A policy signature
/// always calls `policy__`, including during self-removal. A limit for the
/// wallet address grants access to the wallet administration functions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerLimits(pub Option<Map<Address, Option<Vec<SignerKey>>>>);

/// Which durability a signer entry is stored under. At most one entry exists
/// per signer key; lookups check Temporary before Persistent.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerStorage {
    Persistent,
    Temporary,
}

/// Full signer description used by `__constructor`, `add_signer` and
/// `update_signer`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Signer {
    Policy(Address, SignerExpiration, SignerLimits, SignerStorage),
    Ed25519(BytesN<32>, SignerExpiration, SignerLimits, SignerStorage),
    Secp256r1(
        Bytes,
        BytesN<65>,
        SignerExpiration,
        SignerLimits,
        SignerStorage,
    ),
}

/// Storage key identifying a signer. Secp256r1 carries the WebAuthn
/// credential id (`keyId`).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerKey {
    Policy(Address),
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}

/// Stored signer value. Secp256r1 carries the SEC-1 uncompressed public key.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerVal {
    Policy(SignerExpiration, SignerLimits),
    Ed25519(SignerExpiration, SignerLimits),
    Secp256r1(BytesN<65>, SignerExpiration, SignerLimits),
}

/// A WebAuthn assertion over the Soroban authorization payload. The signed
/// message is `authenticator_data || sha256(client_data_json)` and the
/// payload binding lives in clientDataJSON's `challenge` field.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256r1Signature {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub signature: BytesN<64>,
}

/// A signature entry in the signatures map. `Policy` carries no signature
/// material: inclusion of the policy key authorizes an on-chain `policy__`
/// check instead.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Signature {
    Policy,
    Ed25519(BytesN<64>),
    Secp256r1(Secp256r1Signature),
}

/// The `__check_auth` signature object: a map of signer keys to signatures.
/// Map ordering is the host's ScVal ordering. EVERY entry must verify (pass
/// 2 of `__check_auth`) — include only signatures that are needed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signatures(pub Map<SignerKey, Signature>);

/// Storage keys for wallet entries that are NOT signer entries. Every variant
/// name here must stay distinct from every `SignerKey` variant name: a
/// `#[contracttype]` enum encodes as `[Symbol(variant), fields…]` with no
/// type name, so a shared variant name would collide in contract storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingKey {
    /// A `Secp256r1BindingRecord`, keyed by the signer's credential id and
    /// stored in the same durability as the signer entry.
    Secp256r1Binding(Bytes),
}

/// What a binding proof authorizes. Carried in the challenge preimage AND
/// reflected in the domain separator, so the two proof spaces are disjoint
/// twice over: a GENESIS proof can never be replayed into `add_secp256r1`,
/// and an ADD proof can never seed a constructor.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingPurpose {
    /// The wallet's first signer, supplied to `__constructor`.
    Genesis,
    /// A later signer, supplied to `add_secp256r1`.
    Add,
}

/// The preimage of a Secp256r1 binding challenge. The challenge is
/// `sha256(XDR(payload))` — see `binding::secp256r1_binding_challenge`.
///
/// The proof commits to the FULL original `Signer`, not just its key
/// material. A holder consents to one exact signer value on one wallet on one
/// network for one purpose, so a stolen pending proof cannot be re-aimed at a
/// different shape — in particular it cannot be used to seat the holder's
/// passkey with limits that leave the wallet with no admin.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256r1BindingPayload {
    /// `binding::SECP256R1_GENESIS_DOMAIN` or `binding::SECP256R1_ADD_DOMAIN`.
    pub domain: Symbol,
    /// `env.ledger().network_id()` of the network the wallet lives on.
    pub network_id: BytesN<32>,
    /// The wallet address (`env.current_contract_address()` when checked).
    pub contract: Address,
    /// Which entry point the proof authorizes.
    pub purpose: BindingPurpose,
    /// The complete signer value the holder consented to, including
    /// expiration, limits, and storage durability.
    pub signer: Signer,
}

/// A passkey's binding to this wallet: the exact signer it consented to, the
/// purpose that consent was given for, and the WebAuthn assertion it produced
/// over the corresponding challenge.
///
/// Stored under `BindingKey::Secp256r1Binding(key_id)` in the signer's
/// durability; written only by `__constructor` and `add_secp256r1`, each of
/// which verifies `proof` first.
///
/// `signer` is the ORIGINAL value and is never rewritten: `update_signer` may
/// reshape the live signer's mutable policy fields, and the record continues
/// to attest what was actually signed. Its key id and public key must still
/// equal the live signer's — `get_secp256r1_binding` enforces that on read.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256r1BindingRecord {
    pub signer: Signer,
    pub purpose: BindingPurpose,
    pub proof: Secp256r1Signature,
}

/// The credential id and public key inside a `Secp256r1` signer.
pub fn secp256r1_key_material(signer: &Signer) -> Option<(Bytes, BytesN<65>)> {
    match signer {
        Signer::Secp256r1(key_id, public_key, ..) => Some((key_id.clone(), public_key.clone())),
        _ => None,
    }
}
