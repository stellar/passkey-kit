//! Secp256r1 signer binding challenges.
//!
//! A passkey enters a wallet only with a *binding proof*: a WebAuthn assertion
//! the passkey holder produced over a challenge committing to the network, the
//! wallet address, the purpose, and the complete signer value. The wallet
//! verifies the proof before it stores the signer and keeps both in a
//! [`crate::types::Secp256r1BindingRecord`]. A client re-verifies the stored
//! proof and separately verifies that accepted code created the wallet. Birth
//! verification is required because custom birth code can copy a pending proof,
//! add an attacker, and then upgrade to accepted code.
//!
//! ## Two disjoint proof spaces
//!
//! [`SECP256R1_GENESIS_DOMAIN`] covers `__constructor`; [`SECP256R1_ADD_DOMAIN`]
//! covers `add_secp256r1`. The purpose is carried twice — once as the domain
//! separator and once as a typed [`BindingPurpose`] field — so the two
//! preimages differ in two independent positions. Cross-purpose replay fails
//! the challenge comparison in `verify_secp256r1_signature`.
//!
//! ## The full signer is committed
//!
//! The challenge includes expiration, limits, and storage durability, not just
//! the key material. Without that, a stolen pending constructor proof could be
//! re-submitted with a different shape — for instance seating the holder's own
//! passkey under `SignerLimits(Some(empty))`, which is durable but not
//! admin-capable, producing a wallet nobody can ever authorize. Committing the
//! whole value makes a proof usable for exactly the deployment its holder
//! intended.
//!
//! `update_signer` may still reshape the live signer afterwards under wallet
//! authorization; the record keeps the original value it attests to.
//!
//! Both halves are exposed so a deploy client can compute the exact challenge
//! the wallet will check:
//! `secp256r1_binding_challenge(env, &secp256r1_binding_payload(...))`.

use soroban_sdk::{crypto::Hash, xdr::ToXdr, Address, Env, Symbol};

use crate::types::{BindingPurpose, Secp256r1BindingPayload, Signer};

/// Domain separator for a `__constructor` (first signer) proof.
pub const SECP256R1_GENESIS_DOMAIN: &str = "secp256r1_genesis_v1";

/// Domain separator for an `add_secp256r1` (later signer) proof.
pub const SECP256R1_ADD_DOMAIN: &str = "secp256r1_add_v1";

/// The domain separator paired with a purpose. The pairing is fixed here so
/// the wallet and every client derive it identically.
pub fn binding_domain(purpose: &BindingPurpose) -> &'static str {
    match purpose {
        BindingPurpose::Genesis => SECP256R1_GENESIS_DOMAIN,
        BindingPurpose::Add => SECP256R1_ADD_DOMAIN,
    }
}

/// Build the binding payload for `signer` on `contract` for `purpose`, using
/// the current ledger's network id.
pub fn secp256r1_binding_payload(
    env: &Env,
    contract: &Address,
    purpose: &BindingPurpose,
    signer: &Signer,
) -> Secp256r1BindingPayload {
    Secp256r1BindingPayload {
        domain: Symbol::new(env, binding_domain(purpose)),
        network_id: env.ledger().network_id(),
        contract: contract.clone(),
        purpose: purpose.clone(),
        signer: signer.clone(),
    }
}

/// The binding challenge: `sha256(XDR(payload))`. This hash is the WebAuthn
/// `challenge` (base64url-encoded in clientDataJSON) the proof must carry.
pub fn secp256r1_binding_challenge(env: &Env, payload: &Secp256r1BindingPayload) -> Hash<32> {
    env.crypto().sha256(&payload.clone().to_xdr(env))
}
