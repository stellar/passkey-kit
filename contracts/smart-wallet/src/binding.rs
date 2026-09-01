//! Secp256r1 signer binding: proof verification and record storage.
//!
//! A binding record ties a passkey to THIS wallet on THIS network for ONE
//! purpose, through a WebAuthn assertion the holder produced over the binding
//! challenge (`smart_wallet_interface::binding`). The wallet verifies the
//! proof before it writes a record. Clients re-verify the stored proof and
//! separately verify that accepted code created the wallet. Birth verification
//! is required because custom birth code can copy a pending proof into storage,
//! add an attacker, and then upgrade to this wasm.
//!
//! The challenge commits to the COMPLETE original signer, so a proof is
//! usable for exactly one signer shape at one address for one purpose.
//!
//! Records share the signer entry's durability and TTL and are keyed by
//! `BindingKey::Secp256r1Binding(key_id)`.

use smart_wallet_interface::{
    binding::{secp256r1_binding_challenge, secp256r1_binding_payload},
    types::{
        secp256r1_key_material, BindingKey, BindingPurpose, Error, Secp256r1BindingRecord,
        Secp256r1Signature, Signer, SignerStorage,
    },
};
use soroban_sdk::{Bytes, BytesN, Env};

use crate::{storage::extend_binding_record, verify::verify_secp256r1_signature};

/// Verify that `proof` is a WebAuthn assertion by `signer`'s public key over
/// THIS wallet's binding challenge for `purpose` and this exact signer value.
///
/// Reuses the `__check_auth` WebAuthn verifier: the challenge inside
/// clientDataJSON must equal base64url(binding challenge), so a proof made for
/// another address, another network, the other purpose, or ANY other signer
/// field — key id, public key, expiration, limits, storage — fails with
/// `Error::ClientDataJsonChallengeIncorrect`. A proof signed by a different
/// key fails host secp256r1 verification.
pub fn verify_binding_proof(
    env: &Env,
    purpose: &BindingPurpose,
    signer: &Signer,
    proof: Secp256r1Signature,
) -> Result<(), Error> {
    let (_, public_key) = secp256r1_key_material(signer).ok_or(Error::BindingProofUnexpected)?;

    let payload = secp256r1_binding_payload(env, &env.current_contract_address(), purpose, signer);
    let challenge = secp256r1_binding_challenge(env, &payload);

    verify_secp256r1_signature(env, &challenge, &public_key, proof)
}

/// The key id and public key a record attests to.
pub fn record_key_material(record: &Secp256r1BindingRecord) -> Option<(Bytes, BytesN<65>)> {
    secp256r1_key_material(&record.signer)
}

fn binding_key(key_id: &Bytes) -> BindingKey {
    BindingKey::Secp256r1Binding(key_id.clone())
}

/// Write a record in the signer's durability and extend its TTL.
pub fn store_binding_record(
    env: &Env,
    key_id: &Bytes,
    record: &Secp256r1BindingRecord,
    signer_storage: &SignerStorage,
) {
    let key = binding_key(key_id);

    let persistent = match signer_storage {
        SignerStorage::Persistent => {
            env.storage()
                .persistent()
                .set::<BindingKey, Secp256r1BindingRecord>(&key, record);
            true
        }
        SignerStorage::Temporary => {
            env.storage()
                .temporary()
                .set::<BindingKey, Secp256r1BindingRecord>(&key, record);
            false
        }
    };

    extend_binding_record(env, key_id, persistent);
}

/// Read a record from one durability.
fn get_binding_record_in(
    env: &Env,
    key_id: &Bytes,
    signer_storage: &SignerStorage,
) -> Option<Secp256r1BindingRecord> {
    let key = binding_key(key_id);

    match signer_storage {
        SignerStorage::Persistent => env
            .storage()
            .persistent()
            .get::<BindingKey, Secp256r1BindingRecord>(&key),
        SignerStorage::Temporary => env
            .storage()
            .temporary()
            .get::<BindingKey, Secp256r1BindingRecord>(&key),
    }
}

/// Look up a record, Temporary before Persistent (mirrors the signer lookup
/// order).
pub fn get_binding_record(
    env: &Env,
    key_id: &Bytes,
) -> Option<(Secp256r1BindingRecord, SignerStorage)> {
    if let Some(record) = get_binding_record_in(env, key_id, &SignerStorage::Temporary) {
        return Some((record, SignerStorage::Temporary));
    }

    get_binding_record_in(env, key_id, &SignerStorage::Persistent)
        .map(|record| (record, SignerStorage::Persistent))
}

/// Delete a record from one durability. A no-op when absent (a non-Secp256r1
/// signer has no record).
pub fn remove_binding_record(env: &Env, key_id: &Bytes, signer_storage: &SignerStorage) {
    let key = binding_key(key_id);

    match signer_storage {
        SignerStorage::Persistent => {
            if env.storage().persistent().has::<BindingKey>(&key) {
                env.storage().persistent().remove::<BindingKey>(&key);
            }
        }
        SignerStorage::Temporary => {
            if env.storage().temporary().has::<BindingKey>(&key) {
                env.storage().temporary().remove::<BindingKey>(&key);
            }
        }
    }
}

/// Follow a signer's durability flip: move its record (if any) from `from`
/// to `to`, so the "record lives with its signer" invariant holds.
pub fn move_binding_record(env: &Env, key_id: &Bytes, from: &SignerStorage, to: &SignerStorage) {
    if from == to {
        return;
    }

    if let Some(record) = get_binding_record_in(env, key_id, from) {
        remove_binding_record(env, key_id, from);
        store_binding_record(env, key_id, &record, to);
    }
}
