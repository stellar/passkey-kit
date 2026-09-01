#![cfg(test)]
//! Secp256r1 signer binding protocol.
//!
//! A passkey enters a wallet only with a binding proof: a WebAuthn assertion
//! by that passkey over `sha256(XDR(Secp256r1BindingPayload))`, which commits
//! to the network, the wallet address, the PURPOSE, and the COMPLETE signer
//! value.
//!
//! Two properties carry most of the weight here and each has its own section:
//!
//! - **Purpose separation.** `__constructor` reads GENESIS proofs and
//!   `add_secp256r1` reads ADD proofs. Neither accepts the other's.
//! - **Whole-signer commitment.** Changing any field of the signer after the
//!   proof is minted invalidates it. This is what stops a stolen pending
//!   constructor proof from being re-aimed at a different shape — in
//!   particular a durable-but-unprivileged one that would brick the wallet.

extern crate std;

use sha2::{Digest, Sha256};
use smart_wallet_interface::{
    binding::{
        secp256r1_binding_challenge, secp256r1_binding_payload, SECP256R1_ADD_DOMAIN,
        SECP256R1_GENESIS_DOMAIN,
    },
    types::{
        BindingKey, BindingPurpose, Error, Secp256r1BindingRecord, Signatures, Signer,
        SignerExpiration, SignerKey, SignerLimits, SignerStorage, SignerVal,
    },
};
use soroban_sdk::{
    map,
    testutils::{Address as _, Ledger as _},
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, IntoVal, String as SdkString, Symbol,
};

use crate::tests::test_common::*;
use crate::{Contract, ContractClient};

/// A fixed contract address for the golden vectors.
const FIXED_CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
/// The golden vectors are pinned on the public testnet network id so a client
/// can reproduce them with its own network-passphrase constant.
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

fn hex(bytes: &[u8]) -> std::string::String {
    bytes.iter().map(|b| std::format!("{b:02x}")).collect()
}

fn durable() -> (SignerExpiration, SignerLimits) {
    (SignerExpiration(None), SignerLimits(None))
}

/// An Ed25519-admin wallet to add passkeys onto.
fn ed25519_wallet<'a>(env: &Env) -> (Address, ContractClient<'a>) {
    let (expiration, limits) = durable();
    register_wallet(
        env,
        &Ed25519Signer::new(9).signer(env, expiration, limits, SignerStorage::Persistent),
    )
}

/// Register a wallet at a fresh address with an explicit genesis signer and a
/// caller-chosen proof, so a test can mint the proof over anything it likes.
fn register_genesis(env: &Env, signer: &Signer, proof: Option<crate::Secp256r1Signature>) {
    let wallet = Address::generate(env);

    env.register_at(&wallet, Contract, (signer.clone(), proof));
}

fn has_binding(env: &Env, wallet: &Address, key_id: &Bytes, storage: &SignerStorage) -> bool {
    let key = BindingKey::Secp256r1Binding(key_id.clone());

    env.as_contract(wallet, || match storage {
        SignerStorage::Persistent => env.storage().persistent().has::<BindingKey>(&key),
        SignerStorage::Temporary => env.storage().temporary().has::<BindingKey>(&key),
    })
}

fn write_binding(
    env: &Env,
    wallet: &Address,
    key_id: &Bytes,
    record: &Secp256r1BindingRecord,
    storage: &SignerStorage,
) {
    let key = BindingKey::Secp256r1Binding(key_id.clone());

    env.as_contract(wallet, || match storage {
        SignerStorage::Persistent => env
            .storage()
            .persistent()
            .set::<BindingKey, Secp256r1BindingRecord>(&key, record),
        SignerStorage::Temporary => env
            .storage()
            .temporary()
            .set::<BindingKey, Secp256r1BindingRecord>(&key, record),
    });
}

/// Write a Secp256r1 signer entry directly, bypassing the binding protocol —
/// the state any custom code could write before upgrading to this wasm.
fn write_passkey_entry(
    env: &Env,
    wallet: &Address,
    key_id: &Bytes,
    public_key: &BytesN<65>,
    storage: &SignerStorage,
) {
    let key = SignerKey::Secp256r1(key_id.clone());
    let val = SignerVal::Secp256r1(
        public_key.clone(),
        SignerExpiration(None),
        SignerLimits(None),
    );

    env.as_contract(wallet, || match storage {
        SignerStorage::Persistent => env
            .storage()
            .persistent()
            .set::<SignerKey, SignerVal>(&key, &val),
        SignerStorage::Temporary => env
            .storage()
            .temporary()
            .set::<SignerKey, SignerVal>(&key, &val),
    });
}

/// Whether `passkey` can authorize a transfer context through `__check_auth`.
fn passkey_authorizes(env: &Env, wallet: &Address, passkey: &Passkey) -> bool {
    let payload = payload(env, 7);
    let token = Address::generate(env);
    let contexts = soroban_sdk::vec![env, transfer_context(env, &token, wallet, 1)];
    let signatures = Signatures(map![
        env,
        (passkey.signer_key(env), passkey.sign(env, &payload))
    ]);

    env.try_invoke_contract_check_auth::<Error>(
        wallet,
        &payload,
        signatures.into_val(env),
        &contexts,
    )
    .is_ok()
}

// --- GENESIS: the constructor path -------------------------------------------

#[test]
fn constructor_binds_first_passkey_with_a_genesis_record() {
    let env = test_env();
    let passkey = Passkey::new(1);
    let (expiration, limits) = durable();
    let (wallet, client) = register_passkey_wallet(
        &env,
        &passkey,
        expiration,
        limits,
        SignerStorage::Persistent,
    );

    let record = client
        .get_secp256r1_binding(&passkey.key_id(&env))
        .expect("genesis record");

    assert_eq!(record.purpose, BindingPurpose::Genesis);
    assert_eq!(record.signer, passkey.admin_signer(&env));
    assert!(has_binding(
        &env,
        &wallet,
        &passkey.key_id(&env),
        &SignerStorage::Persistent
    ));
    assert!(passkey_authorizes(&env, &wallet, &passkey));
}

#[test]
#[should_panic(expected = "Error(Contract, #130)")]
fn constructor_rejects_passkey_without_proof() {
    let env = test_env();

    register_genesis(&env, &Passkey::new(1).admin_signer(&env), None);
}

#[test]
#[should_panic(expected = "Error(Contract, #131)")]
fn constructor_rejects_proof_for_ed25519_signer() {
    let env = test_env();
    let (expiration, limits) = durable();
    let passkey = Passkey::new(1);
    let stray = passkey.genesis_proof(&env, &Address::generate(&env), &passkey.admin_signer(&env));

    register_genesis(
        &env,
        &Ed25519Signer::new(2).signer(&env, expiration, limits, SignerStorage::Persistent),
        Some(stray),
    );
}

/// A proof made for ANOTHER wallet address does not bind here: the challenge
/// commits to `env.current_contract_address()`.
#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn constructor_rejects_proof_for_other_address() {
    let env = test_env();
    let passkey = Passkey::new(1);
    let signer = passkey.admin_signer(&env);
    let wallet = Address::generate(&env);
    let proof = passkey.genesis_proof(&env, &Address::generate(&env), &signer);

    env.register_at(&wallet, Contract, (signer, Some(proof)));
}

/// A proof made on ANOTHER network does not bind here: the challenge commits
/// to `env.ledger().network_id()`.
#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn constructor_rejects_proof_for_other_network() {
    let env = test_env();
    let passkey = Passkey::new(1);
    let signer = passkey.admin_signer(&env);
    let wallet = Address::generate(&env);

    env.ledger()
        .with_mut(|ledger| ledger.network_id = [0x55; 32]);
    let proof = passkey.genesis_proof(&env, &wallet, &signer);
    env.ledger()
        .with_mut(|ledger| ledger.network_id = [0x66; 32]);

    env.register_at(&wallet, Contract, (signer, Some(proof)));
}

#[test]
#[should_panic]
fn constructor_rejects_proof_signed_by_another_key() {
    let env = test_env();
    let victim = Passkey::new(1);
    let attacker = Passkey::new(2);
    let signer = victim.admin_signer(&env);
    let wallet = Address::generate(&env);

    // The attacker signs the victim's exact payload. The challenge therefore
    // MATCHES and the rejection comes from the host secp256r1 verifier, which
    // traps rather than returning a typed contract error.
    let payload = secp256r1_binding_payload(&env, &wallet, &BindingPurpose::Genesis, &signer);
    let proof = attacker.binding_proof_for(&env, &payload);

    env.register_at(&wallet, Contract, (signer, Some(proof)));
}

/// Cross-purpose replay: an ADD proof cannot seed a constructor.
#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn constructor_rejects_an_add_purpose_proof() {
    let env = test_env();
    let passkey = Passkey::new(1);
    let signer = passkey.admin_signer(&env);
    let wallet = Address::generate(&env);
    let add_proof = passkey.add_proof(&env, &wallet, &signer);

    env.register_at(&wallet, Contract, (signer, Some(add_proof)));
}

/// The first signer must be DURABLE — a Temporary genesis could evict to zero
/// live signers with no contract call to guard it.
#[test]
#[should_panic(expected = "Error(Contract, #104)")]
fn constructor_rejects_a_non_durable_first_signer() {
    let env = test_env();
    let passkey = Passkey::new(1);
    let (expiration, limits) = durable();
    let signer = passkey.signer(&env, expiration, limits, SignerStorage::Temporary);
    let wallet = Address::generate(&env);
    let proof = passkey.genesis_proof(&env, &wallet, &signer);

    env.register_at(&wallet, Contract, (signer, Some(proof)));
}

/// Durability is not viability. A durable signer with no independent admin
/// authority yields a wallet nobody can ever authorize — unrecoverable, and it
/// can still receive funds. `admin_count`, not just `durable_count`.
#[test]
#[should_panic(expected = "Error(Contract, #103)")]
fn constructor_rejects_a_durable_non_admin_first_signer() {
    let env = test_env();
    let passkey = Passkey::new(1);
    let wallet = Address::generate(&env);
    // Persistent and non-expiring, so `is_durable` holds — but an empty limits
    // map grants no independent authority, so `is_durable_admin` does not.
    let signer = passkey.signer(
        &env,
        SignerExpiration(None),
        SignerLimits(Some(map![&env])),
        SignerStorage::Persistent,
    );
    let proof = passkey.genesis_proof(&env, &wallet, &signer);

    env.register_at(&wallet, Contract, (signer, Some(proof)));
}

/// A wallet-self grant that still needs a co-signer is not independently
/// admin-capable either.
#[test]
#[should_panic(expected = "Error(Contract, #103)")]
fn constructor_rejects_a_first_signer_needing_a_co_signer() {
    let env = test_env();
    let passkey = Passkey::new(1);
    let wallet = Address::generate(&env);
    let co_signer = Ed25519Signer::new(4).signer_key(&env);
    let signer = passkey.signer(
        &env,
        SignerExpiration(None),
        SignerLimits(Some(map![
            &env,
            (
                wallet.clone(),
                Some(soroban_sdk::vec![&env, co_signer.clone()])
            )
        ])),
        SignerStorage::Persistent,
    );
    let proof = passkey.genesis_proof(&env, &wallet, &signer);

    env.register_at(&wallet, Contract, (signer, Some(proof)));
}

// --- Whole-signer commitment -------------------------------------------------

/// Mint a GENESIS proof over `signed`, then deploy `submitted`. Every field of
/// the signer is inside the challenge, so any divergence must be rejected.
fn genesis_shape_mismatch(signed: impl Fn(&Env, &Passkey) -> Signer) {
    let env = test_env();
    let passkey = Passkey::new(1);
    let wallet = Address::generate(&env);
    let submitted = passkey.admin_signer(&env);
    let proof = passkey.genesis_proof(&env, &wallet, &signed(&env, &passkey));

    env.register_at(&wallet, Contract, (submitted, Some(proof)));
}

#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn genesis_proof_commits_to_the_expiration() {
    genesis_shape_mismatch(|env, passkey| {
        passkey.signer(
            env,
            SignerExpiration(Some(u64::MAX)),
            SignerLimits(None),
            SignerStorage::Persistent,
        )
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn genesis_proof_commits_to_the_limits() {
    genesis_shape_mismatch(|env, passkey| {
        passkey.signer(
            env,
            SignerExpiration(None),
            SignerLimits(Some(map![env])),
            SignerStorage::Persistent,
        )
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn genesis_proof_commits_to_the_storage_durability() {
    genesis_shape_mismatch(|env, passkey| {
        passkey.signer(
            env,
            SignerExpiration(None),
            SignerLimits(None),
            SignerStorage::Temporary,
        )
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn genesis_proof_commits_to_the_public_key() {
    genesis_shape_mismatch(|env, _| {
        Signer::Secp256r1(
            Passkey::new(1).key_id(env),
            Passkey::new(2).public_key(env),
            SignerExpiration(None),
            SignerLimits(None),
            SignerStorage::Persistent,
        )
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #122)")]
fn genesis_proof_commits_to_the_credential_id() {
    genesis_shape_mismatch(|env, _| {
        Signer::Secp256r1(
            Passkey::new(2).key_id(env),
            Passkey::new(1).public_key(env),
            SignerExpiration(None),
            SignerLimits(None),
            SignerStorage::Persistent,
        )
    });
}

// --- ADD: the add_secp256r1 path ---------------------------------------------

#[test]
fn add_secp256r1_binds_in_the_signer_durability() {
    for storage in [SignerStorage::Persistent, SignerStorage::Temporary] {
        let env = test_env();
        env.mock_all_auths();
        let (wallet, client) = ed25519_wallet(&env);
        let passkey = Passkey::new(3);
        let signer = passkey.signer(
            &env,
            SignerExpiration(None),
            SignerLimits(None),
            storage.clone(),
        );
        let proof = passkey.add_proof(&env, &wallet, &signer);

        client.add_secp256r1(&signer, &proof);

        let record = client
            .get_secp256r1_binding(&passkey.key_id(&env))
            .expect("add record");
        assert_eq!(record.purpose, BindingPurpose::Add);
        assert_eq!(record.signer, signer);
        assert!(has_binding(&env, &wallet, &passkey.key_id(&env), &storage));
        assert!(passkey_authorizes(&env, &wallet, &passkey));
    }
}

/// Cross-purpose replay: a GENESIS proof cannot add a later signer.
#[test]
fn add_secp256r1_rejects_a_genesis_purpose_proof() {
    let env = test_env();
    env.mock_all_auths();
    let (wallet, client) = ed25519_wallet(&env);
    let passkey = Passkey::new(3);
    let signer = passkey.admin_signer(&env);
    let genesis_proof = passkey.genesis_proof(&env, &wallet, &signer);

    assert_eq!(
        client.try_add_secp256r1(&signer, &genesis_proof),
        Err(Ok(Error::ClientDataJsonChallengeIncorrect))
    );
    assert_eq!(client.get_secp256r1_binding(&passkey.key_id(&env)), None);
}

#[test]
fn add_secp256r1_rejects_an_altered_signer_shape() {
    let env = test_env();
    env.mock_all_auths();
    let (wallet, client) = ed25519_wallet(&env);
    let passkey = Passkey::new(3);
    let signed = passkey.admin_signer(&env);
    let proof = passkey.add_proof(&env, &wallet, &signed);

    let widened = passkey.signer(
        &env,
        SignerExpiration(Some(u64::MAX)),
        SignerLimits(None),
        SignerStorage::Persistent,
    );

    assert_eq!(
        client.try_add_secp256r1(&widened, &proof),
        Err(Ok(Error::ClientDataJsonChallengeIncorrect))
    );
}

#[test]
fn add_secp256r1_rejects_a_wrong_address_proof() {
    let env = test_env();
    env.mock_all_auths();
    let (_, client) = ed25519_wallet(&env);
    let passkey = Passkey::new(3);
    let signer = passkey.admin_signer(&env);
    let proof = passkey.add_proof(&env, &Address::generate(&env), &signer);

    assert_eq!(
        client.try_add_secp256r1(&signer, &proof),
        Err(Ok(Error::ClientDataJsonChallengeIncorrect))
    );
}

#[test]
fn add_secp256r1_rejects_a_non_passkey_signer() {
    let env = test_env();
    env.mock_all_auths();
    let (wallet, client) = ed25519_wallet(&env);
    let (expiration, limits) = durable();
    let passkey = Passkey::new(3);
    let proof = passkey.add_proof(&env, &wallet, &passkey.admin_signer(&env));

    assert_eq!(
        client.try_add_secp256r1(
            &Ed25519Signer::new(5).signer(&env, expiration, limits, SignerStorage::Persistent),
            &proof
        ),
        Err(Ok(Error::BindingProofUnexpected))
    );
}

#[test]
fn add_secp256r1_rejects_a_duplicate_key_id() {
    let env = test_env();
    env.mock_all_auths();
    let (wallet, client) = ed25519_wallet(&env);
    let passkey = Passkey::new(3);
    let signer = passkey.admin_signer(&env);
    let proof = passkey.add_proof(&env, &wallet, &signer);

    client.add_secp256r1(&signer, &proof);
    assert_eq!(
        client.try_add_secp256r1(&signer, &proof),
        Err(Ok(Error::SignerAlreadyExists))
    );
}

#[test]
#[should_panic]
fn add_secp256r1_requires_wallet_auth() {
    let env = test_env();
    let (wallet, client) = ed25519_wallet(&env);
    let passkey = Passkey::new(3);
    let signer = passkey.admin_signer(&env);
    let proof = passkey.add_proof(&env, &wallet, &signer);

    client.add_secp256r1(&signer, &proof);
}

/// Passkeys never enter through the generic entry point.
#[test]
fn generic_add_signer_rejects_a_passkey() {
    let env = test_env();
    env.mock_all_auths();
    let (_, client) = ed25519_wallet(&env);

    assert_eq!(
        client.try_add_signer(&Passkey::new(3).admin_signer(&env)),
        Err(Ok(Error::BindingProofRequired))
    );
}

// --- update_signer -----------------------------------------------------------

#[test]
fn update_signer_rejects_a_public_key_substitution() {
    let env = test_env();
    env.mock_all_auths();
    let victim = Passkey::new(1);
    let (expiration, limits) = durable();
    let (_, client) =
        register_passkey_wallet(&env, &victim, expiration, limits, SignerStorage::Persistent);

    let substituted = Signer::Secp256r1(
        victim.key_id(&env),
        Passkey::new(2).public_key(&env),
        SignerExpiration(None),
        SignerLimits(None),
        SignerStorage::Persistent,
    );

    assert_eq!(
        client.try_update_signer(&substituted),
        Err(Ok(Error::BindingPublicKeyImmutable))
    );
}

/// Mutable policy fields may change. The record keeps the ORIGINAL signer —
/// that is what the holder actually signed — and stays readable because the
/// key material still matches.
#[test]
fn update_signer_changes_policy_but_keeps_the_original_record() {
    let env = test_env();
    env.mock_all_auths();
    let admin = Ed25519Signer::new(9);
    let (expiration, limits) = durable();
    let (wallet, client) = register_wallet(
        &env,
        &admin.signer(&env, expiration, limits, SignerStorage::Persistent),
    );
    let passkey = Passkey::new(3);
    let original = passkey.admin_signer(&env);
    let proof = passkey.add_proof(&env, &wallet, &original);
    client.add_secp256r1(&original, &proof);

    let narrowed = passkey.signer(
        &env,
        SignerExpiration(None),
        SignerLimits(Some(map![&env])),
        SignerStorage::Persistent,
    );
    client.update_signer(&narrowed);

    let record = client
        .get_secp256r1_binding(&passkey.key_id(&env))
        .expect("record survives a policy change");
    assert_eq!(record.signer, original, "the record keeps what was signed");
    assert_eq!(record.purpose, BindingPurpose::Add);

    let live = client
        .get_signer(&passkey.signer_key(&env))
        .expect("live signer");
    assert_eq!(
        live,
        SignerVal::Secp256r1(
            passkey.public_key(&env),
            SignerExpiration(None),
            SignerLimits(Some(map![&env])),
        ),
        "the live entry did change"
    );
}

#[test]
fn update_signer_moves_the_binding_with_durability() {
    let env = test_env();
    env.mock_all_auths();
    let admin = Ed25519Signer::new(9);
    let (expiration, limits) = durable();
    let (wallet, client) = register_wallet(
        &env,
        &admin.signer(&env, expiration, limits, SignerStorage::Persistent),
    );
    let passkey = Passkey::new(3);
    let original = passkey.admin_signer(&env);
    let proof = passkey.add_proof(&env, &wallet, &original);
    client.add_secp256r1(&original, &proof);

    let key_id = passkey.key_id(&env);
    assert!(has_binding(
        &env,
        &wallet,
        &key_id,
        &SignerStorage::Persistent
    ));

    client.update_signer(&passkey.signer(
        &env,
        SignerExpiration(None),
        SignerLimits(None),
        SignerStorage::Temporary,
    ));

    assert!(!has_binding(
        &env,
        &wallet,
        &key_id,
        &SignerStorage::Persistent
    ));
    assert!(has_binding(
        &env,
        &wallet,
        &key_id,
        &SignerStorage::Temporary
    ));
    assert!(client.get_secp256r1_binding(&key_id).is_some());
}

// --- remove_signer and re-add ------------------------------------------------

#[test]
fn remove_deletes_the_record_and_readd_needs_a_fresh_add_proof() {
    let env = test_env();
    env.mock_all_auths();
    let admin = Ed25519Signer::new(9);
    let (expiration, limits) = durable();
    let (wallet, client) = register_wallet(
        &env,
        &admin.signer(&env, expiration, limits, SignerStorage::Persistent),
    );
    let passkey = Passkey::new(3);
    let signer = passkey.admin_signer(&env);
    let add_proof = passkey.add_proof(&env, &wallet, &signer);
    let key_id = passkey.key_id(&env);

    client.add_secp256r1(&signer, &add_proof);
    client.remove_signer(&passkey.signer_key(&env));

    assert_eq!(client.get_secp256r1_binding(&key_id), None);
    assert!(!has_binding(
        &env,
        &wallet,
        &key_id,
        &SignerStorage::Persistent
    ));
    assert!(!has_binding(
        &env,
        &wallet,
        &key_id,
        &SignerStorage::Temporary
    ));
    assert_eq!(client.get_signer(&passkey.signer_key(&env)), None);

    // A GENESIS proof still does not work on the re-add path.
    let genesis_proof = passkey.genesis_proof(&env, &wallet, &signer);
    assert_eq!(
        client.try_add_secp256r1(&signer, &genesis_proof),
        Err(Ok(Error::ClientDataJsonChallengeIncorrect))
    );

    // The ADD proof is reusable for the identical signer on the identical
    // wallet: it is a possession proof, not a nonce, and re-adding still needs
    // wallet auth. Re-add writes a NEW record.
    client.add_secp256r1(&signer, &add_proof);
    let record = client
        .get_secp256r1_binding(&key_id)
        .expect("re-added record");
    assert_eq!(record.purpose, BindingPurpose::Add);
    assert_eq!(record.signer, signer);
}

// --- Read-side equality invariant --------------------------------------------

/// A record whose signer names other key material is filtered on read, so
/// state written by any other code cannot pass itself off as consent.
#[test]
fn get_secp256r1_binding_hides_an_inconsistent_record() {
    let env = test_env();
    env.mock_all_auths();
    let victim = Passkey::new(1);
    let attacker = Passkey::new(2);
    let (expiration, limits) = durable();
    let (wallet, client) =
        register_passkey_wallet(&env, &victim, expiration, limits, SignerStorage::Persistent);

    let key_id = victim.key_id(&env);
    let forged = Secp256r1BindingRecord {
        signer: attacker.admin_signer(&env),
        purpose: BindingPurpose::Add,
        proof: attacker.add_proof(&env, &wallet, &attacker.admin_signer(&env)),
    };
    write_binding(&env, &wallet, &key_id, &forged, &SignerStorage::Persistent);

    assert_eq!(
        client.get_secp256r1_binding(&key_id),
        None,
        "a record naming another key is not this signer's consent"
    );
}

/// An unbound signer entry — what custom birth code writes — reads as unbound.
#[test]
fn get_secp256r1_binding_reports_an_unbound_signer_entry() {
    let env = test_env();
    let admin = Ed25519Signer::new(9);
    let (expiration, limits) = durable();
    let (wallet, client) = register_wallet(
        &env,
        &admin.signer(&env, expiration, limits, SignerStorage::Persistent),
    );
    let passkey = Passkey::new(3);

    write_passkey_entry(
        &env,
        &wallet,
        &passkey.key_id(&env),
        &passkey.public_key(&env),
        &SignerStorage::Persistent,
    );

    assert!(client.get_signer(&passkey.signer_key(&env)).is_some());
    assert_eq!(client.get_secp256r1_binding(&passkey.key_id(&env)), None);
}

// --- Golden vectors ----------------------------------------------------------

fn golden(env: &Env, purpose: &BindingPurpose) -> (std::string::String, std::string::String) {
    let contract = Address::from_string(&SdkString::from_str(env, FIXED_CONTRACT));
    let signer = Signer::Secp256r1(
        Bytes::from_slice(env, &[0x22; 20]),
        BytesN::from_array(env, &[0x33; 65]),
        SignerExpiration(None),
        SignerLimits(None),
        SignerStorage::Persistent,
    );

    let payload = secp256r1_binding_payload(env, &contract, purpose, &signer);
    assert_eq!(payload.purpose, *purpose);
    assert_eq!(payload.signer, signer);
    assert_eq!(payload.contract, contract);
    assert_eq!(payload.network_id, env.ledger().network_id());

    let xdr = payload.clone().to_xdr(env);
    let mut xdr_bytes = std::vec![0u8; xdr.len() as usize];
    xdr.copy_into_slice(&mut xdr_bytes);

    (
        hex(&xdr_bytes),
        hex(&secp256r1_binding_challenge(env, &payload).to_array()),
    )
}

/// Pin both challenges for fixed inputs so a client can prove it computes the
/// same values. If this fails, a binding domain CHANGED: every stored proof is
/// then unverifiable by the new rule, so version the domain instead of
/// "fixing the test".
#[test]
fn binding_challenge_golden_vectors() {
    let env = test_env();
    env.ledger()
        .with_mut(|ledger| ledger.network_id = Sha256::digest(TESTNET_PASSPHRASE).into());

    assert_eq!(SECP256R1_GENESIS_DOMAIN, "secp256r1_genesis_v1");
    assert_eq!(SECP256R1_ADD_DOMAIN, "secp256r1_add_v1");
    assert_eq!(
        hex(&env.ledger().network_id().to_array()),
        "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472",
        "sha256(\"Test SDF Network ; September 2015\")"
    );

    let (genesis_xdr, genesis_challenge) = golden(&env, &BindingPurpose::Genesis);
    let (add_xdr, add_challenge) = golden(&env, &BindingPurpose::Add);

    assert_ne!(
        genesis_challenge, add_challenge,
        "the two purposes must not share a challenge"
    );

    assert_eq!(
        (
            genesis_xdr.as_str(),
            genesis_challenge.as_str(),
            add_xdr.as_str(),
            add_challenge.as_str(),
        ),
        (
            GENESIS_PAYLOAD_XDR,
            GENESIS_CHALLENGE,
            ADD_PAYLOAD_XDR,
            ADD_CHALLENGE,
        )
    );
}

const GENESIS_PAYLOAD_XDR: &str = "0000001100000001000000050000000f00000008636f6e74726163740000001200000001d7928b72c2703ccfeaf7eb9ff4ef4d504a55a8b979fc9b450ea2c842b4d1ce610000000f00000006646f6d61696e00000000000f000000147365637032353672315f67656e657369735f76310000000f0000000a6e6574776f726b5f696400000000000d00000020cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd4720000000f00000007707572706f7365000000001000000001000000010000000f0000000747656e65736973000000000f000000067369676e657200000000001000000001000000060000000f000000095365637032353672310000000000000d0000001422222222222222222222222222222222222222220000000d00000041333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333300000000000010000000010000000100000001000000100000000100000001000000010000001000000001000000010000000f0000000a50657273697374656e740000";
const GENESIS_CHALLENGE: &str = "f8ba40008c5c0776bb975f9a7f5d0476ee18c7d49b2066cfc6411b5f6077e2c3";
const ADD_PAYLOAD_XDR: &str = "0000001100000001000000050000000f00000008636f6e74726163740000001200000001d7928b72c2703ccfeaf7eb9ff4ef4d504a55a8b979fc9b450ea2c842b4d1ce610000000f00000006646f6d61696e00000000000f000000107365637032353672315f6164645f76310000000f0000000a6e6574776f726b5f696400000000000d00000020cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd4720000000f00000007707572706f7365000000001000000001000000010000000f00000003416464000000000f000000067369676e657200000000001000000001000000060000000f000000095365637032353672310000000000000d0000001422222222222222222222222222222222222222220000000d00000041333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333300000000000010000000010000000100000001000000100000000100000001000000010000001000000001000000010000000f0000000a50657273697374656e740000";
const ADD_CHALLENGE: &str = "2847ba4e42719703a6f100dfce5a0e5d58f0246b62a187694416ed40c7db7c83";

// --- Golden vector: SignerLimits with an account AND a contract address -------

/// Deterministic account (`G…`) and contract (`C…`) addresses for the limits
/// golden vector. Raw keys are `[0x11; 32]` and `[0x22; 32]` so a client can
/// reproduce the exact strkeys. The host `Map` keeps keys in ScVal order, and
/// an `Account` address sorts before a `Contract` address (its ScAddress
/// discriminant is smaller), so the account entry always precedes the contract
/// entry no matter the insertion order below.
const LIMITS_ACCOUNT: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
const LIMITS_CONTRACT: &str = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";

fn limits_golden(env: &Env) -> (std::string::String, std::string::String) {
    let contract = Address::from_string(&SdkString::from_str(env, FIXED_CONTRACT));
    let account = Address::from_string(&SdkString::from_str(env, LIMITS_ACCOUNT));
    let limit_contract = Address::from_string(&SdkString::from_str(env, LIMITS_CONTRACT));

    // Insert the contract entry first to show the host re-sorts by key: the
    // serialized map must still list the account address first.
    let limits = SignerLimits(Some(map![
        env,
        (limit_contract.clone(), None::<soroban_sdk::Vec<SignerKey>>),
        (account.clone(), None::<soroban_sdk::Vec<SignerKey>>),
    ]));
    let signer = Signer::Secp256r1(
        Bytes::from_slice(env, &[0x22; 20]),
        BytesN::from_array(env, &[0x33; 65]),
        SignerExpiration(None),
        limits,
        SignerStorage::Persistent,
    );

    let payload = secp256r1_binding_payload(env, &contract, &BindingPurpose::Genesis, &signer);
    assert_eq!(payload.signer, signer);

    let xdr = payload.clone().to_xdr(env);
    let mut xdr_bytes = std::vec![0u8; xdr.len() as usize];
    xdr.copy_into_slice(&mut xdr_bytes);

    (
        hex(&xdr_bytes),
        hex(&secp256r1_binding_challenge(env, &payload).to_array()),
    )
}

/// Pin the exact payload XDR and challenge for a Secp256r1 signer whose
/// SignerLimits carries two entries — one account address and one contract
/// address — so a TypeScript client can prove byte-for-byte agreement,
/// including the account-before-contract address-map ordering.
#[test]
fn binding_challenge_limits_golden_vector() {
    let env = test_env();
    env.ledger()
        .with_mut(|ledger| ledger.network_id = Sha256::digest(TESTNET_PASSPHRASE).into());

    let (xdr, challenge) = limits_golden(&env);
    assert_eq!(
        (xdr.as_str(), challenge.as_str()),
        (LIMITS_PAYLOAD_XDR, LIMITS_CHALLENGE)
    );
}

const LIMITS_PAYLOAD_XDR: &str = "0000001100000001000000050000000f00000008636f6e74726163740000001200000001d7928b72c2703ccfeaf7eb9ff4ef4d504a55a8b979fc9b450ea2c842b4d1ce610000000f00000006646f6d61696e00000000000f000000147365637032353672315f67656e657369735f76310000000f0000000a6e6574776f726b5f696400000000000d00000020cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd4720000000f00000007707572706f7365000000001000000001000000010000000f0000000747656e65736973000000000f000000067369676e657200000000001000000001000000060000000f000000095365637032353672310000000000000d0000001422222222222222222222222222222222222222220000000d0000004133333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333330000000000001000000001000000010000000100000010000000010000000100000011000000010000000200000012000000000000000011111111111111111111111111111111111111111111111111111111111111110000000100000012000000012222222222222222222222222222222222222222222222222222222222222222000000010000001000000001000000010000000f0000000a50657273697374656e740000";
const LIMITS_CHALLENGE: &str = "f1f01d9d02b880c9e9ec32eeb0ce224efb8036b190931715fd3c2f55e684c99d";

/// The domain separator is inside the payload, so the two spaces differ in the
/// domain AND the purpose field. Either alone would be enough; both is cheap.
#[test]
fn the_two_domains_differ_in_domain_and_purpose() {
    let env = test_env();
    let contract = Address::from_string(&SdkString::from_str(&env, FIXED_CONTRACT));
    let signer = Passkey::new(1).admin_signer(&env);

    let genesis = secp256r1_binding_payload(&env, &contract, &BindingPurpose::Genesis, &signer);
    let add = secp256r1_binding_payload(&env, &contract, &BindingPurpose::Add, &signer);

    assert_eq!(genesis.domain, Symbol::new(&env, SECP256R1_GENESIS_DOMAIN));
    assert_eq!(add.domain, Symbol::new(&env, SECP256R1_ADD_DOMAIN));
    assert_ne!(genesis.domain, add.domain);
    assert_ne!(genesis.purpose, add.purpose);
}
