//! Tests for the legacy-line upgrade target.
//!
//! The end-to-end tests load the real mainnet WASM of two vulnerable builds
//! (`fixtures/`), create a wallet on each, upgrade it in place to the WASM
//! built from this crate, and check that the wallet keeps working, that the
//! hole is closed, and that `migrate_signers` re-encodes the pre-`6a27d48`
//! entries. `make test` builds the WASM first.
extern crate std;

use ed25519_dalek::{Signer as _, SigningKey};
use smart_wallet_interface::types::{
    Signature, Signatures, Signer, SignerExpiration, SignerKey, SignerLimits, SignerStorage,
    SignerVal,
};
use soroban_sdk::{
    map, symbol_short,
    testutils::{Address as _, Ledger as _},
    vec,
    xdr::{
        HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScAddress,
        ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
    },
    Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec,
};

use crate::{Contract, ContractClient};

/// Mainnet `0c0a264d…`: pre-`6a27d48` layout, no constructor (born via
/// `CreateContract` + an unauthenticated first `add_signer`).
const WASM_0C0A264D: &[u8] = include_bytes!("fixtures/0c0a264d.wasm");
/// Mainnet `b62f6221…`: current layout, has `__constructor`, no auth on
/// `update_signer`.
const WASM_B62F6221: &[u8] = include_bytes!("fixtures/b62f6221.wasm");
/// Mainnet `c5509dfa…`: an integrator build not in this repo; same spec as
/// `b62f6221…` (constructor, wrapped layout, no auth on `update_signer`).
const WASM_C5509DFA: &[u8] = include_bytes!("fixtures/c5509dfa.wasm");
/// This crate, built by `make build`.
const WASM_NEW: &[u8] = include_bytes!("../../../target/wasm32v1-none/release/smart_wallet.wasm");
/// The shipped artifact: `make optimize` output, whose sha256 is the
/// published upgrade-target hash.
const WASM_NEW_OPTIMIZED: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/smart_wallet.optimized.wasm");

const SEED: [u8; 32] = [7u8; 32];

/// Every signed auth entry needs a distinct nonce per address.
static NONCE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(11);

fn ed25519() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::from_bytes(&SEED);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

fn empty_limits(env: &Env) -> SignerLimits {
    SignerLimits(Some(Map::new(env)))
}

/// A `SignerVal::Ed25519` encoded the way pre-`6a27d48` builds stored it:
/// `["Ed25519", <void|u32>, [<map>]]` (bare expiration, one-element limits).
fn bare_ed25519_val(env: &Env, expiration: Option<u32>) -> Val {
    let exp: Val = match expiration {
        None => ().into_val(env),
        Some(n) => n.into_val(env),
    };
    let limits: Vec<Val> = vec![
        env,
        Map::<Address, Option<Vec<SignerKey>>>::new(env).into_val(env),
    ];
    let v: Vec<Val> = vec![
        env,
        symbol_short!("Ed25519").into_val(env),
        exp,
        limits.into_val(env),
    ];
    v.into_val(env)
}

/// A `Signer::Ed25519` argument encoded the way pre-`6a27d48` clients sent it:
/// `["Ed25519", <pk>, <void|u32>, [<map>], <storage>]`.
fn bare_ed25519_signer_arg(env: &Env, pk: &BytesN<32>, expiration: Option<u32>) -> Val {
    let exp: Val = match expiration {
        None => ().into_val(env),
        Some(n) => n.into_val(env),
    };
    let limits: Vec<Val> = vec![
        env,
        Map::<Address, Option<Vec<SignerKey>>>::new(env).into_val(env),
    ];
    let v: Vec<Val> = vec![
        env,
        symbol_short!("Ed25519").into_val(env),
        pk.into_val(env),
        exp,
        limits.into_val(env),
        SignerStorage::Persistent.into_val(env),
    ];
    v.into_val(env)
}

/// Build a real `SorobanAuthorizationEntry` for `wallet.<fn>(args)` signed by
/// the Ed25519 signer, so `__check_auth` runs for real (no mock auths).
fn signed_auth(
    env: &Env,
    wallet: &Address,
    sk: &SigningKey,
    pk: &BytesN<32>,
    fn_name: &str,
    args: std::vec::Vec<ScVal>,
) -> SorobanAuthorizationEntry {
    let nonce: i64 = NONCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let signature_expiration_ledger = env.ledger().sequence() + 100;
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::try_from(wallet.clone()).unwrap(),
            function_name: ScSymbol(fn_name.try_into().unwrap()),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: std::vec::Vec::new().try_into().unwrap(),
    };
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: env.ledger().network_id().to_array().into(),
        nonce,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let payload = payload.to_xdr(Limits::none()).unwrap();
    let payload = Bytes::from_slice(env, payload.as_slice());
    let payload = env.crypto().sha256(&payload);

    let sig = Signature::Ed25519(BytesN::from_array(
        env,
        &sk.sign(payload.to_array().as_slice()).to_bytes(),
    ));
    let signatures = Signatures(map![env, (SignerKey::Ed25519(pk.clone()), sig)]);

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::try_from(wallet.clone()).unwrap(),
            nonce,
            signature_expiration_ledger,
            signature: {
                let v: Val = signatures.into_val(env);
                ScVal::try_from_val(env, &v).unwrap()
            },
        }),
        root_invocation,
    }
}

fn invoke<T: TryFromVal<Env, Val>>(env: &Env, wallet: &Address, f: &str, args: Vec<Val>) -> T {
    env.invoke_contract::<T>(wallet, &Symbol::new(env, f), args)
}

fn try_invoke(env: &Env, wallet: &Address, f: &str, args: Vec<Val>) -> bool {
    env.try_invoke_contract::<Val, soroban_sdk::Error>(wallet, &Symbol::new(env, f), args)
        .is_ok()
}

// ---------------------------------------------------------------------------

#[test]
fn bare_layout_reads_and_migrates() {
    let env = Env::default();
    let (_, pk) = ed25519();
    let pk = BytesN::from_array(&env, &pk);
    let key = SignerKey::Ed25519(pk.clone());

    // A wallet on this crate's code, constructed normally.
    let genesis = Signer::Ed25519(
        BytesN::from_array(&env, &[9u8; 32]),
        SignerExpiration(None),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    let wallet = env.register(Contract, (genesis,));
    let client = ContractClient::new(&env, &wallet);

    // Inject a persistent entry in the pre-6a27d48 layout, expiration Some(42).
    env.as_contract(&wallet, || {
        env.storage()
            .persistent()
            .set::<SignerKey, Val>(&key, &bare_ed25519_val(&env, Some(42)));
        // Sanity: the strict decoder rejects it, i.e. this is what bricks
        // ecd990f0/e45c42b9/v1.
        let raw: Val = env
            .storage()
            .persistent()
            .get::<SignerKey, Val>(&key)
            .unwrap();
        assert!(SignerVal::try_from_val(&env, &raw).is_err());
    });

    // Tolerant read.
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(Some(42)),
            empty_limits(&env)
        ))
    );

    // Migrate: one rewrite, missing key skipped, second pass is a no-op.
    let missing = SignerKey::Ed25519(BytesN::from_array(&env, &[1u8; 32]));
    assert_eq!(
        client.migrate_signers(&vec![&env, key.clone(), missing.clone()]),
        1
    );
    assert_eq!(client.migrate_signers(&vec![&env, key.clone()]), 0);

    // Now the strict decoder accepts it and the value is unchanged.
    env.as_contract(&wallet, || {
        let v = env
            .storage()
            .persistent()
            .get::<SignerKey, SignerVal>(&key)
            .unwrap();
        assert_eq!(
            v,
            SignerVal::Ed25519(SignerExpiration(Some(42)), empty_limits(&env))
        );
    });
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(Some(42)),
            empty_limits(&env)
        ))
    );
    assert_eq!(client.get_signer(&missing), None);

    // Temporary entries too.
    let tkey = SignerKey::Ed25519(BytesN::from_array(&env, &[2u8; 32]));
    env.as_contract(&wallet, || {
        env.storage()
            .temporary()
            .set::<SignerKey, Val>(&tkey, &bare_ed25519_val(&env, None));
    });
    assert_eq!(
        client.get_signer(&tkey),
        Some(SignerVal::Ed25519(
            SignerExpiration(None),
            empty_limits(&env)
        ))
    );
    assert_eq!(client.migrate_signers(&vec![&env, tkey.clone()]), 1);
    env.as_contract(&wallet, || {
        assert!(env
            .storage()
            .temporary()
            .get::<SignerKey, SignerVal>(&tkey)
            .is_some());
        assert!(env
            .storage()
            .persistent()
            .get::<SignerKey, Val>(&tkey)
            .is_none());
    });
}

#[test]
fn update_signer_requires_auth() {
    let env = Env::default();
    let (_, pk) = ed25519();
    let pk = BytesN::from_array(&env, &pk);
    let signer = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(None),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    let wallet = env.register(Contract, (signer.clone(),));
    let client = ContractClient::new(&env, &wallet);

    assert!(client.try_update_signer(&signer).is_err());
    env.mock_all_auths();
    assert!(client.try_update_signer(&signer).is_ok());
}

#[test]
fn upgrade_from_0c0a264d_end_to_end() {
    let env = Env::default();
    env.ledger().set_sequence_number(1_000);
    let (sk, pk_raw) = ed25519();
    let pk = BytesN::from_array(&env, &pk_raw);
    let key = SignerKey::Ed25519(pk.clone());

    // Born the way 0c0a264d wallets were: no constructor, first add_signer
    // needs no auth, argument in the bare shape.
    let wallet = env.register(WASM_0C0A264D, ());
    invoke::<()>(
        &env,
        &wallet,
        "add_signer",
        vec![&env, bare_ed25519_signer_arg(&env, &pk, None)],
    );

    // The vulnerability: update_signer with no auth succeeds on the old code
    // (expiration set to Some(5_000) by "anyone").
    assert!(try_invoke(
        &env,
        &wallet,
        "update_signer",
        vec![&env, bare_ed25519_signer_arg(&env, &pk, Some(5_000))],
    ));

    // The stored entry is in the bare layout (this is what bricks a strict build).
    env.as_contract(&wallet, || {
        let raw: Val = env
            .storage()
            .persistent()
            .get::<SignerKey, Val>(&key)
            .unwrap();
        assert!(SignerVal::try_from_val(&env, &raw).is_err());
    });

    // In-place upgrade to this crate, authorized by the owner's real signature
    // through the OLD code's __check_auth.
    let new_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, WASM_NEW));
    let hash_val: Val = new_hash.into_val(&env);
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_contract_code",
        std::vec![ScVal::try_from_val(&env, &hash_val).unwrap()],
    );
    env.set_auths(&[auth]);
    invoke::<()>(&env, &wallet, "update_contract_code", vec![&env, hash_val]);

    // Now on the new code. The hole is closed.
    let client = ContractClient::new(&env, &wallet);
    let typed_signer = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(Some(6_000)),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    env.set_auths(&[]);
    assert!(client.try_update_signer(&typed_signer).is_err());

    // The bare entry is still readable, unchanged.
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(Some(5_000)),
            empty_limits(&env)
        ))
    );

    // __check_auth on the NEW code over the still-bare entry: a real signed
    // update_contract_code (re-upgrade to the same hash) must pass.
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_contract_code",
        std::vec![ScVal::try_from_val(&env, &hash_val).unwrap()],
    );
    env.set_auths(&[auth]);
    invoke::<()>(&env, &wallet, "update_contract_code", vec![&env, hash_val]);

    // Migrate re-encodes it; value unchanged; strict decode now works.
    assert_eq!(client.migrate_signers(&vec![&env, key.clone()]), 1);
    assert_eq!(client.migrate_signers(&vec![&env, key.clone()]), 0);
    env.as_contract(&wallet, || {
        let v = env
            .storage()
            .persistent()
            .get::<SignerKey, SignerVal>(&key)
            .unwrap();
        assert_eq!(
            v,
            SignerVal::Ed25519(SignerExpiration(Some(5_000)), empty_limits(&env))
        );
    });

    // A properly authorized update_signer still works after migration.
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_signer",
        std::vec![{
            let v: Val = typed_signer.clone().into_val(&env);
            ScVal::try_from_val(&env, &v).unwrap()
        }],
    );
    env.set_auths(&[auth]);
    client.update_signer(&typed_signer);
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(Some(6_000)),
            empty_limits(&env)
        ))
    );
}

#[test]
fn upgrade_from_b62f6221_end_to_end() {
    let env = Env::default();
    env.ledger().set_sequence_number(1_000);
    let (sk, pk_raw) = ed25519();
    let pk = BytesN::from_array(&env, &pk_raw);
    let key = SignerKey::Ed25519(pk.clone());

    // Born the way b62f6221 wallets were: constructor with a typed Signer.
    let genesis = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(None),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    let wallet = env.register(WASM_B62F6221, (genesis.clone(),));

    // The vulnerability on the old code.
    let tampered = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(Some(5_000)),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    assert!(try_invoke(
        &env,
        &wallet,
        "update_signer",
        vec![&env, tampered.clone().into_val(&env)],
    ));

    // Upgrade with a real signature through the old __check_auth.
    let new_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, WASM_NEW));
    let hash_val: Val = new_hash.into_val(&env);
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_contract_code",
        std::vec![ScVal::try_from_val(&env, &hash_val).unwrap()],
    );
    env.set_auths(&[auth]);
    invoke::<()>(&env, &wallet, "update_contract_code", vec![&env, hash_val]);

    let client = ContractClient::new(&env, &wallet);
    env.set_auths(&[]);
    assert!(client.try_update_signer(&tampered).is_err());
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(Some(5_000)),
            empty_limits(&env)
        ))
    );
    // Already in the current layout: nothing to migrate.
    assert_eq!(client.migrate_signers(&vec![&env, key.clone()]), 0);

    // Authorized path still works.
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_signer",
        std::vec![{
            let v: Val = genesis.clone().into_val(&env);
            ScVal::try_from_val(&env, &v).unwrap()
        }],
    );
    env.set_auths(&[auth]);
    client.update_signer(&genesis);
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(None),
            empty_limits(&env)
        ))
    );
}

/// A bare-layout value for any variant: `[<tag>, (pk,)? <void|u32>, [<map>]]`.
fn bare_val(env: &Env, tag: &str, pk: Option<&BytesN<65>>, expiration: Option<u32>) -> Val {
    let exp: Val = match expiration {
        None => ().into_val(env),
        Some(n) => n.into_val(env),
    };
    let limits: Vec<Val> = vec![
        env,
        Map::<Address, Option<Vec<SignerKey>>>::new(env).into_val(env),
    ];
    let mut v: Vec<Val> = vec![env, Symbol::new(env, tag).into_val(env)];
    if let Some(pk) = pk {
        v.push_back(pk.into_val(env));
    }
    v.push_back(exp);
    v.push_back(limits.into_val(env));
    v.into_val(env)
}

#[test]
fn bare_layout_secp256r1_and_policy_decode() {
    let env = Env::default();
    let genesis = Signer::Ed25519(
        BytesN::from_array(&env, &[9u8; 32]),
        SignerExpiration(None),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    let wallet = env.register(Contract, (genesis,));
    let client = ContractClient::new(&env, &wallet);

    // Passkey: credential id key, 65-byte SEC-1 public key in the value.
    let cred = Bytes::from_slice(&env, &[0xAB; 16]);
    let pk65 = BytesN::from_array(&env, &[0x04; 65]);
    let pkey = SignerKey::Secp256r1(cred.clone());
    // Policy: the policy address is the key; value has no public key.
    let policy = Address::generate(&env);
    let polkey = SignerKey::Policy(policy.clone());

    env.as_contract(&wallet, || {
        env.storage()
            .persistent()
            .set::<SignerKey, Val>(&pkey, &bare_val(&env, "Secp256r1", Some(&pk65), Some(777)));
        env.storage()
            .temporary()
            .set::<SignerKey, Val>(&polkey, &bare_val(&env, "Policy", None, None));
        for k in [&pkey, &polkey] {
            let raw: Val = if *k == pkey {
                env.storage().persistent().get::<SignerKey, Val>(k).unwrap()
            } else {
                env.storage().temporary().get::<SignerKey, Val>(k).unwrap()
            };
            assert!(SignerVal::try_from_val(&env, &raw).is_err());
        }
    });

    assert_eq!(
        client.get_signer(&pkey),
        Some(SignerVal::Secp256r1(
            pk65.clone(),
            SignerExpiration(Some(777)),
            empty_limits(&env)
        ))
    );
    assert_eq!(
        client.get_signer(&polkey),
        Some(SignerVal::Policy(
            SignerExpiration(None),
            empty_limits(&env)
        ))
    );
    assert_eq!(
        client.migrate_signers(&vec![&env, pkey.clone(), polkey.clone()]),
        2
    );
    assert_eq!(
        client.migrate_signers(&vec![&env, pkey.clone(), polkey.clone()]),
        0
    );
    env.as_contract(&wallet, || {
        assert_eq!(
            env.storage()
                .persistent()
                .get::<SignerKey, SignerVal>(&pkey)
                .unwrap(),
            SignerVal::Secp256r1(
                pk65.clone(),
                SignerExpiration(Some(777)),
                empty_limits(&env)
            )
        );
        assert_eq!(
            env.storage()
                .temporary()
                .get::<SignerKey, SignerVal>(&polkey)
                .unwrap(),
            SignerVal::Policy(SignerExpiration(None), empty_limits(&env))
        );
    });

    // A wrapped value must never be mistaken for a legacy one (no rewrite).
    let wkey = SignerKey::Ed25519(BytesN::from_array(&env, &[3u8; 32]));
    env.as_contract(&wallet, || {
        env.storage().persistent().set::<SignerKey, SignerVal>(
            &wkey,
            &SignerVal::Ed25519(SignerExpiration(Some(1)), SignerLimits(None)),
        );
        let raw: Val = env
            .storage()
            .persistent()
            .get::<SignerKey, Val>(&wkey)
            .unwrap();
        assert!(smart_wallet_interface::types::LegacySignerVal::try_from_val(&env, &raw).is_err());
    });
    assert_eq!(client.migrate_signers(&vec![&env, wkey.clone()]), 0);
}

#[test]
fn update_signer_over_still_bare_entry() {
    // An authorized update_signer on a bare entry (no migrate first) must
    // work and leave a wrapped value.
    let env = Env::default();
    let (_, pk) = ed25519();
    let pk = BytesN::from_array(&env, &pk);
    let key = SignerKey::Ed25519(pk.clone());
    let genesis = Signer::Ed25519(
        BytesN::from_array(&env, &[9u8; 32]),
        SignerExpiration(None),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    let wallet = env.register(Contract, (genesis,));
    let client = ContractClient::new(&env, &wallet);
    env.as_contract(&wallet, || {
        env.storage()
            .persistent()
            .set::<SignerKey, Val>(&key, &bare_ed25519_val(&env, Some(42)));
    });
    env.mock_all_auths();
    // Flip durability to Temporary while updating: the bare persistent entry
    // must be found (so this is an update, not an insert) and removed.
    client.update_signer(&Signer::Ed25519(
        pk.clone(),
        SignerExpiration(Some(99)),
        empty_limits(&env),
        SignerStorage::Temporary,
    ));
    env.as_contract(&wallet, || {
        assert!(env
            .storage()
            .persistent()
            .get::<SignerKey, Val>(&key)
            .is_none());
        assert_eq!(
            env.storage()
                .temporary()
                .get::<SignerKey, SignerVal>(&key)
                .unwrap(),
            SignerVal::Ed25519(SignerExpiration(Some(99)), empty_limits(&env))
        );
    });
    assert_eq!(client.migrate_signers(&vec![&env, key.clone()]), 0);
}

#[test]
fn upgrade_from_c5509dfa_end_to_end() {
    let env = Env::default();
    env.ledger().set_sequence_number(1_000);
    let (sk, pk_raw) = ed25519();
    let pk = BytesN::from_array(&env, &pk_raw);
    let key = SignerKey::Ed25519(pk.clone());
    let genesis = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(None),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    let wallet = env.register(WASM_C5509DFA, (genesis.clone(),));
    let tampered = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(Some(5_000)),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    // Vulnerable on the old code.
    assert!(try_invoke(
        &env,
        &wallet,
        "update_signer",
        vec![&env, tampered.clone().into_val(&env)],
    ));
    let new_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, WASM_NEW));
    let hash_val: Val = new_hash.into_val(&env);
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_contract_code",
        std::vec![ScVal::try_from_val(&env, &hash_val).unwrap()],
    );
    env.set_auths(&[auth]);
    invoke::<()>(&env, &wallet, "update_contract_code", vec![&env, hash_val]);
    let client = ContractClient::new(&env, &wallet);
    env.set_auths(&[]);
    assert!(client.try_update_signer(&tampered).is_err());
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(Some(5_000)),
            empty_limits(&env)
        ))
    );
    assert_eq!(client.migrate_signers(&vec![&env, key.clone()]), 0);
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_signer",
        std::vec![{
            let v: Val = genesis.clone().into_val(&env);
            ScVal::try_from_val(&env, &v).unwrap()
        }],
    );
    env.set_auths(&[auth]);
    client.update_signer(&genesis);
}

#[test]
fn upgrade_from_0c0a264d_to_optimized_artifact() {
    // Same path as the unoptimized test, against the bytes that ship.
    let env = Env::default();
    env.ledger().set_sequence_number(1_000);
    let (sk, pk_raw) = ed25519();
    let pk = BytesN::from_array(&env, &pk_raw);
    let key = SignerKey::Ed25519(pk.clone());
    let wallet = env.register(WASM_0C0A264D, ());
    invoke::<()>(
        &env,
        &wallet,
        "add_signer",
        vec![&env, bare_ed25519_signer_arg(&env, &pk, None)],
    );
    let new_hash = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(&env, WASM_NEW_OPTIMIZED));
    let hash_val: Val = new_hash.into_val(&env);
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_contract_code",
        std::vec![ScVal::try_from_val(&env, &hash_val).unwrap()],
    );
    env.set_auths(&[auth]);
    invoke::<()>(&env, &wallet, "update_contract_code", vec![&env, hash_val]);
    let client = ContractClient::new(&env, &wallet);
    env.set_auths(&[]);
    let typed = Signer::Ed25519(
        pk.clone(),
        SignerExpiration(Some(6_000)),
        empty_limits(&env),
        SignerStorage::Persistent,
    );
    assert!(client.try_update_signer(&typed).is_err());
    assert_eq!(
        client.get_signer(&key),
        Some(SignerVal::Ed25519(
            SignerExpiration(None),
            empty_limits(&env)
        ))
    );
    // Real signed call through the optimized code's __check_auth over the bare entry.
    let auth = signed_auth(
        &env,
        &wallet,
        &sk,
        &pk,
        "update_signer",
        std::vec![{
            let v: Val = typed.clone().into_val(&env);
            ScVal::try_from_val(&env, &v).unwrap()
        }],
    );
    env.set_auths(&[auth]);
    client.update_signer(&typed);
    assert_eq!(client.migrate_signers(&vec![&env, key.clone()]), 0);
}
