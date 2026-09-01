#![cfg(test)]
//! Shared helpers for the smart wallet test suite.

extern crate std;

use ed25519_dalek::{Signer as _, SigningKey};
use p256::ecdsa::{
    signature::hazmat::PrehashSigner, Signature as P256Signature, SigningKey as P256SigningKey,
};
use sha2::{Digest, Sha256};
use smart_wallet_interface::{
    binding::{secp256r1_binding_challenge, secp256r1_binding_payload},
    types::{
        BindingPurpose, Secp256r1BindingPayload, Secp256r1Signature, Signature, Signer,
        SignerExpiration, SignerKey, SignerLimits, SignerStorage,
    },
};
use soroban_sdk::{
    auth::{Context, ContractContext},
    testutils::{Address as _, EnvTestConfig},
    xdr::{
        HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, ScVal,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, ToXdr, VecM, WriteXdr,
    },
    Address, Bytes, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};

use crate::{Contract, ContractClient};

pub fn test_env() -> Env {
    let mut env = Env::default();

    env.set_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });

    env
}

/// Register a wallet with an Ed25519 or Policy first signer (no binding
/// proof). For a passkey first signer use `register_passkey_wallet`.
pub fn register_wallet<'a>(env: &Env, signer: &Signer) -> (Address, ContractClient<'a>) {
    let address = env.register(Contract, (signer.clone(), None::<Secp256r1Signature>));
    let client = ContractClient::new(env, &address);

    (address, client)
}

/// Register a wallet whose FIRST signer is a passkey. The binding proof
/// commits to the wallet address, so the address is generated up front and
/// the contract is registered at it.
pub fn register_passkey_wallet<'a>(
    env: &Env,
    passkey: &Passkey,
    expiration: SignerExpiration,
    limits: SignerLimits,
    storage: SignerStorage,
) -> (Address, ContractClient<'a>) {
    let address = Address::generate(env);
    let signer = passkey.signer(env, expiration, limits, storage);
    let proof = passkey.genesis_proof(env, &address, &signer);

    env.register_at(&address, Contract, (signer, Some(proof)));
    let client = ContractClient::new(env, &address);

    (address, client)
}

/// Seed for the Ed25519 admin that satisfies the constructor's durable-admin
/// requirement in wallets whose SUBJECT signer is deliberately not an admin.
/// Chosen far from the per-test seeds so it never collides.
pub const GENESIS_ADMIN_SEED: u8 = 200;

pub fn genesis_admin() -> Ed25519Signer {
    Ed25519Signer::new(GENESIS_ADMIN_SEED)
}

/// Register a wallet whose subject signer is NOT admin-capable.
///
/// `__constructor` requires a durable ADMIN first signer, so a wallet holding
/// only a limited, co-signer-gated, expiring, or Temporary signer cannot be
/// born. Such a wallet is built in two steps instead: an unlimited Ed25519
/// admin at genesis, then `signer` added under wallet auth.
///
/// The genesis admin never appears in the signature maps these tests build, so
/// it does not change what they assert about `signer`.
pub fn register_wallet_with<'a>(env: &Env, signer: &Signer) -> (Address, ContractClient<'a>) {
    let admin = genesis_admin();
    let (wallet, client) = register_wallet(
        env,
        &admin.signer(
            env,
            SignerExpiration(None),
            SignerLimits(None),
            SignerStorage::Persistent,
        ),
    );

    match signer {
        Signer::Secp256r1(key_id, ..) => {
            let passkey = Passkey::from_key_id(key_id);
            client
                .mock_all_auths()
                .add_secp256r1(signer, &passkey.add_proof(env, &wallet, signer));
        }
        _ => {
            client.mock_all_auths().add_signer(signer);
        }
    }

    (wallet, client)
}

/// Unwrap the WebAuthn assertion out of a `Signature::Secp256r1`.
pub fn secp256r1_signature(signature: Signature) -> Secp256r1Signature {
    match signature {
        Signature::Secp256r1(signature) => signature,
        _ => panic!("expected a Secp256r1 signature"),
    }
}

// --- Ed25519 -----------------------------------------------------------

pub struct Ed25519Signer {
    pub keypair: SigningKey,
    pub public_key_bytes: [u8; 32],
}

impl Ed25519Signer {
    /// Deterministic signer from a seed byte.
    pub fn new(seed: u8) -> Self {
        let keypair = SigningKey::from_bytes(&[seed; 32]);
        let public_key_bytes = keypair.verifying_key().to_bytes();

        Self {
            keypair,
            public_key_bytes,
        }
    }

    pub fn public_key(&self, env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &self.public_key_bytes)
    }

    pub fn signer_key(&self, env: &Env) -> SignerKey {
        SignerKey::Ed25519(self.public_key(env))
    }

    pub fn signer(
        &self,
        env: &Env,
        expiration: SignerExpiration,
        limits: SignerLimits,
        storage: SignerStorage,
    ) -> Signer {
        Signer::Ed25519(self.public_key(env), expiration, limits, storage)
    }

    pub fn sign(&self, env: &Env, payload: &BytesN<32>) -> Signature {
        Signature::Ed25519(BytesN::from_array(
            env,
            &self.keypair.sign(&payload.to_array()).to_bytes(),
        ))
    }
}

// --- Secp256r1 / WebAuthn ----------------------------------------------

pub struct Passkey {
    pub signing_key: P256SigningKey,
    pub key_id: [u8; 20],
    pub public_key_bytes: [u8; 65],
}

/// Everything a test might want to corrupt about a WebAuthn assertion.
pub struct WebAuthnOptions {
    pub json_type: &'static str,
    pub flags: u8,
    pub truncate_authenticator_data: bool,
    /// Pad authenticatorData with trailing zero bytes (extensions-shaped) to
    /// this total length; the signature is computed over the padded data.
    pub authenticator_data_pad_to: usize,
    pub challenge_override: Option<std::string::String>,
    pub json_pad_to: usize,
    pub malformed_json: bool,
}

impl Default for WebAuthnOptions {
    fn default() -> Self {
        Self {
            json_type: "webauthn.get",
            // UP (0x01) + UV (0x04): what a real platform authenticator sets.
            flags: 0x05,
            truncate_authenticator_data: false,
            authenticator_data_pad_to: 0,
            challenge_override: None,
            json_pad_to: 0,
            malformed_json: false,
        }
    }
}

impl Passkey {
    /// Deterministic passkey from a seed byte (RFC 6979 signing makes every
    /// assertion byte-for-byte reproducible).
    pub fn new(seed: u8) -> Self {
        let signing_key = P256SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public_key_bytes: [u8; 65] = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();

        Self {
            signing_key,
            key_id: [seed; 20],
            public_key_bytes,
        }
    }

    /// Recover the deterministic passkey behind a seeded credential id.
    /// Every `Passkey::new(seed)` uses `[seed; 20]`, so the first byte is the
    /// seed.
    pub fn from_key_id(key_id: &Bytes) -> Self {
        Self::new(key_id.get(0).expect("a non-empty credential id"))
    }

    pub fn key_id(&self, env: &Env) -> Bytes {
        Bytes::from_slice(env, &self.key_id)
    }

    pub fn public_key(&self, env: &Env) -> BytesN<65> {
        BytesN::from_array(env, &self.public_key_bytes)
    }

    pub fn signer_key(&self, env: &Env) -> SignerKey {
        SignerKey::Secp256r1(self.key_id(env))
    }

    pub fn signer(
        &self,
        env: &Env,
        expiration: SignerExpiration,
        limits: SignerLimits,
        storage: SignerStorage,
    ) -> Signer {
        Signer::Secp256r1(
            self.key_id(env),
            self.public_key(env),
            expiration,
            limits,
            storage,
        )
    }

    pub fn sign(&self, env: &Env, payload: &BytesN<32>) -> Signature {
        self.sign_with(env, payload, WebAuthnOptions::default())
    }

    /// A correct GENESIS proof for `signer` on `wallet`.
    pub fn genesis_proof(
        &self,
        env: &Env,
        wallet: &Address,
        signer: &Signer,
    ) -> Secp256r1Signature {
        self.binding_proof(env, wallet, &BindingPurpose::Genesis, signer)
    }

    /// A correct ADD proof for `signer` on `wallet`.
    pub fn add_proof(&self, env: &Env, wallet: &Address, signer: &Signer) -> Secp256r1Signature {
        self.binding_proof(env, wallet, &BindingPurpose::Add, signer)
    }

    /// A correct binding proof for THIS passkey: current network, the wallet
    /// address, the purpose, and the complete signer value.
    pub fn binding_proof(
        &self,
        env: &Env,
        wallet: &Address,
        purpose: &BindingPurpose,
        signer: &Signer,
    ) -> Secp256r1Signature {
        let payload = secp256r1_binding_payload(env, wallet, purpose, signer);

        self.binding_proof_for(env, &payload)
    }

    /// An unlimited, persistent, non-expiring signer — the admin shape the
    /// constructor requires.
    pub fn admin_signer(&self, env: &Env) -> Signer {
        self.signer(
            env,
            SignerExpiration(None),
            SignerLimits(None),
            SignerStorage::Persistent,
        )
    }

    /// A binding proof over an ARBITRARY payload, for the negative vectors
    /// (wrong network, wrong address, wrong public key).
    pub fn binding_proof_for(
        &self,
        env: &Env,
        payload: &Secp256r1BindingPayload,
    ) -> Secp256r1Signature {
        let challenge = secp256r1_binding_challenge(env, payload).to_bytes();

        secp256r1_signature(self.sign(env, &challenge))
    }

    /// Build a WebAuthn assertion over `payload`, shaped like real
    /// authenticator output, with optional corruptions.
    pub fn sign_with(
        &self,
        env: &Env,
        payload: &BytesN<32>,
        options: WebAuthnOptions,
    ) -> Signature {
        let challenge = match &options.challenge_override {
            Some(challenge) => challenge.clone(),
            None => base64_url_encode(&payload.to_array()),
        };

        let mut client_data_json = if options.malformed_json {
            std::string::String::from("this is not json")
        } else {
            std::format!(
                r#"{{"type":"{}","challenge":"{}","origin":"http://localhost:4507","crossOrigin":false}}"#,
                options.json_type,
                challenge
            )
        };

        // Pad with trailing spaces to force an oversized clientDataJSON
        // without changing its JSON meaning.
        while client_data_json.len() < options.json_pad_to {
            client_data_json.push(' ');
        }

        // rpIdHash (32) + flags (1) + signCount (4).
        let mut authenticator_data = std::vec::Vec::new();
        authenticator_data.extend_from_slice(&Sha256::digest(b"localhost"));
        authenticator_data.push(options.flags);
        authenticator_data.extend_from_slice(&[0u8; 4]);

        if options.truncate_authenticator_data {
            authenticator_data.truncate(36);
        }

        while authenticator_data.len() < options.authenticator_data_pad_to {
            authenticator_data.push(0);
        }

        // The signed message per WebAuthn:
        // sha256(authenticatorData || sha256(clientDataJSON)).
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let digest = Sha256::digest(&message);

        let signature: P256Signature = self.signing_key.sign_prehash(&digest).unwrap();
        // The host rejects malleable (high-S) signatures.
        let signature = signature.normalize_s().unwrap_or(signature);

        Signature::Secp256r1(Secp256r1Signature {
            authenticator_data: Bytes::from_slice(env, &authenticator_data),
            client_data_json: Bytes::from_slice(env, client_data_json.as_bytes()),
            signature: BytesN::from_array(env, &signature.to_bytes().into()),
        })
    }
}

pub fn base64_url_encode(bytes: &[u8]) -> std::string::String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

// --- Contexts and payloads ----------------------------------------------

/// An arbitrary fixed payload for direct `__check_auth` invocations.
pub fn payload(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

/// A `transfer`-shaped contract context.
pub fn transfer_context(env: &Env, token: &Address, from: &Address, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: token.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args: (from.clone(), from.clone(), amount).into_val(env),
    })
}

/// A context invoking `fn_name` on `contract` with the given args.
pub fn contract_context(env: &Env, contract: &Address, fn_name: &str, args: Vec<Val>) -> Context {
    Context::Contract(ContractContext {
        contract: contract.clone(),
        fn_name: Symbol::new(env, fn_name),
        args,
    })
}

/// The wallet-self `remove_signer(key)` context.
pub fn remove_signer_context(env: &Env, wallet: &Address, key: &SignerKey) -> Context {
    contract_context(
        env,
        wallet,
        "remove_signer",
        soroban_sdk::vec![env, key.into_val(env)],
    )
}

/// Compute the real Soroban authorization payload hash for a root invocation,
/// mirroring what the host signs for `SorobanCredentials::Address`.
pub fn auth_payload(
    env: &Env,
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: &SorobanAuthorizedInvocation,
) -> BytesN<32> {
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: env.ledger().network_id().to_array().into(),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    let preimage = preimage.to_xdr(Limits::none()).unwrap();
    let preimage = Bytes::from_slice(env, preimage.as_slice());

    env.crypto().sha256(&preimage).to_bytes()
}

/// Build a `transfer` `SorobanAuthorizedInvocation` for full-stack tests.
pub fn transfer_invocation(
    token: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: token.clone().into(),
            function_name: "transfer".try_into().unwrap(),
            args: std::vec![from.clone().into(), to.clone().into(), amount.into(),]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: VecM::default(),
    }
}

/// Build the wallet-self `remove_signer(key)` `SorobanAuthorizedInvocation`
/// for full-stack (address-credential) tests.
pub fn remove_signer_invocation(
    env: &Env,
    wallet: &Address,
    key: &SignerKey,
) -> SorobanAuthorizedInvocation {
    let key_val: Val = key.into_val(env);
    let key_scval = ScVal::try_from_val(env, &key_val).unwrap();

    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: wallet.clone().into(),
            function_name: "remove_signer".try_into().unwrap(),
            args: std::vec![key_scval].try_into().unwrap(),
        }),
        sub_invocations: VecM::default(),
    }
}

/// Extract the last-32-byte ed25519/contract raw key from an Address.
pub fn address_raw_bytes(env: &Env, address: &Address) -> [u8; 32] {
    let bytes = address.clone().to_xdr(env);
    let bytes = bytes.slice(bytes.len() - 32..);
    let mut array = [0u8; 32];
    bytes.copy_into_slice(&mut array);

    array
}
