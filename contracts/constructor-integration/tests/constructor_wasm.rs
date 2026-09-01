use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature as P256Signature, SigningKey};
use sha2::{Digest, Sha256};
use smart_wallet::ContractClient;
use smart_wallet_interface::{
    binding::{secp256r1_binding_challenge, secp256r1_binding_payload},
    types::{
        BindingPurpose, Secp256r1Signature, Signer, SignerExpiration, SignerKey, SignerLimits,
        SignerStorage,
    },
};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

const WALLET_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/smart_wallet.wasm"));
const DEPLOYER: &str = "GC2C7AWLS2FMFTQAHW3IBUB4ZXVP4E37XNLEF2IK7IVXBB6CMEPCSXFO";

/// Test-only transaction boundary around the standard `deploy_v2` host call.
/// This contract is not a product factory and is never built for deployment.
#[contract]
struct DeploymentHarness;

#[contractimpl]
impl DeploymentHarness {
    pub fn deploy(
        env: Env,
        deployer: Address,
        salt: BytesN<32>,
        wasm_hash: BytesN<32>,
        signer: Signer,
        proof: Secp256r1Signature,
    ) -> Address {
        deployer.require_auth();
        env.deployer()
            .with_address(deployer, salt)
            .deploy_v2(wasm_hash, (signer, Some(proof)))
    }
}

struct Passkey {
    signing_key: SigningKey,
    key_id: [u8; 20],
    public_key: [u8; 65],
}

impl Passkey {
    fn new(seed: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        Self {
            signing_key,
            key_id: [seed; 20],
            public_key,
        }
    }

    fn key_id(&self, env: &Env) -> Bytes {
        Bytes::from_slice(env, &self.key_id)
    }

    fn public_key(&self, env: &Env) -> BytesN<65> {
        BytesN::from_array(env, &self.public_key)
    }

    fn signer(&self, env: &Env) -> Signer {
        Signer::Secp256r1(
            self.key_id(env),
            self.public_key(env),
            SignerExpiration(None),
            SignerLimits(None),
            SignerStorage::Persistent,
        )
    }

    /// A GENESIS proof for this passkey's `signer` on `wallet` — what the
    /// production deploy path mints before it builds the transaction.
    fn genesis_proof(&self, env: &Env, wallet: &Address, signer: &Signer) -> Secp256r1Signature {
        let payload = secp256r1_binding_payload(env, wallet, &BindingPurpose::Genesis, signer);
        let challenge = secp256r1_binding_challenge(env, &payload).to_array();
        let challenge = URL_SAFE_NO_PAD.encode(challenge);
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://app.example","crossOrigin":false}}"#
        );

        let mut authenticator_data = Vec::from(Sha256::digest(b"app.example").as_slice());
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&[0u8; 4]);

        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let digest = Sha256::digest(signed);
        let signature: P256Signature = self.signing_key.sign_prehash(&digest).unwrap();
        let signature = signature.normalize_s().unwrap_or(signature);

        Secp256r1Signature {
            authenticator_data: Bytes::from_slice(env, &authenticator_data),
            client_data_json: Bytes::from_slice(env, client_data_json.as_bytes()),
            signature: BytesN::from_array(env, &signature.to_bytes().into()),
        }
    }
}

fn setup() -> (Env, Address, BytesN<32>) {
    let env = Env::default();
    env.mock_all_auths();
    let deployer = Address::from_str(&env, DEPLOYER);
    let wasm_hash = env.deployer().upload_contract_wasm(WALLET_WASM);
    (env, deployer, wasm_hash)
}

#[test]
fn valid_proof_deploys_real_wasm_through_create_contract_v2() {
    let (env, deployer, wasm_hash) = setup();
    let passkey = Passkey::new(1);
    let salt = env.crypto().sha256(&passkey.key_id(&env)).to_bytes();
    let deployment = env.deployer().with_address(deployer.clone(), salt.clone());
    let expected = deployment.deployed_address();
    let signer = passkey.signer(&env);
    let proof = passkey.genesis_proof(&env, &expected, &signer);

    // This is the production account-deployer path. The harness below exists
    // only for the failed-call rollback boundary in the second test.
    let wallet = deployment.deploy_v2(wasm_hash, (signer.clone(), Some(proof)));
    assert_eq!(wallet, expected);

    let client = ContractClient::new(&env, &wallet);
    let record = client
        .get_secp256r1_binding(&passkey.key_id(&env))
        .expect("the constructor stored a genesis binding record");
    assert_eq!(record.purpose, BindingPurpose::Genesis);
    assert_eq!(
        record.signer, signer,
        "the record keeps the exact signer the proof committed to"
    );
    assert!(client
        .get_signer(&SignerKey::Secp256r1(passkey.key_id(&env)))
        .is_some());
}

#[test]
fn invalid_proof_aborts_deployment_atomically() {
    let (env, deployer, wasm_hash) = setup();
    let passkey = Passkey::new(2);
    let salt = env.crypto().sha256(&passkey.key_id(&env)).to_bytes();
    let expected = env
        .deployer()
        .with_address(deployer.clone(), salt.clone())
        .deployed_address();
    let wrong_address = Address::from_str(
        &env,
        "CC2R2H3DTXS7OCNV3FTNPAZYIRCY2L2OTBG5FZWJV63HXQ35WB2T2NWJ",
    );
    let signer = passkey.signer(&env);
    let wrong_proof = passkey.genesis_proof(&env, &wrong_address, &signer);

    let harness_address = env.register(DeploymentHarness, ());
    let harness = DeploymentHarnessClient::new(&env, &harness_address);
    let failed = harness.try_deploy(
        &deployer,
        &salt,
        &wasm_hash,
        &passkey.signer(&env),
        &wrong_proof,
    );
    assert!(failed.is_err());

    let correct_proof = passkey.genesis_proof(&env, &expected, &signer);
    let wallet = harness.deploy(
        &deployer,
        &salt,
        &wasm_hash,
        &passkey.signer(&env),
        &correct_proof,
    );
    assert_eq!(wallet, expected, "the failed constructor left no instance");
}
