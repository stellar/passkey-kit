//! Legacy-line smart wallet: the last pre-1.0 contract (`e45c42b9…`, commit
//! aeb04d7) plus two additions that make it a safe in-place upgrade target for
//! every pre-fix wallet still on mainnet:
//!
//! 1. Signer reads accept both pre-1.0 storage layouts (see
//!    `LegacySignerVal`). Wallets built before commit `6a27d48` (2024-12-13)
//!    store a different encoding that every later build fails to decode, which
//!    is why an upgrade to `ecd990f0…`/`e45c42b9…` bricks them.
//! 2. `migrate_signers` re-encodes listed entries into the current layout, and
//!    `get_signer` exposes a read so tooling can verify the result.
//!
//! Everything else, including `require_auth` on `update_signer` (the fix from
//! commit dcc6e3dc9c), the `sw_v1` events, the error codes, and the
//! ledger-sequence expiration semantics, is unchanged from `e45c42b9…`.
#![no_std]

use context::verify_context;
use signer::{
    get_signer_val_storage, normalize_signer, process_signer, store_signer,
    verify_signer_expiration,
};
use smart_wallet_interface::{
    types::{Error, Signature, Signatures, Signer, SignerKey, SignerStorage, SignerVal},
    PolicyClient, SmartWalletInterface,
};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    panic_with_error, symbol_short, BytesN, Env, Symbol, Vec,
};
use storage::extend_instance;
use verify::verify_secp256r1_signature;

mod base64_url;
mod context;
mod signer;
mod storage;
mod types;
mod verify;

#[cfg(test)]
mod tests;

#[contract]
pub struct Contract;

const EVENT_TAG: Symbol = symbol_short!("sw_v1");
const INITIALIZED: Symbol = symbol_short!("init");

#[contractimpl]
impl SmartWalletInterface for Contract {
    fn __constructor(env: Env, signer: Signer) {
        Self::add_signer(env, signer);
    }
    fn add_signer(env: Env, signer: Signer) {
        if env
            .storage()
            .instance()
            .get::<Symbol, bool>(&INITIALIZED)
            .unwrap_or(false)
        {
            env.current_contract_address().require_auth();
        } else {
            env.storage()
                .instance()
                .set::<Symbol, bool>(&INITIALIZED, &true);
        }

        let (signer_key, signer_val, signer_storage) = process_signer(signer);

        store_signer(&env, &signer_key, &signer_val, &signer_storage, false);

        extend_instance(&env);

        env.events().publish(
            (EVENT_TAG, symbol_short!("add"), signer_key),
            (signer_val, signer_storage),
        );
    }
    fn update_signer(env: Env, signer: Signer) {
        env.current_contract_address().require_auth();

        let (signer_key, signer_val, signer_storage) = process_signer(signer);

        store_signer(&env, &signer_key, &signer_val, &signer_storage, true);

        extend_instance(&env);

        env.events().publish(
            (EVENT_TAG, symbol_short!("update"), signer_key),
            (signer_val, signer_storage),
        );
    }
    fn remove_signer(env: Env, signer_key: SignerKey) {
        env.current_contract_address().require_auth();

        match get_signer_val_storage(&env, &signer_key, false) {
            Some((_, signer_storage)) => match signer_storage {
                SignerStorage::Persistent => {
                    env.storage().persistent().remove::<SignerKey>(&signer_key);
                }
                SignerStorage::Temporary => {
                    env.storage().temporary().remove::<SignerKey>(&signer_key);
                }
            },
            None => panic_with_error!(env, Error::NotFound),
        }

        extend_instance(&env);

        env.events()
            .publish((EVENT_TAG, symbol_short!("remove"), signer_key), ());
    }
    fn update_contract_code(env: Env, hash: BytesN<32>) {
        env.current_contract_address().require_auth();

        env.deployer().update_current_contract_wasm(hash);

        extend_instance(&env);
    }
}

#[contractimpl]
impl Contract {
    /// Re-encode the listed signer entries from the pre-`6a27d48` storage
    /// layout into the current one. Returns how many entries were rewritten.
    ///
    /// Deliberately unauthenticated: the rewrite is value-preserving (same
    /// key, public key, expiration, limits, and durability), so there is
    /// nothing for a third party to gain, and it lets an operator normalize
    /// wallets in bulk without each owner's passkey. Reads are tolerant of
    /// both layouts anyway; this exists so a wallet can later move to a
    /// strict build (`ecd990f0…`, `e45c42b9…`, or v1) without decode failures.
    /// Keys that are absent or already current are skipped. Soroban has no
    /// storage iteration, so the caller supplies the keys (the `sw_v1` events
    /// or the passkey indexer list them).
    pub fn migrate_signers(env: Env, signer_keys: Vec<SignerKey>) -> u32 {
        let mut migrated: u32 = 0;

        for signer_key in signer_keys.iter() {
            if normalize_signer(&env, &signer_key) {
                migrated += 1;
            }
        }

        extend_instance(&env);

        migrated
    }

    /// Read a signer entry in the current layout, whatever layout it is
    /// stored in. `None` when no entry exists under the key.
    pub fn get_signer(env: Env, signer_key: SignerKey) -> Option<SignerVal> {
        get_signer_val_storage(&env, &signer_key, false).map(|(signer_val, _)| signer_val)
    }
}

#[contractimpl]
impl CustomAccountInterface for Contract {
    type Error = Error;
    type Signature = Signatures;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Signatures,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        // Check all contexts for an authorizing signature
        for context in auth_contexts.iter() {
            'check: loop {
                for (signer_key, _) in signatures.0.iter() {
                    if let Some((signer_val, _)) = get_signer_val_storage(&env, &signer_key, false)
                    {
                        let (signer_expiration, signer_limits) = match signer_val {
                            SignerVal::Policy(signer_expiration, signer_limits) => {
                                (signer_expiration, signer_limits)
                            }
                            SignerVal::Ed25519(signer_expiration, signer_limits) => {
                                (signer_expiration, signer_limits)
                            }
                            SignerVal::Secp256r1(_, signer_expiration, signer_limits) => {
                                (signer_expiration, signer_limits)
                            }
                        };

                        verify_signer_expiration(&env, signer_expiration);

                        if verify_context(&env, &context, &signer_key, &signer_limits, &signatures)
                        {
                            break 'check;
                        } else {
                            continue;
                        }
                    }
                }

                panic_with_error!(env, Error::MissingContext);
            }
        }

        // Check all signatures for a matching context
        for (signer_key, signature) in signatures.0.iter() {
            // This is probably the only right place to verify_signer_expiration for crypto keys

            match get_signer_val_storage(&env, &signer_key, true) {
                None => panic_with_error!(env, Error::NotFound),
                Some((signer_val, _)) => {
                    match signature {
                        Signature::Policy => {
                            // If there's a policy signer in the signatures map we call it as a full forward of this __check_auth's Vec<Context>
                            if let SignerKey::Policy(policy) = &signer_key {
                                PolicyClient::new(&env, policy).policy__(
                                    &env.current_contract_address(),
                                    &signer_key,
                                    &auth_contexts,
                                );
                                continue;
                            }

                            panic_with_error!(&env, Error::SignatureKeyValueMismatch)
                        }
                        Signature::Ed25519(signature) => {
                            if let SignerKey::Ed25519(public_key) = &signer_key {
                                env.crypto().ed25519_verify(
                                    &public_key,
                                    &signature_payload.clone().into(),
                                    &signature,
                                );
                                continue;
                            }

                            panic_with_error!(&env, Error::SignatureKeyValueMismatch)
                        }
                        Signature::Secp256r1(signature) => {
                            if let SignerVal::Secp256r1(public_key, _, _) = signer_val {
                                verify_secp256r1_signature(
                                    &env,
                                    &signature_payload,
                                    &public_key,
                                    signature,
                                );
                                continue;
                            }

                            panic_with_error!(&env, Error::SignatureKeyValueMismatch)
                        }
                    }
                }
            };
        }

        extend_instance(&env);

        Ok(())
    }
}
