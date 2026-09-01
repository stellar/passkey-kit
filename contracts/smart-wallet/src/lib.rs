#![no_std]

use binding::{
    get_binding_record, move_binding_record, record_key_material, remove_binding_record,
    store_binding_record, verify_binding_proof,
};
use context::verify_context;
use signer::{
    get_signer_val_storage, is_durable, is_durable_admin, is_signer_expired, process_signer,
    signer_expiration, signer_limits, store_signer,
};
use smart_wallet_interface::{
    events::{SignerAdded, SignerRemoved, SignerUpdated, Upgraded},
    types::{
        BindingPurpose, Error, Secp256r1BindingRecord, Secp256r1Signature, Signature, Signatures,
        Signer, SignerKey, SignerStorage, SignerVal,
    },
    PolicyClient, SmartWalletInterface,
};
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl, contractmeta,
    crypto::Hash,
    panic_with_error, symbol_short, Bytes, BytesN, Env, Symbol, Vec,
};
use storage::extend_instance;
use verify::verify_secp256r1_signature;

mod base64_url;
mod binding;
mod context;
mod signer;
mod storage;
mod verify;

#[cfg(test)]
mod tests;

contractmeta!(key = "binver", val = env!("CARGO_PKG_VERSION"));

/// Instance storage key caching the wasm hash installed by the most recent
/// `upgrade`. Absent until the first upgrade (a contract cannot read its own
/// executable hash from the host). Sourced for `Upgraded.old_hash`.
const WASM_HASH: Symbol = symbol_short!("wasm_hash");

/// Instance storage key counting the wallet's DURABLE ADMIN signers (see
/// `is_durable_admin`: Persistent + non-expiring + independently
/// admin-capable). Storage cannot be enumerated, so the count is maintained
/// across `__constructor`/`add_signer`/`update_signer`/`remove_signer` and
/// backs the `Error::LastAdminSigner` guard: the count may never go from
/// nonzero to zero, because with zero admin-capable signers no
/// `add_signer`/`upgrade` could ever be authorized again, and the contract
/// code is immutable.
///
/// Legacy caveat: a wallet upgraded from a pre-1.0 wasm starts at 0 and the
/// counter PERMANENTLY undercounts its pre-existing admins — signers already
/// in storage are never learned (no enumeration), so the count only tracks
/// admins added or promoted after the upgrade. Strictly fail-SAFE: an
/// undercount can only make the guard refuse removals/demotions that would
/// actually be safe (pre-existing admins stay effectively pinned unless a
/// post-upgrade admin is counted); it can never permit the nonzero→zero
/// transition.
const ADMIN_COUNT: Symbol = symbol_short!("admins");

/// Instance storage key counting the wallet's DURABLE signers (`is_durable`:
/// `Persistent` + non-expiring, ANY limits). Backs the `Error::LastSigner`
/// guard: any transition that would take this count from one to zero —
/// removing the last durable signer, demoting it via `update_signer` to
/// Temporary or to an expiring value, or constructing a wallet with no
/// durable signer at all — is rejected, so the wallet always holds at least
/// one signer that cannot silently disappear.
///
/// EXACT by construction (drift-free): durable entries enter and leave
/// storage only through counter-tracked calls (`__constructor`/`add_signer`/
/// `update_signer`/`remove_signer`). Non-durable signers are deliberately
/// NOT counted — Temporary entries evict and expiring entries lapse with no
/// contract call the counter could observe, so including them would inflate
/// the count above the live-signer set and let a "guarded" removal reach
/// zero live signers (the exact drift this design eliminates).
///
/// This is the classification-independent backstop beneath the richer
/// `ADMIN_COUNT` guard: even if some admin-capable limits shape is
/// mis-classified there, at least one durable signer always survives.
/// Legacy caveat: a pre-1.0 wallet upgraded to this wasm starts at 0 and
/// permanently undercounts pre-existing durable signers (no enumeration
/// exists) — strictly fail-safe: over-refuses, never over-allows.
const DURABLE_COUNT: Symbol = symbol_short!("durable");

#[contract]
pub struct Contract;

impl Contract {
    fn admin_count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<Symbol, u32>(&ADMIN_COUNT)
            .unwrap_or(0)
    }

    fn set_admin_count(env: &Env, count: u32) {
        env.storage()
            .instance()
            .set::<Symbol, u32>(&ADMIN_COUNT, &count);
    }

    fn durable_count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<Symbol, u32>(&DURABLE_COUNT)
            .unwrap_or(0)
    }

    fn set_durable_count(env: &Env, count: u32) {
        env.storage()
            .instance()
            .set::<Symbol, u32>(&DURABLE_COUNT, &count);
    }

    fn add_signer_impl(env: &Env, signer: Signer) -> Result<(), Error> {
        let (signer_key, signer_val, signer_storage) = process_signer(signer);

        store_signer(env, &signer_key, &signer_val, &signer_storage, false)?;

        if is_durable(&signer_val, &signer_storage) {
            Self::set_durable_count(env, Self::durable_count(env) + 1);
        }

        if is_durable_admin(env, &signer_val, &signer_storage) {
            Self::set_admin_count(env, Self::admin_count(env) + 1);
        }

        // Policy signers get their install hook invoked (the policy sees the
        // wallet as its authenticated invoker). A failing install aborts the
        // add — policies must opt in to being attached.
        if let SignerKey::Policy(policy) = &signer_key {
            PolicyClient::new(env, policy).install(&env.current_contract_address());
        }

        extend_instance(env);

        SignerAdded {
            key: signer_key,
            val: signer_val,
            storage: signer_storage,
        }
        .publish(env);

        Ok(())
    }

    /// The Secp256r1 fields a binding commits to, if `signer` is a passkey.
    fn secp256r1_binding_parts(signer: &Signer) -> Option<(Bytes, BytesN<65>, SignerStorage)> {
        match signer {
            Signer::Secp256r1(key_id, public_key, _, _, signer_storage) => {
                Some((key_id.clone(), public_key.clone(), signer_storage.clone()))
            }
            _ => None,
        }
    }

    /// Add a signer under the binding protocol: a Secp256r1 signer MUST
    /// carry a proof (verified, then stored with the signer); any other
    /// signer MUST NOT.
    fn add_signer_with_proof(
        env: &Env,
        signer: Signer,
        proof: Option<Secp256r1Signature>,
        purpose: BindingPurpose,
    ) -> Result<(), Error> {
        match (Self::secp256r1_binding_parts(&signer), proof) {
            (Some((key_id, _, signer_storage)), Some(proof)) => {
                // Cheap duplicate check before the expensive proof
                // verification (`store_signer` re-checks; this only saves the
                // budget of verifying a proof for a doomed add).
                if get_signer_val_storage(env, &SignerKey::Secp256r1(key_id.clone()), false)
                    .is_some()
                {
                    return Err(Error::SignerAlreadyExists);
                }

                // The challenge commits to `purpose` and to every field of
                // `signer`, so a proof minted for the other entry point or for
                // any other signer shape fails here.
                verify_binding_proof(env, &purpose, &signer, proof.clone())?;

                // The record keeps the ORIGINAL signer, which is what the
                // holder actually signed. `update_signer` may reshape the live
                // entry later; the attestation must not drift with it.
                let record = Secp256r1BindingRecord {
                    signer: signer.clone(),
                    purpose,
                    proof,
                };

                Self::add_signer_impl(env, signer)?;

                store_binding_record(env, &key_id, &record, &signer_storage);

                Ok(())
            }
            (Some(_), None) => Err(Error::BindingProofRequired),
            (None, Some(_)) => Err(Error::BindingProofUnexpected),
            (None, None) => Self::add_signer_impl(env, signer),
        }
    }
}

#[contractimpl]
impl SmartWalletInterface for Contract {
    fn __constructor(env: Env, signer: Signer, proof: Option<Secp256r1Signature>) {
        // Deploy-time-only initialization (CAP-0058 constructor). There is no
        // init flag and no un-authenticated first-add path. A passkey first
        // signer must prove it consented to THIS address on THIS network for
        // the GENESIS purpose and for this exact signer value.
        //
        // Every panic below unwinds the whole `CreateContractV2`, so a
        // rejected constructor leaves no instance and no storage behind.
        if let Err(error) =
            Self::add_signer_with_proof(&env, signer, proof, BindingPurpose::Genesis)
        {
            panic_with_error!(env, error);
        }

        // A wallet born without a durable (Persistent + non-expiring) signer
        // could reach zero live signers with no contract call — a Temporary
        // first signer evicts, an expiring one lapses — and nothing on-chain
        // can observe or prevent that. The first signer must be durable.
        if Self::durable_count(&env) == 0 {
            panic_with_error!(env, Error::LastSigner);
        }

        // Durability alone is not viability. A durable signer with no
        // independent admin authority — `SignerLimits(Some(empty))`, or a
        // wallet-self grant that needs a co-signer nobody holds — yields a
        // wallet that can never authorize `add_signer` or `upgrade` again.
        // That state is unrecoverable and can still receive funds, so the
        // first signer must ALSO be a durable admin.
        //
        // A durable admin is by definition durable, so this subsumes the
        // check above; the `LastSigner` guard is kept as an independent
        // backstop against a mis-classification in `is_durable_admin`.
        if Self::admin_count(&env) == 0 {
            panic_with_error!(env, Error::LastAdminSigner);
        }
    }

    fn add_signer(env: Env, signer: Signer) -> Result<(), Error> {
        env.current_contract_address().require_auth();

        // Passkeys enter only with a binding proof. Reject here rather than
        // silently storing an unbound Secp256r1 signer.
        if matches!(signer, Signer::Secp256r1(..)) {
            return Err(Error::BindingProofRequired);
        }

        Self::add_signer_impl(&env, signer)
    }

    fn add_secp256r1(env: Env, signer: Signer, proof: Secp256r1Signature) -> Result<(), Error> {
        env.current_contract_address().require_auth();

        if !matches!(signer, Signer::Secp256r1(..)) {
            return Err(Error::BindingProofUnexpected);
        }

        Self::add_signer_with_proof(&env, signer, Some(proof), BindingPurpose::Add)
    }

    fn update_signer(env: Env, signer: Signer) -> Result<(), Error> {
        env.current_contract_address().require_auth();

        // A Secp256r1 public key is immutable: the binding proof commits to
        // it. Checked BEFORE any write so a rejected update leaves no trace.
        if let Signer::Secp256r1(key_id, public_key, _, _, _) = &signer {
            if let Some((SignerVal::Secp256r1(stored_public_key, _, _), _)) =
                get_signer_val_storage(&env, &SignerKey::Secp256r1(key_id.clone()), false)
            {
                if stored_public_key != *public_key {
                    return Err(Error::BindingPublicKeyImmutable);
                }
            }
        }

        let (signer_key, signer_val, signer_storage) = process_signer(signer);

        let (old_val, old_storage) =
            store_signer(&env, &signer_key, &signer_val, &signer_storage, true)?
                .ok_or(Error::SignerNotFound)?;

        // Durable-admin accounting. Demoting the LAST durable admin (limiting
        // it, adding an expiration, or moving it to Temporary) closes the
        // wallet's admin surface exactly like removing it — reject.
        let was_admin = is_durable_admin(&env, &old_val, &old_storage);
        let is_admin = is_durable_admin(&env, &signer_val, &signer_storage);
        if was_admin && !is_admin {
            let count = Self::admin_count(&env);
            if count <= 1 {
                return Err(Error::LastAdminSigner);
            }
            Self::set_admin_count(&env, count - 1);
        } else if !was_admin && is_admin {
            Self::set_admin_count(&env, Self::admin_count(&env) + 1);
        }

        // Durable accounting (the LastSigner backstop). Demoting the LAST
        // durable signer to Temporary or to an expiring value would let it
        // later evict/lapse to zero live signers with no call to guard —
        // reject the 1→0 transition here, at the only moment it is visible.
        let was_durable = is_durable(&old_val, &old_storage);
        let now_durable = is_durable(&signer_val, &signer_storage);
        if was_durable && !now_durable {
            let count = Self::durable_count(&env);
            if count <= 1 {
                return Err(Error::LastSigner);
            }
            Self::set_durable_count(&env, count - 1);
        } else if !was_durable && now_durable {
            Self::set_durable_count(&env, Self::durable_count(&env) + 1);
        }

        // The binding record lives in its signer's durability: follow a flip.
        if let SignerKey::Secp256r1(key_id) = &signer_key {
            move_binding_record(&env, key_id, &old_storage, &signer_storage);
        }

        extend_instance(&env);

        SignerUpdated {
            key: signer_key,
            val: signer_val,
            storage: signer_storage,
            old_storage,
        }
        .publish(&env);

        Ok(())
    }

    fn remove_signer(env: Env, signer_key: SignerKey) -> Result<(), Error> {
        env.current_contract_address().require_auth();

        let (signer_val, signer_storage) =
            get_signer_val_storage(&env, &signer_key, false).ok_or(Error::SignerNotFound)?;

        // Never remove the wallet's LAST durable admin signer:
        // from zero unlimited signers no add_signer/upgrade can ever be
        // authorized again, and the contract code is immutable.
        // This guard runs at execution time, so it also covers the pass-1
        // self-removal special case: a sole admin can AUTHORIZE its own
        // removal, but the removal itself still fails here.
        if is_durable_admin(&env, &signer_val, &signer_storage) {
            let count = Self::admin_count(&env);
            if count <= 1 {
                return Err(Error::LastAdminSigner);
            }
            Self::set_admin_count(&env, count - 1);
        }

        // Terminal backstop, beneath (and independent of) the admin
        // classification above: NEVER remove the wallet's last DURABLE
        // signer. Since a wallet is born with a durable signer and every
        // durable 1→0 transition (remove here, demote in update_signer) is
        // rejected, at least one signer that cannot silently evict or expire
        // always exists — a zero-live-signer wallet is unreachable. The
        // counter deliberately ignores non-durable signers: they can vanish
        // with no contract call, and counting them is exactly what would let
        // this guard drift open.
        if is_durable(&signer_val, &signer_storage) {
            let count = Self::durable_count(&env);
            if count <= 1 {
                return Err(Error::LastSigner);
            }
            Self::set_durable_count(&env, count - 1);
        }

        match &signer_storage {
            SignerStorage::Persistent => {
                env.storage().persistent().remove::<SignerKey>(&signer_key);
            }
            SignerStorage::Temporary => {
                env.storage().temporary().remove::<SignerKey>(&signer_key);
            }
        }

        // A passkey's binding leaves with it; re-adding the key needs a
        // fresh proof through `add_secp256r1`.
        if let SignerKey::Secp256r1(key_id) = &signer_key {
            remove_binding_record(&env, key_id, &signer_storage);
        }

        // Removal is pure wallet state — NO policy code runs on this
        // path. Calling the policy's `uninstall` here
        // would let a rejecting/broken policy block its own removal: `try_*`
        // recovers only *recoverable* contract errors, so a policy that
        // exhausts the transaction budget triggers a non-recoverable
        // Budget/Storage ExceededLimit that unwinds the whole atomic
        // transaction and rolls the removal back. Policies instead self-clean
        // their install-state via the permissionless `uninstall` entrypoint,
        // which verifies the signer is actually gone before acting.
        extend_instance(&env);

        SignerRemoved {
            key: signer_key,
            storage: signer_storage,
        }
        .publish(&env);

        Ok(())
    }

    fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        env.current_contract_address().require_auth();

        let old_hash = env
            .storage()
            .instance()
            .get::<Symbol, BytesN<32>>(&WASM_HASH);

        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());

        env.storage()
            .instance()
            .set::<Symbol, BytesN<32>>(&WASM_HASH, &new_wasm_hash);

        extend_instance(&env);

        Upgraded {
            old_hash,
            new_hash: new_wasm_hash,
        }
        .publish(&env);

        Ok(())
    }

    fn get_signer(env: Env, signer_key: SignerKey) -> Option<SignerVal> {
        get_signer_val_storage(&env, &signer_key, false).map(|(signer_val, _)| signer_val)
    }

    fn get_secp256r1_binding(env: Env, key_id: Bytes) -> Option<Secp256r1BindingRecord> {
        let (record, _) = get_binding_record(&env, &key_id)?;

        // Equality invariant: a record is meaningful only for the signer it
        // names. Under this code the two agree by construction; a record
        // written by other code that disagrees is filtered, not trusted.
        //
        // Only the IMMUTABLE key material is compared. `update_signer` may
        // legitimately reshape expiration, limits, and storage, and the record
        // deliberately keeps the original value it attests to, so comparing
        // the whole signer would drop a valid record after any policy edit.
        let (record_key_id, record_public_key) = record_key_material(&record)?;
        let (signer_val, _) =
            get_signer_val_storage(&env, &SignerKey::Secp256r1(key_id.clone()), false)?;

        match signer_val {
            SignerVal::Secp256r1(public_key, _, _)
                if record_key_id == key_id && record_public_key == public_key =>
            {
                Some(record)
            }
            _ => None,
        }
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
        // Pass 1 — context coverage. Every context must be authorizable by at
        // least one signer in the signatures map. `verify_context` rejects a
        // candidate boolean-ly for every RECOVERABLE failure (wrong shape,
        // missing co-signer, rejecting/failing policy via `try_policy__`), so
        // such a candidate never fails the attempt for other candidates.
        // CAVEAT: non-recoverable host errors (Budget/Storage ExceededLimit)
        // raised inside a required policy are NOT contained by `try_policy__`
        // and abort the whole authorization — a pathological co-signer policy
        // can DoS an otherwise-coverable auth (never make a bad auth
        // succeed). Exposure is minimized by invoking policies only after
        // every other candidate check has passed (see
        // `verify_signer_limit_keys`). Expiration is deliberately NOT checked
        // here — pass 2 is the single point of truth and fails the whole
        // auth if ANY map entry is expired.
        for context in auth_contexts.iter() {
            let mut covered = false;

            for (signer_key, _) in signatures.0.iter() {
                if let Some((signer_val, _)) = get_signer_val_storage(&env, &signer_key, false) {
                    if verify_context(
                        &env,
                        &context,
                        &signer_key,
                        signer_limits(&signer_val),
                        &signatures,
                    ) {
                        covered = true;
                        break;
                    }
                }
            }

            if !covered {
                return Err(Error::MissingContext);
            }
        }

        // Pass 2 — verify EVERY signatures map entry: it must be stored on
        // this wallet, unexpired, and its signature material must verify.
        // Include only signatures that are needed; an invalid or expired
        // extra entry fails the entire authorization (deterministically,
        // regardless of map order).
        for (signer_key, signature) in signatures.0.iter() {
            let (signer_val, _) =
                get_signer_val_storage(&env, &signer_key, true).ok_or(Error::SignerNotFound)?;

            if is_signer_expired(&env, signer_expiration(&signer_val)) {
                return Err(Error::SignerExpired);
            }

            match signature {
                Signature::Policy => {
                    if let SignerKey::Policy(policy) = &signer_key {
                        // A policy signature carries no cryptographic material,
                        // so every policy entry must consult `policy__`, including
                        // sole self-removal. A rejecting policy therefore vetoes
                        // its removal. Another wallet signer can still authorize
                        // `remove_signer` without including this policy entry.
                        // Policy-as-signature sees the FULL context list (a policy
                        // used inside another signer's limits sees one context at
                        // a time). A rejecting policy fails the whole auth.
                        PolicyClient::new(&env, policy).policy__(
                            &env.current_contract_address(),
                            &signer_key,
                            &auth_contexts,
                        );
                    } else {
                        return Err(Error::SignatureKeyValueMismatch);
                    }
                }
                Signature::Ed25519(signature) => {
                    if let SignerKey::Ed25519(public_key) = &signer_key {
                        env.crypto().ed25519_verify(
                            public_key,
                            &signature_payload.clone().into(),
                            &signature,
                        );
                    } else {
                        return Err(Error::SignatureKeyValueMismatch);
                    }
                }
                Signature::Secp256r1(signature) => {
                    if let SignerVal::Secp256r1(public_key, _, _) = &signer_val {
                        verify_secp256r1_signature(
                            &env,
                            &signature_payload,
                            public_key,
                            signature,
                        )?;
                    } else {
                        return Err(Error::SignatureKeyValueMismatch);
                    }
                }
            }
        }

        extend_instance(&env);

        Ok(())
    }
}
