//! Deterministic hidden-authority recovery from a wallet's BIP-39 seed.
//!
//! These derivations are wallet policy, not on-chain validity rules. They make
//! a 64-byte wallet seed plus a nonsecret list of canonical names sufficient
//! to recover each per-name Orchard authority and every epoch COMMIT opening.

use coppice_names::{
    protocol::{BOND_ZATOSHIS, CanonicalUa, CommitRef, Commitment, FieldElement, Name, StateRef},
    statement::{registration_commitment, ua_field},
};
use orchard::{
    circuit::state_note_binding::v2::owner_commitment,
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{Note, NoteVersion, RandomSeed, Rho},
    value::NoteValue,
};
use pasta_curves::{
    group::ff::{FromUniformBytes, PrimeField},
    pallas,
};
use zeroize::Zeroizing;

const WALLET_SEED_BYTES: usize = 64;

/// Deterministic COMMIT material. The secret is never serialized by this
/// crate; it is supplied directly to the REVEAL prover and then dropped.
pub struct CommitOpening {
    commitment: Commitment,
    secret: FieldElement,
}

impl CommitOpening {
    pub const fn commitment(&self) -> Commitment {
        self.commitment
    }

    pub const fn secret(&self) -> FieldElement {
        self.secret
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    WrongSeedLength,
    AuthorityDerivationExhausted,
    CommitDerivationExhausted,
    InvalidActionNullifier,
    NoteDerivationExhausted,
}

/// Derives the deployment- and name-separated hidden Orchard spending key.
pub fn derive_name_spending_key(
    wallet_seed: &[u8],
    deployment_id: [u8; 32],
    name: &Name,
) -> Result<SpendingKey, RecoveryError> {
    let master = derive_names_master(wallet_seed)?;

    for retry in 0..=u32::MAX {
        let mut input = Vec::with_capacity(32 + 1 + name.as_bytes().len() + 4);
        input.extend_from_slice(&deployment_id);
        input.push(u8::try_from(name.as_bytes().len()).expect("canonical name length fits u8"));
        input.extend_from_slice(name.as_bytes());
        input.extend_from_slice(&retry.to_be_bytes());
        let candidate = Zeroizing::new(keyed_hash32(b"CoppiceNmOwner", &master[..], &input));
        if let Some(spending_key) = Option::<SpendingKey>::from(SpendingKey::from_bytes(*candidate))
        {
            return Ok(spending_key);
        }
    }
    Err(RecoveryError::AuthorityDerivationExhausted)
}

pub(crate) fn derive_names_master(
    wallet_seed: &[u8],
) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    if wallet_seed.len() != WALLET_SEED_BYTES {
        return Err(RecoveryError::WrongSeedLength);
    }
    let mut root_input = Zeroizing::new(Vec::with_capacity(2 + wallet_seed.len()));
    root_input.extend_from_slice(&(wallet_seed.len() as u16).to_be_bytes());
    root_input.extend_from_slice(wallet_seed);
    Ok(Zeroizing::new(hash32(b"CoppiceNmRoot_", &root_input)))
}

/// Derives the first nonzero epoch-specific secret whose complete hidden
/// registration relation also produces a nonzero canonical COMMIT value.
pub fn derive_commit_opening(
    spending_key: &SpendingKey,
    deployment_id: [u8; 32],
    name: &Name,
    target_epoch: u32,
) -> Result<CommitOpening, RecoveryError> {
    let name_id = name
        .id()
        .map_err(|_| RecoveryError::CommitDerivationExhausted)?;
    let owner = FieldElement::from_bytes(owner_commitment(spending_key).to_bytes())
        .map_err(|_| RecoveryError::CommitDerivationExhausted)?;
    let key = Zeroizing::new(*spending_key.to_bytes());
    for retry in 0..=u32::MAX {
        let mut input = Vec::with_capacity(32 + 4 + 4);
        input.extend_from_slice(&deployment_id);
        input.extend_from_slice(&target_epoch.to_be_bytes());
        input.extend_from_slice(&retry.to_be_bytes());
        let uniform = Zeroizing::new(keyed_hash64(b"CoppiceNmComS", &key[..], &input));
        let candidate = pallas::Base::from_uniform_bytes(&uniform);
        if candidate == pallas::Base::zero() {
            continue;
        }
        let secret = FieldElement::from_bytes(candidate.to_repr())
            .map_err(|_| RecoveryError::CommitDerivationExhausted)?;
        let commitment =
            registration_commitment(deployment_id, name_id, target_epoch, owner, secret);
        if let Ok(commitment) = Commitment::from_bytes(commitment) {
            return Ok(CommitOpening { commitment, secret });
        }
    }
    Err(RecoveryError::CommitDerivationExhausted)
}

/// Reconstructs the exact REVEAL successor bond note from canonical public
/// inputs and the recoverable per-name key.
pub fn derive_reveal_bond_note(
    spending_key: &SpendingKey,
    deployment_id: [u8; 32],
    commit_ref: CommitRef,
    target_epoch: u32,
    ua: &CanonicalUa,
    action_index: u32,
    action_nullifier: FieldElement,
) -> Result<Note, RecoveryError> {
    let mut reference = Vec::with_capacity(40);
    reference.extend_from_slice(&commit_ref.height.to_be_bytes());
    reference.extend_from_slice(&commit_ref.tx_index.to_be_bytes());
    reference.extend_from_slice(&commit_ref.txid);
    derive_bond_note(
        spending_key,
        deployment_id,
        1,
        &reference,
        target_epoch,
        ua,
        action_index,
        action_nullifier,
    )
}

/// Reconstructs the exact REFRESH successor bond note from canonical public
/// inputs and the recoverable per-name key.
pub fn derive_refresh_bond_note(
    spending_key: &SpendingKey,
    deployment_id: [u8; 32],
    predecessor_ref: StateRef,
    target_epoch: u32,
    ua: &CanonicalUa,
    action_index: u32,
    action_nullifier: FieldElement,
) -> Result<Note, RecoveryError> {
    let mut reference = Vec::with_capacity(44);
    reference.extend_from_slice(&predecessor_ref.height.to_be_bytes());
    reference.extend_from_slice(&predecessor_ref.tx_index.to_be_bytes());
    reference.extend_from_slice(&predecessor_ref.txid);
    reference.extend_from_slice(&predecessor_ref.action_index.to_be_bytes());
    derive_bond_note(
        spending_key,
        deployment_id,
        2,
        &reference,
        target_epoch,
        ua,
        action_index,
        action_nullifier,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_bond_note(
    spending_key: &SpendingKey,
    deployment_id: [u8; 32],
    operation_tag: u8,
    reference: &[u8],
    target_epoch: u32,
    ua: &CanonicalUa,
    action_index: u32,
    action_nullifier: FieldElement,
) -> Result<Note, RecoveryError> {
    let rho = Option::<Rho>::from(Rho::from_bytes(&action_nullifier.to_bytes()))
        .ok_or(RecoveryError::InvalidActionNullifier)?;
    let key = Zeroizing::new(*spending_key.to_bytes());
    let ua = ua_field(ua).to_repr();
    let fvk = FullViewingKey::from(spending_key);
    for retry in 0..=u32::MAX {
        let mut input = Vec::with_capacity(32 + 1 + reference.len() + 4 + 32 + 4 + 32 + 4);
        input.extend_from_slice(&deployment_id);
        input.push(operation_tag);
        input.extend_from_slice(reference);
        input.extend_from_slice(&target_epoch.to_be_bytes());
        input.extend_from_slice(&ua);
        input.extend_from_slice(&action_index.to_be_bytes());
        input.extend_from_slice(&action_nullifier.to_bytes());
        input.extend_from_slice(&retry.to_be_bytes());
        let candidate = Zeroizing::new(keyed_hash32(b"CoppiceNmNote_", &key[..], &input));
        let Some(seed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(*candidate, &rho))
        else {
            continue;
        };
        if let Some(note) = Option::<Note>::from(Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(BOND_ZATOSHIS),
            rho,
            seed,
            NoteVersion::V3,
        )) {
            return Ok(note);
        }
    }
    Err(RecoveryError::NoteDerivationExhausted)
}

fn hash32(personalization: &[u8], input: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .hash(input)
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-256 output")
}

fn keyed_hash32(personalization: &[u8], key: &[u8], input: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personalization)
        .key(key)
        .hash(input)
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-256 output")
}

fn keyed_hash64(personalization: &[u8], key: &[u8], input: &[u8]) -> [u8; 64] {
    blake2b_simd::Params::new()
        .hash_length(64)
        .personal(personalization)
        .key(key)
        .hash(input)
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-512 output")
}

#[cfg(test)]
mod tests {
    use super::*;
    use coppice_names::protocol::Network;
    use orchard::note::ExtractedNoteCommitment;

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    #[test]
    fn authority_and_commit_opening_are_recoverable_and_separated() {
        let seed = [7; 64];
        let deployment = [9; 32];
        let alice = Name::parse("alice").unwrap();
        let bob = Name::parse("bob").unwrap();
        let alice_key = derive_name_spending_key(&seed, deployment, &alice).unwrap();
        let repeated = derive_name_spending_key(&seed, deployment, &alice).unwrap();
        let bob_key = derive_name_spending_key(&seed, deployment, &bob).unwrap();
        let other_deployment = derive_name_spending_key(&seed, [8; 32], &alice).unwrap();
        assert_eq!(alice_key.to_bytes(), repeated.to_bytes());
        assert_ne!(alice_key.to_bytes(), bob_key.to_bytes());
        assert_ne!(alice_key.to_bytes(), other_deployment.to_bytes());

        let epoch_17 = derive_commit_opening(&alice_key, deployment, &alice, 17).unwrap();
        let repeated = derive_commit_opening(&alice_key, deployment, &alice, 17).unwrap();
        let epoch_18 = derive_commit_opening(&alice_key, deployment, &alice, 18).unwrap();
        assert_eq!(
            hex::encode(alice_key.to_bytes()),
            "31206cb680820f5154e2542c3c894895d755b3d56225cfdb47d4ce09a4f73142"
        );
        assert_eq!(
            hex::encode(epoch_17.commitment().to_bytes()),
            "bd0f7bf9c244c069c2216f451cce26101907dd3aac8d188975e7ad9f7abcb514"
        );
        assert_eq!(
            hex::encode(epoch_17.secret().to_bytes()),
            "67e9e45bdedc56834f2e7770eeac239ed443b78517c5562ae522c78e3eae9614"
        );
        assert_eq!(epoch_17.commitment(), repeated.commitment());
        assert_eq!(epoch_17.secret(), repeated.secret());
        assert_ne!(epoch_17.commitment(), epoch_18.commitment());
        assert_ne!(epoch_17.secret(), epoch_18.secret());
    }

    #[test]
    fn authority_requires_the_wallets_exact_seed_width() {
        let name = Name::parse("alice").unwrap();
        for len in [0, 32, 63, 65] {
            assert_eq!(
                derive_name_spending_key(&vec![7; len], [9; 32], &name).map(|_| ()),
                Err(RecoveryError::WrongSeedLength)
            );
        }
    }

    #[test]
    fn bond_note_reconstruction_is_deterministic_and_context_bound() {
        let deployment = [9; 32];
        let name = Name::parse("alice").unwrap();
        let key = derive_name_spending_key(&[7; 64], deployment, &name).unwrap();
        let ua = CanonicalUa::parse(Network::Regtest, UA).unwrap();
        let action_nullifier = FieldElement::from_bytes(pallas::Base::from(33).to_repr()).unwrap();
        let reference = CommitRef {
            height: 120,
            tx_index: 2,
            txid: [4; 32],
        };
        let note =
            derive_reveal_bond_note(&key, deployment, reference, 17, &ua, 3, action_nullifier)
                .unwrap();
        let repeated =
            derive_reveal_bond_note(&key, deployment, reference, 17, &ua, 3, action_nullifier)
                .unwrap();
        let changed = derive_reveal_bond_note(
            &key,
            deployment,
            CommitRef {
                tx_index: 3,
                ..reference
            },
            17,
            &ua,
            3,
            action_nullifier,
        )
        .unwrap();
        let fvk = FullViewingKey::from(&key);
        assert_eq!(note, repeated);
        assert_ne!(note, changed);
        assert_eq!(note.value().inner(), BOND_ZATOSHIS);
        assert_eq!(note.rho().to_bytes(), action_nullifier.to_bytes());
        assert_eq!(
            hex::encode(note.rseed().as_bytes()),
            "e0922838459efe2ef5cc31a633379f0ed618fa28e0247dda32763d644686ce27"
        );
        assert_eq!(
            hex::encode(ExtractedNoteCommitment::from(note.commitment()).to_bytes()),
            "4692f7d8aea07771a874005ac0795cd93fa6003cedce066c5a23c17294697108"
        );
        assert_eq!(
            hex::encode(note.nullifier(&fvk).to_bytes()),
            "4ae75d37bd54173229651a42a7c387dadeb07955339c7a6abf4de85a4c645114"
        );

        let refresh = derive_refresh_bond_note(
            &key,
            deployment,
            StateRef {
                height: 130,
                tx_index: 4,
                txid: [5; 32],
                action_index: 3,
            },
            18,
            &ua,
            1,
            action_nullifier,
        )
        .unwrap();
        assert_ne!(note, refresh);
    }
}
