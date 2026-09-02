//! Deterministic hidden-authority recovery from a wallet's BIP-39 seed.
//!
//! These derivations are wallet policy, not on-chain validity rules. They make
//! a 64-byte wallet seed plus a nonsecret list of canonical names sufficient
//! to recover each per-name Orchard authority and every epoch COMMIT opening.

use coppice_names::{
    protocol::{Commitment, FieldElement, Name},
    statement::registration_commitment,
};
use orchard::{circuit::state_note_binding::v2::owner_commitment, keys::SpendingKey};
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
}

/// Derives the deployment- and name-separated hidden Orchard spending key.
pub fn derive_name_spending_key(
    wallet_seed: &[u8],
    deployment_id: [u8; 32],
    name: &Name,
) -> Result<SpendingKey, RecoveryError> {
    if wallet_seed.len() != WALLET_SEED_BYTES {
        return Err(RecoveryError::WrongSeedLength);
    }
    let mut root_input = Zeroizing::new(Vec::with_capacity(2 + wallet_seed.len()));
    root_input.extend_from_slice(&(wallet_seed.len() as u16).to_be_bytes());
    root_input.extend_from_slice(wallet_seed);
    let master = Zeroizing::new(hash32(b"CoppiceN2Root_", &root_input));

    for retry in 0..=u32::MAX {
        let mut input = Vec::with_capacity(32 + 1 + name.as_bytes().len() + 4);
        input.extend_from_slice(&deployment_id);
        input.push(u8::try_from(name.as_bytes().len()).expect("canonical name length fits u8"));
        input.extend_from_slice(name.as_bytes());
        input.extend_from_slice(&retry.to_be_bytes());
        let candidate = Zeroizing::new(keyed_hash32(b"CoppiceN2Owner", &master[..], &input));
        if let Some(spending_key) = Option::<SpendingKey>::from(SpendingKey::from_bytes(*candidate))
        {
            return Ok(spending_key);
        }
    }
    Err(RecoveryError::AuthorityDerivationExhausted)
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
        let uniform = Zeroizing::new(keyed_hash64(b"CoppiceN2ComS", &key[..], &input));
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
            "b98b04b541957e93abb906348027eaa785dc7c7448745f3ea0294aa646623945"
        );
        assert_eq!(
            hex::encode(epoch_17.commitment().to_bytes()),
            "f0c440c4f8184549dabc04c56bf7df7935193de6b38ed491681f6f5ef72e4805"
        );
        assert_eq!(
            hex::encode(epoch_17.secret().to_bytes()),
            "ce7c71bfcdc467daf50d9455a371afb8ee1f2bc9bffb3967011261522ad38b25"
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
}
