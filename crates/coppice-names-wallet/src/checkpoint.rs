//! Seed-authenticated storage envelope for derived Names replay checkpoints.
//!
//! Current Ironwood consensus does not commit to Names application state. A
//! checkpoint therefore remains cached verification work: its branch hash must
//! still match the wallet's authenticated chain, and a missing or invalid
//! envelope must fall back to replay. The authentication key is regenerated
//! from the wallet seed and is never a sidecar secret.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::recovery::{RecoveryError, derive_names_master};

const MAGIC: &[u8; 4] = b"CNWC";
const FORMAT_VERSION: u8 = 1;
const HEADER_BYTES: usize = 4 + 1 + 32 + 4;
const TAG_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    WrongSeedLength,
    PayloadTooLarge,
    InvalidEncoding,
    UnsupportedFormat,
    DeploymentMismatch,
    AuthenticationFailed,
}

/// Authenticates opaque checkpoint bytes under a deployment-separated key
/// recoverable from the wallet's exact 64-byte BIP-39 seed output.
pub fn seal_checkpoint(
    wallet_seed: &[u8],
    deployment_id: [u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, CheckpointError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| CheckpointError::PayloadTooLarge)?;
    let key = checkpoint_key(wallet_seed, deployment_id)?;
    let mut output = Vec::with_capacity(HEADER_BYTES + payload.len() + TAG_BYTES);
    output.extend_from_slice(MAGIC);
    output.push(FORMAT_VERSION);
    output.extend_from_slice(&deployment_id);
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(payload);
    let tag = keyed_hash32(b"CoppiceNmCTag", &key[..], &output);
    output.extend_from_slice(&tag);
    Ok(output)
}

/// Verifies and returns opaque checkpoint bytes. Authentication is checked
/// before copying the payload into a new allocation.
pub fn open_checkpoint(
    wallet_seed: &[u8],
    deployment_id: [u8; 32],
    envelope: &[u8],
) -> Result<Vec<u8>, CheckpointError> {
    if envelope.len() < HEADER_BYTES + TAG_BYTES {
        return Err(CheckpointError::InvalidEncoding);
    }
    if &envelope[..4] != MAGIC {
        return Err(CheckpointError::InvalidEncoding);
    }
    if envelope[4] != FORMAT_VERSION {
        return Err(CheckpointError::UnsupportedFormat);
    }
    if envelope[5..37] != deployment_id {
        return Err(CheckpointError::DeploymentMismatch);
    }
    let payload_len = u32::from_be_bytes(
        envelope[37..41]
            .try_into()
            .expect("fixed checkpoint length field"),
    ) as usize;
    let expected_len = HEADER_BYTES
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(TAG_BYTES))
        .ok_or(CheckpointError::InvalidEncoding)?;
    if envelope.len() != expected_len {
        return Err(CheckpointError::InvalidEncoding);
    }
    let tag_start = HEADER_BYTES + payload_len;
    let key = checkpoint_key(wallet_seed, deployment_id)?;
    let expected = keyed_hash32(b"CoppiceNmCTag", &key[..], &envelope[..tag_start]);
    if expected.ct_eq(&envelope[tag_start..]).unwrap_u8() != 1 {
        return Err(CheckpointError::AuthenticationFailed);
    }
    Ok(envelope[HEADER_BYTES..tag_start].to_vec())
}

fn checkpoint_key(
    wallet_seed: &[u8],
    deployment_id: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CheckpointError> {
    let master = derive_names_master(wallet_seed).map_err(|error| match error {
        RecoveryError::WrongSeedLength => CheckpointError::WrongSeedLength,
        _ => unreachable!("master derivation has no retry-dependent failure"),
    })?;
    Ok(Zeroizing::new(keyed_hash32(
        b"CoppiceNmCKey",
        &master[..],
        &deployment_id,
    )))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_round_trip_is_seed_and_deployment_bound() {
        let seed = [7; 64];
        let deployment = [9; 32];
        let payload = b"branch-bound exact resolver snapshot";
        let sealed = seal_checkpoint(&seed, deployment, payload).unwrap();
        assert_eq!(
            open_checkpoint(&seed, deployment, &sealed).unwrap(),
            payload
        );
        assert_eq!(
            open_checkpoint(&[8; 64], deployment, &sealed),
            Err(CheckpointError::AuthenticationFailed)
        );
        assert_eq!(
            open_checkpoint(&seed, [8; 32], &sealed),
            Err(CheckpointError::DeploymentMismatch)
        );
    }

    #[test]
    fn checkpoint_rejects_tampering_and_noncanonical_lengths() {
        let seed = [7; 64];
        let deployment = [9; 32];
        let sealed = seal_checkpoint(&seed, deployment, b"payload").unwrap();
        for index in [5, 40, HEADER_BYTES, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(open_checkpoint(&seed, deployment, &tampered).is_err());
        }
        assert_eq!(
            open_checkpoint(&seed, deployment, &sealed[..sealed.len() - 1]),
            Err(CheckpointError::InvalidEncoding)
        );
        assert_eq!(
            seal_checkpoint(&seed[..63], deployment, b"payload"),
            Err(CheckpointError::WrongSeedLength)
        );
    }
}
