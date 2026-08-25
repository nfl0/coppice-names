use crate::crypto;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPosition {
    pub block_height: u32,
    pub tx_index: u32,
}

pub type PendingCommitments = BTreeMap<[u8; 32], ChainPosition>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingEncodingError {
    CountTooLarge,
    Hash(crypto::Error),
}

pub fn canonical_preimage(pending: &PendingCommitments) -> Result<Vec<u8>, PendingEncodingError> {
    let count = u32::try_from(pending.len()).map_err(|_| PendingEncodingError::CountTooLarge)?;
    let mut bytes = Vec::with_capacity(4 + pending.len() * (32 + 4 + 4));
    bytes.extend_from_slice(&count.to_be_bytes());
    for (commitment, position) in pending {
        bytes.extend_from_slice(commitment);
        bytes.extend_from_slice(&position.block_height.to_be_bytes());
        bytes.extend_from_slice(&position.tx_index.to_be_bytes());
    }
    Ok(bytes)
}

pub fn root(pending: &PendingCommitments) -> Result<[u8; 32], PendingEncodingError> {
    let preimage = canonical_preimage(pending)?;
    crypto::hash("CoppiceCSetV1", &preimage).map_err(PendingEncodingError::Hash)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingTimingError {
    HeightOverflow,
}

pub fn reveal_is_valid(
    commit_height: u32,
    reveal_height: u32,
    commit_ttl_blocks: u32,
) -> Result<bool, PendingTimingError> {
    let first_valid_height = commit_height
        .checked_add(1)
        .ok_or(PendingTimingError::HeightOverflow)?;
    let last_valid_height = commit_height
        .checked_add(commit_ttl_blocks)
        .ok_or(PendingTimingError::HeightOverflow)?;
    Ok(reveal_height >= first_valid_height && reveal_height <= last_valid_height)
}

pub fn commitment_expired_at_end_of_block(
    commit_height: u32,
    commit_ttl_blocks: u32,
    height: u32,
) -> Result<bool, PendingTimingError> {
    let expiry_height = commit_height
        .checked_add(commit_ttl_blocks)
        .ok_or(PendingTimingError::HeightOverflow)?;
    Ok(expiry_height <= height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/pending.json")).unwrap()
    }

    fn vector<'a>(fixture: &'a Value, id: &str) -> &'a Value {
        fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"].as_str() == Some(id))
            .unwrap()
    }

    #[test]
    fn pending_root_vectors_match() {
        let fixture = fixture();

        let empty = PendingCommitments::new();
        let empty_vector = vector(&fixture, "empty");
        assert_eq!(
            canonical_preimage(&empty).unwrap(),
            hex::decode(empty_vector["canonical_preimage_hex"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            root(&empty).unwrap(),
            fixed32(empty_vector["expected_root_hex"].as_str().unwrap())
        );

        let mut two_sorted = PendingCommitments::new();
        two_sorted.insert(
            [0x20; 32],
            ChainPosition {
                block_height: 99,
                tx_index: 3,
            },
        );
        two_sorted.insert(
            [0x10; 32],
            ChainPosition {
                block_height: 100,
                tx_index: 7,
            },
        );
        let two_sorted_vector = vector(&fixture, "two-sorted");
        assert_eq!(
            canonical_preimage(&two_sorted).unwrap(),
            hex::decode(
                two_sorted_vector["canonical_preimage_hex"]
                    .as_str()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            root(&two_sorted).unwrap(),
            fixed32(two_sorted_vector["expected_root_hex"].as_str().unwrap())
        );
    }

    #[test]
    fn pending_timing_boundaries_match() {
        let fixture = fixture();
        let vector = vector(&fixture, "timing-boundaries");
        let commit_height = vector["commit_height"].as_u64().unwrap() as u32;
        let ttl = vector["ttl"].as_u64().unwrap() as u32;
        let first_valid = vector["first_valid_reveal_height"].as_u64().unwrap() as u32;
        let last_valid = vector["last_valid_reveal_height"].as_u64().unwrap() as u32;
        let expired_at = vector["expired_after_end_of_block"].as_u64().unwrap() as u32;

        assert!(!reveal_is_valid(commit_height, commit_height, ttl).unwrap());
        assert!(reveal_is_valid(commit_height, first_valid, ttl).unwrap());
        assert!(reveal_is_valid(commit_height, last_valid, ttl).unwrap());
        assert!(commitment_expired_at_end_of_block(commit_height, ttl, expired_at).unwrap());
    }

    #[test]
    fn pending_timing_rejects_height_overflow() {
        assert_eq!(
            reveal_is_valid(u32::MAX, u32::MAX, 1),
            Err(PendingTimingError::HeightOverflow)
        );
        assert_eq!(
            commitment_expired_at_end_of_block(u32::MAX - 1, 2, u32::MAX),
            Err(PendingTimingError::HeightOverflow)
        );
    }
}
