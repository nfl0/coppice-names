use crate::crypto;
use std::collections::BTreeMap;

pub type RecentSpent = BTreeMap<[u8; 32], u32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecentSpentEncodingError {
    CountTooLarge,
    Hash(crypto::Error),
}

pub fn canonical_preimage(
    oldest_retained_height: u32,
    recent_spent: &RecentSpent,
) -> Result<Vec<u8>, RecentSpentEncodingError> {
    let count =
        u32::try_from(recent_spent.len()).map_err(|_| RecentSpentEncodingError::CountTooLarge)?;
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&oldest_retained_height.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for (bond_tag, first_seen_height) in recent_spent {
        bytes.extend_from_slice(bond_tag);
        bytes.extend_from_slice(&first_seen_height.to_be_bytes());
    }
    Ok(bytes)
}

pub fn root(
    oldest_retained_height: u32,
    recent_spent: &RecentSpent,
) -> Result<[u8; 32], RecentSpentEncodingError> {
    let preimage = canonical_preimage(oldest_retained_height, recent_spent)?;
    crypto::hash("CoppiceSpentV1", &preimage).map_err(RecentSpentEncodingError::Hash)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecentSpentArithmeticError {
    RetentionOverflow,
    NextHeightOverflow,
}

pub fn retention_blocks(
    bond_note_max_age_blocks: u32,
    commit_ttl_blocks: u32,
) -> Result<u32, RecentSpentArithmeticError> {
    bond_note_max_age_blocks
        .checked_add(commit_ttl_blocks)
        .ok_or(RecentSpentArithmeticError::RetentionOverflow)
}

pub fn oldest_retained_height(
    activation_height: u32,
    height: u32,
    bond_note_max_age_blocks: u32,
    commit_ttl_blocks: u32,
) -> Result<u32, RecentSpentArithmeticError> {
    let retention = retention_blocks(bond_note_max_age_blocks, commit_ttl_blocks)?;
    let next_height = height
        .checked_add(1)
        .ok_or(RecentSpentArithmeticError::NextHeightOverflow)?;
    Ok(activation_height.max(next_height.saturating_sub(retention)))
}

pub fn prune(recent_spent: &mut RecentSpent, oldest_retained_height: u32) -> usize {
    let previous_len = recent_spent.len();
    recent_spent.retain(|_, first_seen_height| *first_seen_height >= oldest_retained_height);
    previous_len - recent_spent.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/recent_spent.json")).unwrap()
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
    fn recent_spent_root_vectors_match() {
        let fixture = fixture();

        let empty = RecentSpent::new();
        let empty_vector = vector(&fixture, "empty-at-activation");
        let empty_oldest = empty_vector["oldest_retained_height"].as_u64().unwrap() as u32;
        assert_eq!(
            canonical_preimage(empty_oldest, &empty).unwrap(),
            hex::decode(empty_vector["canonical_preimage_hex"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            root(empty_oldest, &empty).unwrap(),
            fixed32(empty_vector["expected_root_hex"].as_str().unwrap())
        );

        let mut two_sorted = RecentSpent::new();
        two_sorted.insert([0x31; 32], 110);
        two_sorted.insert([0x21; 32], 111);
        let two_sorted_vector = vector(&fixture, "two-sorted");
        let two_sorted_oldest = two_sorted_vector["oldest_retained_height"]
            .as_u64()
            .unwrap() as u32;
        assert_eq!(
            canonical_preimage(two_sorted_oldest, &two_sorted).unwrap(),
            hex::decode(
                two_sorted_vector["canonical_preimage_hex"]
                    .as_str()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            root(two_sorted_oldest, &two_sorted).unwrap(),
            fixed32(two_sorted_vector["expected_root_hex"].as_str().unwrap())
        );
    }

    #[test]
    fn recent_spent_pruning_vectors_match() {
        let fixture = fixture();
        for id in ["pruning-boundary", "pruning-after-window"] {
            let vector = vector(&fixture, id);
            let actual = oldest_retained_height(
                vector["activation_height"].as_u64().unwrap() as u32,
                vector["height"].as_u64().unwrap() as u32,
                vector["bond_note_max_age_blocks"].as_u64().unwrap() as u32,
                vector["commit_ttl_blocks"].as_u64().unwrap() as u32,
            )
            .unwrap();
            assert_eq!(
                actual,
                vector["expected_oldest_retained_height"].as_u64().unwrap() as u32,
                "{id}"
            );
        }
    }

    #[test]
    fn recent_spent_pruning_keeps_oldest_boundary() {
        let oldest = 131;
        let removed_tag = [0x01; 32];
        let retained_tag = [0x02; 32];
        let newer_tag = [0x03; 32];
        let mut recent_spent = RecentSpent::new();
        recent_spent.insert(removed_tag, oldest - 1);
        recent_spent.insert(retained_tag, oldest);
        recent_spent.insert(newer_tag, oldest + 1);

        assert_eq!(prune(&mut recent_spent, oldest), 1);
        assert!(!recent_spent.contains_key(&removed_tag));
        assert_eq!(recent_spent.get(&retained_tag), Some(&oldest));
        assert_eq!(recent_spent.get(&newer_tag), Some(&(oldest + 1)));
    }

    #[test]
    fn recent_spent_arithmetic_rejects_overflow() {
        assert_eq!(
            retention_blocks(u32::MAX, 1),
            Err(RecentSpentArithmeticError::RetentionOverflow)
        );
        assert_eq!(
            oldest_retained_height(0, u32::MAX, 0, 0),
            Err(RecentSpentArithmeticError::NextHeightOverflow)
        );
    }
}
