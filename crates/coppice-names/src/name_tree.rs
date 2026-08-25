use crate::{
    crypto, owner,
    record::{self, NameRecord},
};
use std::collections::BTreeMap;

const TREE_DEPTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameProof {
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameTreeError {
    DuplicateNameId,
    Record(record::RecordEncodingError),
    Hash(crypto::Error),
}

fn hash(label: &str, message: &[u8]) -> [u8; 32] {
    crypto::hash(label, message).expect("fixed v1 NameTree hash label")
}

pub fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut message = [0u8; 64];
    message[..32].copy_from_slice(&left);
    message[32..].copy_from_slice(&right);
    hash("CoppiceNNodeV1", &message)
}

pub fn empty_hashes() -> Vec<[u8; 32]> {
    let mut empty = Vec::with_capacity(TREE_DEPTH + 1);
    empty.push(hash("CoppiceNEmptyV1", &[]));
    for i in 0..TREE_DEPTH {
        let previous = empty[i];
        empty.push(node_hash(previous, previous));
    }
    empty
}

pub fn empty_root() -> [u8; 32] {
    empty_hashes()[TREE_DEPTH]
}

pub fn leaf_hash(record: &NameRecord) -> Result<[u8; 32], NameTreeError> {
    let record_hash = record::record_hash(record).map_err(NameTreeError::Record)?;
    Ok(hash("CoppiceNLeafV1", &record_hash))
}

fn bit(key: &[u8; 32], depth: usize) -> bool {
    key[depth / 8] & (1 << (7 - depth % 8)) != 0
}

fn parent(mut key: [u8; 32], depth: usize) -> [u8; 32] {
    key[depth / 8] &= !(1 << (7 - depth % 8));
    key
}

fn sibling(mut key: [u8; 32], depth: usize) -> [u8; 32] {
    key[depth / 8] ^= 1 << (7 - depth % 8);
    key
}

fn leaves(
    records: &BTreeMap<String, NameRecord>,
) -> Result<BTreeMap<[u8; 32], [u8; 32]>, NameTreeError> {
    let mut leaves = BTreeMap::new();
    for (name, record) in records {
        let name_id = owner::name_id(name);
        let leaf = leaf_hash(record)?;
        if leaves.insert(name_id, leaf).is_some() {
            return Err(NameTreeError::DuplicateNameId);
        }
    }
    Ok(leaves)
}

fn levels(
    leaves: &BTreeMap<[u8; 32], [u8; 32]>,
    empty: &[[u8; 32]],
) -> Vec<BTreeMap<[u8; 32], [u8; 32]>> {
    let mut all = Vec::with_capacity(TREE_DEPTH + 1);
    let mut current = leaves.clone();
    all.push(current.clone());
    for depth in (0..TREE_DEPTH).rev() {
        let mut next = BTreeMap::new();
        for (key, value) in &current {
            let parent_key = parent(*key, depth);
            if next.contains_key(&parent_key) {
                continue;
            }
            let sibling_value = current
                .get(&sibling(*key, depth))
                .copied()
                .unwrap_or(empty[TREE_DEPTH - 1 - depth]);
            let (left, right) = if bit(key, depth) {
                (sibling_value, *value)
            } else {
                (*value, sibling_value)
            };
            next.insert(parent_key, node_hash(left, right));
        }
        current = next;
        all.push(current.clone());
    }
    all
}

pub fn root(records: &BTreeMap<String, NameRecord>) -> Result<[u8; 32], NameTreeError> {
    let empty = empty_hashes();
    let leaves = leaves(records)?;
    let all = levels(&leaves, &empty);
    Ok(all[TREE_DEPTH]
        .get(&[0; 32])
        .copied()
        .unwrap_or(empty[TREE_DEPTH]))
}

pub fn prove(
    records: &BTreeMap<String, NameRecord>,
    name: &str,
) -> Result<NameProof, NameTreeError> {
    let empty = empty_hashes();
    let leaves = leaves(records)?;
    let all = levels(&leaves, &empty);
    let mut key = owner::name_id(name);
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    for level in 0..TREE_DEPTH {
        let depth = TREE_DEPTH - 1 - level;
        siblings.push(
            all[level]
                .get(&sibling(key, depth))
                .copied()
                .unwrap_or(empty[level]),
        );
        key = parent(key, depth);
    }
    Ok(NameProof { siblings })
}

pub fn verify(
    expected_root: [u8; 32],
    name: &str,
    record: Option<&NameRecord>,
    proof: &NameProof,
) -> bool {
    if proof.siblings.len() != TREE_DEPTH {
        return false;
    }
    let empty = empty_hashes();
    let mut current = match record {
        Some(record) => match leaf_hash(record) {
            Ok(leaf) => leaf,
            Err(_) => return false,
        },
        None => empty[0],
    };
    let key = owner::name_id(name);
    for (level, sibling_hash) in proof.siblings.iter().enumerate() {
        let depth = TREE_DEPTH - 1 - level;
        current = if bit(&key, depth) {
            node_hash(*sibling_hash, current)
        } else {
            node_hash(current, *sibling_hash)
        };
    }
    current == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn name_tree_fixture() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/name_tree.json")).unwrap()
    }

    fn active_record() -> NameRecord {
        NameRecord {
            owner_pk: core::array::from_fn(|index| index as u8),
            bond_tag: [0x42; 32],
            sequence: 0,
            address: b"u1synthetic-conformance-address".to_vec(),
            status: record::NameStatus::Active,
        }
    }

    fn frozen_active_record_hash() -> [u8; 32] {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../test-vectors/records.json")).unwrap();
        let vector = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"].as_str() == Some("active"))
            .unwrap();
        fixed32(vector["record_hash_hex"].as_str().unwrap())
    }

    #[test]
    fn name_tree_vectors_and_proofs_match() {
        let fixture = name_tree_fixture();
        let one_leaf = &fixture["one_leaf"];
        let empty = empty_hashes();
        assert_eq!(empty.len(), TREE_DEPTH + 1);
        assert_eq!(
            empty[0],
            fixed32(fixture["empty_leaf_hex"].as_str().unwrap())
        );
        assert_eq!(
            empty_root(),
            fixed32(fixture["empty_root_hex"].as_str().unwrap())
        );

        let record = active_record();
        assert_eq!(
            record::record_hash(&record).unwrap(),
            frozen_active_record_hash()
        );
        assert_eq!(
            owner::name_id("alice"),
            fixed32(one_leaf["name_id_hex"].as_str().unwrap())
        );
        assert_eq!(
            leaf_hash(&record).unwrap(),
            fixed32(one_leaf["leaf_hex"].as_str().unwrap())
        );

        let mut records = BTreeMap::new();
        records.insert("alice".to_owned(), record.clone());
        let one_leaf_root = root(&records).unwrap();
        assert_eq!(
            one_leaf_root,
            fixed32(one_leaf["root_hex"].as_str().unwrap())
        );

        let proof = prove(&records, "alice").unwrap();
        let expected_siblings = one_leaf["siblings_bottom_up_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|sibling| fixed32(sibling.as_str().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(expected_siblings.len(), TREE_DEPTH);
        assert_eq!(proof.siblings, expected_siblings);
        assert!(verify(one_leaf_root, "alice", Some(&record), &proof));

        let mut wrong_record = record.clone();
        wrong_record.address.push(b'!');
        assert!(!verify(one_leaf_root, "alice", Some(&wrong_record), &proof));
        assert!(!verify([0; 32], "alice", Some(&record), &proof));

        let absent_proof = prove(&records, "bob").unwrap();
        assert!(verify(one_leaf_root, "bob", None, &absent_proof));
        assert!(!verify(one_leaf_root, "bob", Some(&record), &absent_proof));

        let mut malformed = proof.clone();
        malformed.siblings.pop();
        assert!(!verify(one_leaf_root, "alice", Some(&record), &malformed));
        malformed.siblings.push([0; 32]);
        malformed.siblings.push([0; 32]);
        assert!(!verify(one_leaf_root, "alice", Some(&record), &malformed));
    }
}
