use crate::crypto;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRootInput {
    pub deployment_id: [u8; 32],
    pub height: u32,
    pub block_hash: [u8; 32],
    pub ironwood_tree_size: u32,
    pub ironwood_root: [u8; 32],
    pub name_tree_root: [u8; 32],
    pub pending_root: [u8; 32],
    pub recent_spent_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRootError {
    Hash(crypto::Error),
}

pub fn canonical_preimage(input: &StateRootInput) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(200);
    bytes.extend_from_slice(&input.deployment_id);
    bytes.extend_from_slice(&input.height.to_be_bytes());
    bytes.extend_from_slice(&input.block_hash);
    bytes.extend_from_slice(&input.ironwood_tree_size.to_be_bytes());
    bytes.extend_from_slice(&input.ironwood_root);
    bytes.extend_from_slice(&input.name_tree_root);
    bytes.extend_from_slice(&input.pending_root);
    bytes.extend_from_slice(&input.recent_spent_root);
    bytes
}

pub fn state_root(input: &StateRootInput) -> Result<[u8; 32], StateRootError> {
    crypto::hash("CoppiceStateV1", &canonical_preimage(input)).map_err(StateRootError::Hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn state_root_vector_matches() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../test-vectors/state_roots.json")).unwrap();
        let vector = &fixture["vector"];
        let input = StateRootInput {
            deployment_id: fixed32(vector["deployment_id_hex"].as_str().unwrap()),
            height: vector["height"].as_u64().unwrap() as u32,
            block_hash: fixed32(vector["block_hash_hex"].as_str().unwrap()),
            ironwood_tree_size: vector["ironwood_tree_size"].as_u64().unwrap() as u32,
            ironwood_root: fixed32(vector["ironwood_root_hex"].as_str().unwrap()),
            name_tree_root: fixed32(vector["name_tree_root_hex"].as_str().unwrap()),
            pending_root: fixed32(vector["pending_root_hex"].as_str().unwrap()),
            recent_spent_root: fixed32(vector["recent_spent_root_hex"].as_str().unwrap()),
        };
        assert_eq!(
            canonical_preimage(&input),
            hex::decode(vector["canonical_preimage_hex"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            state_root(&input).unwrap(),
            fixed32(vector["expected_state_root_hex"].as_str().unwrap())
        );
    }
}
