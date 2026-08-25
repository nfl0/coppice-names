//! Canonical Names v1 application state and replay-independent mutations.

use crate::{name_tree, pending, recent_spent, record};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoppiceState {
    pub names: BTreeMap<String, record::NameRecord>,
    pub pending: pending::PendingCommitments,
    pub recent_spent: recent_spent::RecentSpent,
    active_bond_index: BTreeMap<[u8; 32], String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrevalidatedRevealPath {
    NewName,
    TerminalReplacement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevalidatedReveal {
    pub name: String,
    pub owner_pk: [u8; 32],
    pub bond_tag: [u8; 32],
    pub address: Vec<u8>,
    pub commitment: [u8; 32],
    pub path: PrevalidatedRevealPath,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateMutationError {
    DuplicateCommitment,
    UnknownCommitment,
    UnknownName,
    NameNotActive,
    ActiveNameExists,
    InvalidReplacementPath,
    InvalidSequence,
    InvalidTerminalHeight,
    BondAlreadyInUse,
    BondSpent,
    DuplicateActiveBondTag,
    InvariantInconsistency,
    PendingArithmetic(pending::PendingTimingError),
    RecentSpentArithmetic(recent_spent::RecentSpentArithmeticError),
}

impl CoppiceState {
    pub fn from_authoritative_parts(
        names: BTreeMap<String, record::NameRecord>,
        pending: pending::PendingCommitments,
        recent_spent: recent_spent::RecentSpent,
    ) -> Result<Self, StateMutationError> {
        if names.keys().any(|name| !crate::envelope::valid_name(name)) {
            return Err(StateMutationError::InvariantInconsistency);
        }
        let active_bond_index = Self::rebuild_active_bond_index(&names)?;
        Ok(Self {
            names,
            pending,
            recent_spent,
            active_bond_index,
        })
    }

    fn rebuild_active_bond_index(
        names: &BTreeMap<String, record::NameRecord>,
    ) -> Result<BTreeMap<[u8; 32], String>, StateMutationError> {
        let mut index = BTreeMap::new();
        for (name, record) in names {
            if record.status == record::NameStatus::Active
                && index.insert(record.bond_tag, name.clone()).is_some()
            {
                return Err(StateMutationError::DuplicateActiveBondTag);
            }
        }
        Ok(index)
    }

    fn verify_active_bond_index(&self) -> Result<(), StateMutationError> {
        let rebuilt = Self::rebuild_active_bond_index(&self.names)
            .map_err(|_| StateMutationError::InvariantInconsistency)?;
        if rebuilt != self.active_bond_index {
            return Err(StateMutationError::InvariantInconsistency);
        }
        Ok(())
    }

    pub fn active_bond_index(&self) -> &BTreeMap<[u8; 32], String> {
        &self.active_bond_index
    }

    pub fn apply_prevalidated_commit(
        &mut self,
        commitment: [u8; 32],
        position: pending::ChainPosition,
    ) -> Result<(), StateMutationError> {
        if self.pending.contains_key(&commitment) {
            return Err(StateMutationError::DuplicateCommitment);
        }
        self.pending.insert(commitment, position);
        Ok(())
    }

    pub fn apply_prevalidated_reveal(
        &mut self,
        reveal: PrevalidatedReveal,
    ) -> Result<(), StateMutationError> {
        if !crate::envelope::valid_name(&reveal.name) {
            return Err(StateMutationError::InvariantInconsistency);
        }
        self.verify_active_bond_index()?;
        if !self.pending.contains_key(&reveal.commitment) {
            return Err(StateMutationError::UnknownCommitment);
        }
        if self.recent_spent.contains_key(&reveal.bond_tag) {
            return Err(StateMutationError::BondSpent);
        }
        if self.active_bond_index.contains_key(&reveal.bond_tag) {
            return Err(StateMutationError::BondAlreadyInUse);
        }
        match (self.names.get(&reveal.name), reveal.path) {
            (None, PrevalidatedRevealPath::NewName) => {}
            (Some(existing), _) if existing.status == record::NameStatus::Active => {
                return Err(StateMutationError::ActiveNameExists);
            }
            (Some(_), PrevalidatedRevealPath::TerminalReplacement) => {}
            _ => return Err(StateMutationError::InvalidReplacementPath),
        }

        self.pending.remove(&reveal.commitment);
        self.names.insert(
            reveal.name.clone(),
            record::NameRecord {
                owner_pk: reveal.owner_pk,
                bond_tag: reveal.bond_tag,
                sequence: 0,
                address: reveal.address,
                status: record::NameStatus::Active,
            },
        );
        self.active_bond_index.insert(reveal.bond_tag, reveal.name);
        Ok(())
    }

    pub fn apply_prevalidated_update(
        &mut self,
        name: &str,
        next_sequence: u64,
        new_address: Vec<u8>,
    ) -> Result<(), StateMutationError> {
        self.verify_active_bond_index()?;
        let current = self
            .names
            .get(name)
            .ok_or(StateMutationError::UnknownName)?;
        if current.status != record::NameStatus::Active {
            return Err(StateMutationError::NameNotActive);
        }
        if current.sequence.checked_add(1) != Some(next_sequence) {
            return Err(StateMutationError::InvalidSequence);
        }
        if self
            .active_bond_index
            .get(&current.bond_tag)
            .map(String::as_str)
            != Some(name)
        {
            return Err(StateMutationError::InvariantInconsistency);
        }
        let current = self.names.get_mut(name).expect("record checked above");
        current.sequence = next_sequence;
        current.address = new_address;
        Ok(())
    }

    pub fn apply_prevalidated_release(
        &mut self,
        name: &str,
        next_sequence: u64,
        terminal_height: u32,
    ) -> Result<(), StateMutationError> {
        self.verify_active_bond_index()?;
        let current = self
            .names
            .get(name)
            .ok_or(StateMutationError::UnknownName)?;
        if current.status != record::NameStatus::Active {
            return Err(StateMutationError::NameNotActive);
        }
        if current.sequence.checked_add(1) != Some(next_sequence) {
            return Err(StateMutationError::InvalidSequence);
        }
        if terminal_height == 0 {
            return Err(StateMutationError::InvalidTerminalHeight);
        }
        if self
            .active_bond_index
            .get(&current.bond_tag)
            .map(String::as_str)
            != Some(name)
        {
            return Err(StateMutationError::InvariantInconsistency);
        }
        let bond_tag = current.bond_tag;
        let current = self.names.get_mut(name).expect("record checked above");
        current.sequence = next_sequence;
        current.status = record::NameStatus::Released { terminal_height };
        self.active_bond_index.remove(&bond_tag);
        Ok(())
    }

    pub fn process_prevalidated_bond_tag(
        &mut self,
        bond_tag: [u8; 32],
        current_height: u32,
    ) -> Result<(), StateMutationError> {
        self.verify_active_bond_index()?;
        let indexed_name = self.active_bond_index.get(&bond_tag).cloned();
        if let Some(name) = &indexed_name {
            let record = self
                .names
                .get(name)
                .ok_or(StateMutationError::InvariantInconsistency)?;
            if record.status != record::NameStatus::Active || record.bond_tag != bond_tag {
                return Err(StateMutationError::InvariantInconsistency);
            }
        }

        self.recent_spent.entry(bond_tag).or_insert(current_height);
        if let Some(name) = indexed_name {
            self.names
                .get_mut(&name)
                .expect("record consistency checked above")
                .status = record::NameStatus::BondSpent {
                terminal_height: current_height,
            };
            self.active_bond_index.remove(&bond_tag);
        }
        Ok(())
    }

    pub fn expire_pending_at_end_of_block(
        &mut self,
        height: u32,
        commit_ttl_blocks: u32,
    ) -> Result<usize, StateMutationError> {
        let mut expired = Vec::new();
        for (commitment, position) in &self.pending {
            if pending::commitment_expired_at_end_of_block(
                position.block_height,
                commit_ttl_blocks,
                height,
            )
            .map_err(StateMutationError::PendingArithmetic)?
            {
                expired.push(*commitment);
            }
        }
        for commitment in &expired {
            self.pending.remove(commitment);
        }
        Ok(expired.len())
    }

    pub fn prune_recent_spent_at_end_of_block(
        &mut self,
        activation_height: u32,
        height: u32,
        bond_note_max_age_blocks: u32,
        commit_ttl_blocks: u32,
    ) -> Result<(u32, usize), StateMutationError> {
        let oldest = recent_spent::oldest_retained_height(
            activation_height,
            height,
            bond_note_max_age_blocks,
            commit_ttl_blocks,
        )
        .map_err(StateMutationError::RecentSpentArithmetic)?;
        let removed = recent_spent::prune(&mut self.recent_spent, oldest);
        Ok((oldest, removed))
    }

    pub fn name_tree_root(&self) -> Result<[u8; 32], name_tree::NameTreeError> {
        name_tree::root(&self.names)
    }

    pub fn pending_root(&self) -> Result<[u8; 32], pending::PendingEncodingError> {
        pending::root(&self.pending)
    }

    pub fn recent_spent_root(
        &self,
        oldest_retained_height: u32,
    ) -> Result<[u8; 32], recent_spent::RecentSpentEncodingError> {
        recent_spent::root(oldest_retained_height, &self.recent_spent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "alice";
    const ADDRESS: &[u8] = b"u1synthetic-conformance-address";
    const NEW_ADDRESS: &[u8] = b"u1synthetic-new-address";

    fn active(tag: [u8; 32], sequence: u64) -> record::NameRecord {
        record::NameRecord {
            owner_pk: core::array::from_fn(|index| index as u8),
            bond_tag: tag,
            sequence,
            address: ADDRESS.to_vec(),
            status: record::NameStatus::Active,
        }
    }

    fn state_with_record(name: &str, record: record::NameRecord) -> CoppiceState {
        let mut names = BTreeMap::new();
        names.insert(name.to_owned(), record);
        CoppiceState::from_authoritative_parts(
            names,
            pending::PendingCommitments::new(),
            recent_spent::RecentSpent::new(),
        )
        .unwrap()
    }

    fn reveal(commitment: [u8; 32], tag: [u8; 32]) -> PrevalidatedReveal {
        PrevalidatedReveal {
            name: NAME.to_owned(),
            owner_pk: core::array::from_fn(|index| index as u8),
            bond_tag: tag,
            address: ADDRESS.to_vec(),
            commitment,
            path: PrevalidatedRevealPath::NewName,
        }
    }

    #[test]
    fn active_bond_index_rebuilds_from_authoritative_records() {
        let empty = CoppiceState::default();
        assert!(empty.active_bond_index().is_empty());

        let mut names = BTreeMap::new();
        names.insert("alice".to_owned(), active([1; 32], 0));
        names.insert("bob".to_owned(), active([2; 32], 0));
        names.insert(
            "carol".to_owned(),
            record::NameRecord {
                status: record::NameStatus::Released {
                    terminal_height: 10,
                },
                bond_tag: [1; 32],
                ..active([1; 32], 0)
            },
        );
        names.insert(
            "dave".to_owned(),
            record::NameRecord {
                status: record::NameStatus::BondSpent {
                    terminal_height: 11,
                },
                bond_tag: [2; 32],
                ..active([2; 32], 0)
            },
        );
        let state = CoppiceState::from_authoritative_parts(
            names,
            pending::PendingCommitments::new(),
            recent_spent::RecentSpent::new(),
        )
        .unwrap();
        assert_eq!(state.active_bond_index().len(), 2);
        assert_eq!(
            state.active_bond_index().get(&[1; 32]),
            Some(&"alice".to_owned())
        );
        assert_eq!(
            state.active_bond_index().get(&[2; 32]),
            Some(&"bob".to_owned())
        );
    }

    #[test]
    fn duplicate_active_bond_tag_is_rejected_on_rebuild() {
        let mut names = BTreeMap::new();
        names.insert("alice".to_owned(), active([1; 32], 0));
        names.insert("bob".to_owned(), active([1; 32], 0));
        assert_eq!(
            CoppiceState::from_authoritative_parts(
                names,
                pending::PendingCommitments::new(),
                recent_spent::RecentSpent::new(),
            ),
            Err(StateMutationError::DuplicateActiveBondTag)
        );
    }

    #[test]
    fn presentation_suffix_can_never_enter_authoritative_name_state() {
        let mut names = BTreeMap::new();
        names.insert("alice.zec".to_owned(), active([1; 32], 0));
        assert_eq!(
            CoppiceState::from_authoritative_parts(
                names,
                pending::PendingCommitments::new(),
                recent_spent::RecentSpent::new(),
            ),
            Err(StateMutationError::InvariantInconsistency)
        );

        let mut state = CoppiceState::default();
        state
            .apply_prevalidated_commit(
                [3; 32],
                pending::ChainPosition {
                    block_height: 100,
                    tx_index: 0,
                },
            )
            .unwrap();
        let mut presented = reveal([3; 32], [4; 32]);
        presented.name = "alice.zec".to_owned();
        assert_eq!(
            state.apply_prevalidated_reveal(presented),
            Err(StateMutationError::InvariantInconsistency)
        );
        assert!(state.names.is_empty());
    }

    #[test]
    fn prevalidated_commit_rejects_a_still_pending_duplicate() {
        let commitment = [3; 32];
        let position = pending::ChainPosition {
            block_height: 100,
            tx_index: 7,
        };
        let mut state = CoppiceState::default();
        assert_eq!(
            state.apply_prevalidated_commit(commitment, position),
            Ok(())
        );
        assert_eq!(
            state.apply_prevalidated_commit(commitment, position),
            Err(StateMutationError::DuplicateCommitment)
        );
        assert_eq!(state.pending.len(), 1);
    }

    #[test]
    fn transition_vector_reveal_creates_active() {
        let commitment = [3; 32];
        let tag = [0x42; 32];
        let mut state = CoppiceState::default();
        state
            .apply_prevalidated_commit(
                commitment,
                pending::ChainPosition {
                    block_height: 100,
                    tx_index: 7,
                },
            )
            .unwrap();
        state
            .apply_prevalidated_reveal(reveal(commitment, tag))
            .unwrap();
        assert_eq!(state.names[NAME], active(tag, 0));
        assert!(state.pending.is_empty());
        assert_eq!(state.active_bond_index().get(&tag), Some(&NAME.to_owned()));
    }

    #[test]
    fn rejected_reveals_are_atomic() {
        let commitment = [3; 32];
        let tag = [0x42; 32];
        let mut missing = CoppiceState::default();
        assert_eq!(
            missing.apply_prevalidated_reveal(reveal(commitment, tag)),
            Err(StateMutationError::UnknownCommitment)
        );

        let mut active_name = state_with_record(NAME, active([1; 32], 0));
        active_name.pending.insert(
            commitment,
            pending::ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
        );
        let before = active_name.clone();
        assert_eq!(
            active_name.apply_prevalidated_reveal(reveal(commitment, tag)),
            Err(StateMutationError::ActiveNameExists)
        );
        assert_eq!(active_name, before);

        let mut spent = CoppiceState::default();
        spent.pending.insert(
            commitment,
            pending::ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
        );
        spent.recent_spent.insert(tag, 1);
        let before = spent.clone();
        assert_eq!(
            spent.apply_prevalidated_reveal(reveal(commitment, tag)),
            Err(StateMutationError::BondSpent)
        );
        assert_eq!(spent, before);

        let mut collision = state_with_record("bob", active(tag, 0));
        collision.pending.insert(
            commitment,
            pending::ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
        );
        let before = collision.clone();
        assert_eq!(
            collision.apply_prevalidated_reveal(reveal(commitment, tag)),
            Err(StateMutationError::BondAlreadyInUse)
        );
        assert_eq!(collision, before);
    }

    #[test]
    fn transition_vectors_update_increment_and_skip() {
        let tag = [0x42; 32];
        let mut state = state_with_record(NAME, active(tag, 0));
        state
            .apply_prevalidated_update(NAME, 1, NEW_ADDRESS.to_vec())
            .unwrap();
        let updated = &state.names[NAME];
        assert_eq!(updated.sequence, 1);
        assert_eq!(updated.address, NEW_ADDRESS);
        assert_eq!(updated.owner_pk, active(tag, 0).owner_pk);
        assert_eq!(updated.bond_tag, tag);
        assert_eq!(updated.status, record::NameStatus::Active);
        assert_eq!(state.active_bond_index().get(&tag), Some(&NAME.to_owned()));

        let mut skipped = state_with_record(NAME, active(tag, 0));
        let before = skipped.clone();
        assert_eq!(
            skipped.apply_prevalidated_update(NAME, 2, NEW_ADDRESS.to_vec()),
            Err(StateMutationError::InvalidSequence)
        );
        assert_eq!(skipped, before);
    }

    #[test]
    fn update_rejects_sequence_overflow() {
        let mut state = state_with_record(NAME, active([1; 32], u64::MAX));
        let before = state.clone();
        assert_eq!(
            state.apply_prevalidated_update(NAME, 0, NEW_ADDRESS.to_vec()),
            Err(StateMutationError::InvalidSequence)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn transition_vector_release_terminal_is_atomic() {
        let tag = [0x42; 32];
        let mut state = state_with_record(NAME, active(tag, 1));
        let original = state.names[NAME].clone();
        state.apply_prevalidated_release(NAME, 2, 205).unwrap();
        assert_eq!(state.names[NAME].sequence, 2);
        assert_eq!(
            state.names[NAME].status,
            record::NameStatus::Released {
                terminal_height: 205
            }
        );
        assert_eq!(state.names[NAME].owner_pk, original.owner_pk);
        assert_eq!(state.names[NAME].bond_tag, original.bond_tag);
        assert_eq!(state.names[NAME].address, original.address);
        assert!(!state.active_bond_index().contains_key(&tag));

        let mut rejected = state_with_record(NAME, active(tag, 1));
        let before = rejected.clone();
        assert_eq!(
            rejected.apply_prevalidated_release(NAME, 3, 205),
            Err(StateMutationError::InvalidSequence)
        );
        assert_eq!(rejected, before);
    }

    #[test]
    fn transition_vector_bond_spend_terminal_and_first_seen() {
        let tag = [0x42; 32];
        let mut state = state_with_record(NAME, active(tag, 0));
        let original = state.names[NAME].clone();
        state.process_prevalidated_bond_tag(tag, 190).unwrap();
        assert_eq!(state.recent_spent.get(&tag), Some(&190));
        assert_eq!(
            state.names[NAME].status,
            record::NameStatus::BondSpent {
                terminal_height: 190
            }
        );
        assert_eq!(state.names[NAME].owner_pk, original.owner_pk);
        assert_eq!(state.names[NAME].bond_tag, original.bond_tag);
        assert_eq!(state.names[NAME].sequence, original.sequence);
        assert_eq!(state.names[NAME].address, original.address);
        assert!(!state.active_bond_index().contains_key(&tag));
        state.process_prevalidated_bond_tag(tag, 191).unwrap();
        assert_eq!(state.recent_spent.get(&tag), Some(&190));

        let unknown = [9; 32];
        state.process_prevalidated_bond_tag(unknown, 192).unwrap();
        assert_eq!(state.recent_spent.get(&unknown), Some(&192));
    }

    #[test]
    fn bond_tag_processing_rejects_inconsistent_index_atomically() {
        let tag = [0x42; 32];
        let mut state = state_with_record(NAME, active(tag, 0));
        state.names.get_mut(NAME).unwrap().bond_tag = [8; 32];
        let before = state.clone();
        assert_eq!(
            state.process_prevalidated_bond_tag(tag, 190),
            Err(StateMutationError::InvariantInconsistency)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn pending_deadline_block_expires_only_at_explicit_end_of_block() {
        let commitment = [3; 32];
        let mut state = CoppiceState::default();
        state.pending.insert(
            commitment,
            pending::ChainPosition {
                block_height: 100,
                tx_index: 0,
            },
        );
        assert!(state.pending.contains_key(&commitment));
        assert_eq!(state.expire_pending_at_end_of_block(119, 20), Ok(0));
        assert!(state.pending.contains_key(&commitment));
        assert_eq!(state.expire_pending_at_end_of_block(120, 20), Ok(1));
        assert!(!state.pending.contains_key(&commitment));
    }

    #[test]
    fn recent_spent_pruning_keeps_the_boundary() {
        let mut state = CoppiceState::default();
        state.recent_spent.insert([1; 32], 130);
        state.recent_spent.insert([2; 32], 131);
        state.recent_spent.insert([3; 32], 132);
        let (oldest, removed) = state
            .prune_recent_spent_at_end_of_block(100, 150, 10, 10)
            .unwrap();
        assert_eq!(oldest, 131);
        assert_eq!(removed, 1);
        assert!(!state.recent_spent.contains_key(&[1; 32]));
        assert_eq!(state.recent_spent.get(&[2; 32]), Some(&131));
        assert_eq!(state.recent_spent.get(&[3; 32]), Some(&132));
    }

    #[test]
    fn derived_root_accessors_use_canonical_v1_primitives() {
        let mut state = state_with_record(NAME, active([0x42; 32], 0));
        state.pending.insert(
            [3; 32],
            pending::ChainPosition {
                block_height: 100,
                tx_index: 7,
            },
        );
        state.recent_spent.insert([4; 32], 110);
        assert_eq!(state.name_tree_root(), name_tree::root(&state.names));
        assert_eq!(state.pending_root(), pending::root(&state.pending));
        assert_eq!(
            state.recent_spent_root(100),
            recent_spent::root(100, &state.recent_spent)
        );
    }
}
