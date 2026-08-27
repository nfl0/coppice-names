//! Canonical Names v2 state-machine replay over typed Ironwood effects.

use super::{
    lease::{Lifecycle, V2Parameters},
    operation::{
        ActionViewError, CanonicalBlock, CanonicalTransaction, ChainTip, IronwoodActionRef,
        OperationKind, V2Operation,
    },
    registration::{BondProofVerifier, CommitRef},
    state::{NameId, NameState, StateData, StateError, StateRef, StateStatus},
    transition::{GenesisStatement, StatementError, TransitionStatement, V2StateProofVerifier},
};
use std::collections::{BTreeMap, BTreeSet};

/// Errors from canonical v2 block application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// The supplied block is not the next canonical block.
    NonSequentialHeight,
    /// The supplied predecessor hash does not match the current canonical tip.
    PredecessorMismatch,
    /// Transactions are not in canonical transaction-index order.
    NonCanonicalTransactionOrder,
    /// Operation carrier order is not canonical.
    NonCanonicalOperationOrder,
    /// Core effects cannot be represented as one action per index.
    ActionView(ActionViewError),
    /// An action index was reused by two v2 operations in one transaction.
    DuplicateActionIndex,
    /// A commitment was already pending.
    DuplicateCommitment,
    /// A commitment referenced by REVEAL is absent.
    UnknownCommitment,
    /// REVEAL occurred before COMMIT maturity.
    CommitmentNotMature,
    /// REVEAL occurred after the commitment TTL.
    CommitmentExpired,
    /// A commitment value does not match the disclosed intent.
    CommitmentMismatch,
    /// A commitment was made in the same block as its REVEAL.
    SameBlockCommitReveal,
    /// REVEAL was not at the name-derived anchor slot.
    RevealOutsideAnchor,
    /// The disclosed registration intent is malformed.
    InvalidRegistration,
    /// The v1 BondProof evidence was not accepted.
    InvalidBondProof,
    /// A bond identity is already attached to another active name.
    BondAlreadyInUse,
    /// A name is not claimable at REVEAL.
    NameUnavailable,
    /// A replacement COMMIT predates the claimability boundary.
    CommitPredatesClaimability,
    /// A reclaiming REVEAL does not point at the current terminal head.
    InvalidReplacementReference,
    /// A first-use REVEAL unexpectedly carries a replacement pointer.
    UnexpectedReplacementReference,
    /// A state value failed canonical validation.
    InvalidState(StateError),
    /// A proof statement could not be constructed.
    InvalidStatement(StatementError),
    /// A state proof did not verify.
    InvalidStateProof,
    /// The selected action commitment is not the declared successor commitment.
    ActionCommitmentMismatch,
    /// The predecessor reference does not identify the current head.
    StalePredecessor,
    /// No current head exists for a non-genesis operation.
    MissingPredecessor,
    /// The current note is not active at this height.
    InactiveLease,
    /// The next sequence is not exactly the current sequence plus one.
    InvalidSequence,
    /// UPDATE changed a field outside its policy or failed to change its record.
    InvalidUpdate,
    /// RENEW did not use the deterministic slot/lease rule.
    InvalidRenewal,
    /// RELEASE did not create the exact terminal state.
    InvalidRelease,
    /// A state nullifier was already consumed in this application branch.
    DuplicateStateNullifier,
    /// A height arithmetic operation overflowed.
    ArithmeticOverflow,
}

impl From<StateError> for ApplyError {
    fn from(error: StateError) -> Self {
        Self::InvalidState(error)
    }
}

impl From<StatementError> for ApplyError {
    fn from(error: StatementError) -> Self {
        Self::InvalidStatement(error)
    }
}

/// Result of applying one canonical block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedBlock {
    /// New canonical tip.
    pub tip: ChainTip,
    /// State operations accepted in canonical order.
    pub operations: Vec<(NameId, AppliedOperationKind)>,
    /// Number of pending commitments retained after end-of-block expiry.
    pub pending_commitments: usize,
}

/// Operation kinds accepted by one v2 block, including genesis REVEAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppliedOperationKind {
    /// A new per-name lineage head created by REVEAL.
    Reveal,
    /// An arbitrary-height record update.
    Update,
    /// A scheduled lease renewal.
    Renew,
    /// An explicit terminal release.
    Release,
}

/// Derived v2 application state. It is not serialized into Core and has no
/// global root consumed by operations.
#[derive(Clone, Debug)]
pub struct V2StateMachine {
    params: V2Parameters,
    tip: ChainTip,
    pending: BTreeMap<[u8; 32], CommitRef>,
    heads: BTreeMap<NameId, NameState>,
    /// Derived v1-compatible active bond ownership. This is not a consensus
    /// root or a Core index; it is rebuilt while replaying accepted v2
    /// registrations and is independent for names using different bonds.
    active_bonds: BTreeMap<[u8; 32], NameId>,
    spent_state_nullifiers: BTreeSet<[u8; 32]>,
}

impl V2StateMachine {
    /// Creates an empty v2 state machine at the block before activation.
    pub fn new(params: V2Parameters) -> Result<Self, super::lease::LeaseParameterError> {
        params.validate()?;
        Ok(Self {
            tip: ChainTip {
                height: params.activation_height - 1,
                block_hash: [0; 32],
            },
            params,
            pending: BTreeMap::new(),
            heads: BTreeMap::new(),
            active_bonds: BTreeMap::new(),
            spent_state_nullifiers: BTreeSet::new(),
        })
    }

    /// Returns the immutable experimental parameters.
    pub const fn params(&self) -> V2Parameters {
        self.params
    }

    /// Returns the current canonical tip.
    pub const fn tip(&self) -> ChainTip {
        self.tip
    }

    /// Returns the derived current head for a name identifier.
    pub fn head(&self, name_id: NameId) -> Option<&NameState> {
        self.heads.get(&name_id)
    }

    /// Returns the pending COMMIT reference, if present.
    pub fn pending(&self, commitment: [u8; 32]) -> Option<CommitRef> {
        self.pending.get(&commitment).copied()
    }

    /// Applies a canonical block atomically after v2 proof and policy checks.
    pub fn apply_block<P, B>(
        &mut self,
        block: &CanonicalBlock,
        proofs: &P,
        bonds: &B,
    ) -> Result<AppliedBlock, ApplyError>
    where
        P: V2StateProofVerifier,
        B: BondProofVerifier,
    {
        let mut next = self.clone();
        let applied = next.apply_block_inner(block, proofs, bonds)?;
        *self = next;
        Ok(applied)
    }

    fn apply_block_inner<P, B>(
        &mut self,
        block: &CanonicalBlock,
        proofs: &P,
        bonds: &B,
    ) -> Result<AppliedBlock, ApplyError>
    where
        P: V2StateProofVerifier,
        B: BondProofVerifier,
    {
        let expected_height = self
            .tip
            .height
            .checked_add(1)
            .ok_or(ApplyError::ArithmeticOverflow)?;
        if block.height != expected_height {
            return Err(ApplyError::NonSequentialHeight);
        }
        if block.prev_block_hash != self.tip.block_hash {
            return Err(ApplyError::PredecessorMismatch);
        }
        if block.height < self.params.activation_height {
            return Err(ApplyError::NonSequentialHeight);
        }
        if block
            .transactions
            .windows(2)
            .any(|pair| pair[0].tx_index >= pair[1].tx_index)
        {
            return Err(ApplyError::NonCanonicalTransactionOrder);
        }

        let mut accepted = Vec::new();
        for transaction in &block.transactions {
            validate_action_order(transaction)?;
            if !transaction.has_canonical_operation_order() {
                return Err(ApplyError::NonCanonicalOperationOrder);
            }
            let mut used_actions = BTreeSet::new();
            for operation in &transaction.operations {
                match operation {
                    V2Operation::Commit { commitment } => {
                        let position = transaction.position(block.height);
                        let commit = CommitRef::new(position, *commitment);
                        if self.pending.contains_key(commitment) {
                            return Err(ApplyError::DuplicateCommitment);
                        }
                        self.pending.insert(*commitment, commit);
                    }
                    V2Operation::Reveal { .. } => {
                        let state = self.apply_reveal(
                            block,
                            transaction,
                            operation,
                            proofs,
                            bonds,
                            &mut used_actions,
                        )?;
                        accepted.push((state.data.name_id, AppliedOperationKind::Reveal));
                    }
                    V2Operation::Update { .. }
                    | V2Operation::Renew { .. }
                    | V2Operation::Release { .. } => {
                        let (name_id, kind) = self.apply_transition(
                            block,
                            transaction,
                            operation,
                            proofs,
                            &mut used_actions,
                        )?;
                        accepted.push((name_id, kind));
                    }
                }
            }
        }

        let height = block.height;
        self.pending.retain(|_, commit| {
            commit
                .position
                .height
                .checked_add(self.params.commit_ttl_blocks)
                .map(|expiry| expiry > height)
                .unwrap_or(false)
        });
        self.tip = block.tip();
        Ok(AppliedBlock {
            tip: self.tip,
            operations: accepted,
            pending_commitments: self.pending.len(),
        })
    }

    fn apply_reveal<P, B>(
        &mut self,
        block: &CanonicalBlock,
        transaction: &CanonicalTransaction,
        operation: &V2Operation,
        proofs: &P,
        bonds: &B,
        used_actions: &mut BTreeSet<u32>,
    ) -> Result<NameState, ApplyError>
    where
        P: V2StateProofVerifier,
        B: BondProofVerifier,
    {
        let V2Operation::Reveal {
            intent,
            commit,
            replacement_predecessor,
            state,
            state_commitment,
            action_index,
            bond,
            proof,
        } = operation
        else {
            unreachable!("apply_reveal called with non-reveal")
        };
        let name_id = intent
            .name_id()
            .map_err(|_| ApplyError::InvalidRegistration)?;
        if state.name_id != name_id
            || state.owner_pk != intent.owner_pk
            || state.record != intent.record
            || state.sequence != 0
            || state.status != StateStatus::Active
            || state.terminal_height != 0
            || state.lease_expiry
                != self
                    .params
                    .lease_expiry(block.height)
                    .ok_or(ApplyError::ArithmeticOverflow)?
        {
            return Err(ApplyError::InvalidState(StateError::InvalidField));
        }
        self.params.validate_state(state)?;
        let expected_commitment = intent
            .commitment()
            .map_err(|_| ApplyError::InvalidRegistration)?;
        if expected_commitment != commit.commitment {
            return Err(ApplyError::CommitmentMismatch);
        }
        let pending = self
            .pending
            .get(&commit.commitment)
            .copied()
            .ok_or(ApplyError::UnknownCommitment)?;
        if pending != *commit {
            return Err(ApplyError::CommitmentMismatch);
        }
        if pending.position.height == block.height {
            return Err(ApplyError::SameBlockCommitReveal);
        }
        let maturity_height = pending
            .position
            .height
            .checked_add(1)
            .ok_or(ApplyError::ArithmeticOverflow)?;
        let expiry_height = pending
            .position
            .height
            .checked_add(self.params.commit_ttl_blocks)
            .ok_or(ApplyError::ArithmeticOverflow)?;
        if block.height < maturity_height {
            return Err(ApplyError::CommitmentNotMature);
        }
        if block.height > expiry_height {
            return Err(ApplyError::CommitmentExpired);
        }
        if !super::schedule::is_anchor_height(name_id, block.height, self.params) {
            return Err(ApplyError::RevealOutsideAnchor);
        }
        if bond.bond_tag != intent.bond_tag || !bonds.verify(intent, bond) {
            return Err(ApplyError::InvalidBondProof);
        }

        if let Some(indexed_name) = self.active_bonds.get(&bond.bond_tag)
            && *indexed_name != name_id
        {
            return Err(ApplyError::BondAlreadyInUse);
        }

        if let Some(previous) = self.heads.get(&name_id) {
            let claimable = self
                .params
                .claimable_from(
                    previous.data.status,
                    previous.data.lease_expiry,
                    previous.data.terminal_height,
                )
                .ok_or(ApplyError::ArithmeticOverflow)?;
            if block.height < claimable {
                return Err(ApplyError::NameUnavailable);
            }
            if pending.position.height < claimable {
                return Err(ApplyError::CommitPredatesClaimability);
            }
            if replacement_predecessor != &Some(previous.state_ref) {
                return Err(ApplyError::InvalidReplacementReference);
            }
        } else if replacement_predecessor.is_some() {
            return Err(ApplyError::UnexpectedReplacementReference);
        }

        let action = take_action(transaction, *action_index, used_actions)?;
        if action.commitment != *state_commitment {
            return Err(ApplyError::ActionCommitmentMismatch);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            *action_index,
            *state_commitment,
        );
        let name_state = NameState::new(state.clone(), *state_commitment, state_ref)?;
        let statement = GenesisStatement::from_state(&name_state, action)?;
        if !proofs.verify_genesis(&statement, proof) {
            return Err(ApplyError::InvalidStateProof);
        }
        self.pending.remove(&commit.commitment);
        self.active_bonds
            .retain(|_, indexed_name| *indexed_name != name_id);
        self.active_bonds.insert(bond.bond_tag, name_id);
        self.heads.insert(name_id, name_state.clone());
        Ok(name_state)
    }

    fn apply_transition<P>(
        &mut self,
        block: &CanonicalBlock,
        transaction: &CanonicalTransaction,
        operation: &V2Operation,
        proofs: &P,
        used_actions: &mut BTreeSet<u32>,
    ) -> Result<(NameId, AppliedOperationKind), ApplyError>
    where
        P: V2StateProofVerifier,
    {
        let (kind, predecessor, state, state_commitment, action_index, proof) =
            transition_parts(operation)
                .ok_or(ApplyError::InvalidState(StateError::InvalidField))?;
        let name_id = state.name_id;
        let current = self
            .heads
            .get(&name_id)
            .cloned()
            .ok_or(ApplyError::MissingPredecessor)?;
        if current.state_ref != *predecessor || current.commitment != predecessor.commitment {
            return Err(ApplyError::StalePredecessor);
        }
        if !current.is_active_at(block.height) {
            return Err(ApplyError::InactiveLease);
        }
        self.params.validate_state(state)?;
        if state.owner_pk != current.data.owner_pk || state.name_id != current.data.name_id {
            return Err(ApplyError::InvalidState(StateError::InvalidField));
        }
        let expected_sequence = current
            .data
            .sequence
            .checked_add(1)
            .ok_or(ApplyError::InvalidSequence)?;
        if state.sequence != expected_sequence {
            return Err(ApplyError::InvalidSequence);
        }
        match kind {
            OperationKind::Update => {
                if state.status != StateStatus::Active
                    || state.terminal_height != 0
                    || state.lease_expiry != current.data.lease_expiry
                    || state.record == current.data.record
                {
                    return Err(ApplyError::InvalidUpdate);
                }
            }
            OperationKind::Renew => {
                let expected_expiry = self
                    .params
                    .lease_expiry(block.height)
                    .ok_or(ApplyError::ArithmeticOverflow)?;
                if state.status != StateStatus::Active
                    || state.terminal_height != 0
                    || state.record != current.data.record
                    || !super::schedule::is_anchor_height(name_id, block.height, self.params)
                    || state.lease_expiry != expected_expiry
                    || state.lease_expiry <= current.data.lease_expiry
                {
                    return Err(ApplyError::InvalidRenewal);
                }
            }
            OperationKind::Release => {
                if state.status != StateStatus::Released
                    || state.terminal_height != block.height
                    || state.record != current.data.record
                    || state.lease_expiry != current.data.lease_expiry
                {
                    return Err(ApplyError::InvalidRelease);
                }
            }
        }
        let action = take_action(transaction, action_index, used_actions)?;
        if action.commitment != *state_commitment {
            return Err(ApplyError::ActionCommitmentMismatch);
        }
        if !self.spent_state_nullifiers.insert(action.nullifier) {
            return Err(ApplyError::DuplicateStateNullifier);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            action_index,
            *state_commitment,
        );
        let successor = NameState::new(state.clone(), *state_commitment, state_ref)?;
        let statement =
            TransitionStatement::from_states(&current, &successor, action, kind, block.height)?;
        if !proofs.verify_transition(&statement, proof) {
            return Err(ApplyError::InvalidStateProof);
        }
        self.heads.insert(name_id, successor);
        let applied_kind = match kind {
            OperationKind::Update => AppliedOperationKind::Update,
            OperationKind::Renew => AppliedOperationKind::Renew,
            OperationKind::Release => {
                self.active_bonds
                    .retain(|_, indexed_name| *indexed_name != name_id);
                AppliedOperationKind::Release
            }
        };
        Ok((name_id, applied_kind))
    }

    /// Returns a derived resolution without consulting a provider index.
    pub fn resolution_at(&self, name_id: NameId, height: u32) -> ResolutionStatus {
        let Some(state) = self.heads.get(&name_id) else {
            return ResolutionStatus::Missing;
        };
        match self.params.lifecycle(&state.data, height) {
            Lifecycle::Active => ResolutionStatus::Active,
            Lifecycle::Grace => ResolutionStatus::Grace,
            Lifecycle::Released => ResolutionStatus::Released,
            Lifecycle::Claimable => ResolutionStatus::Expired,
        }
    }
}

/// Resolver-visible status for a derived state head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionStatus {
    /// A live, payable name state.
    Active,
    /// An expired active lease still inside its grace period.
    Grace,
    /// An explicitly released state waiting for reuse.
    Released,
    /// The state exists but is no longer active/payable and is reclaimable.
    Expired,
    /// No state head is known.
    Missing,
}

fn validate_action_order(transaction: &CanonicalTransaction) -> Result<(), ApplyError> {
    for (expected, action) in transaction.actions.iter().enumerate() {
        if action.action_index != expected as u32 {
            return Err(ApplyError::ActionView(ActionViewError::NonCanonicalIndex));
        }
    }
    Ok(())
}

fn take_action(
    transaction: &CanonicalTransaction,
    action_index: u32,
    used_actions: &mut BTreeSet<u32>,
) -> Result<IronwoodActionRef, ApplyError> {
    if !used_actions.insert(action_index) {
        return Err(ApplyError::DuplicateActionIndex);
    }
    transaction
        .action(action_index)
        .ok_or(ApplyError::ActionCommitmentMismatch)
}

type TransitionParts<'a> = Option<(
    OperationKind,
    &'a StateRef,
    &'a StateData,
    &'a [u8; 32],
    u32,
    &'a [u8],
)>;

fn transition_parts(operation: &V2Operation) -> TransitionParts<'_> {
    match operation {
        V2Operation::Update {
            predecessor,
            state,
            state_commitment,
            action_index,
            proof,
        } => Some((
            OperationKind::Update,
            predecessor,
            state,
            state_commitment,
            *action_index,
            proof,
        )),
        V2Operation::Renew {
            predecessor,
            state,
            state_commitment,
            action_index,
            proof,
        } => Some((
            OperationKind::Renew,
            predecessor,
            state,
            state_commitment,
            *action_index,
            proof,
        )),
        V2Operation::Release {
            predecessor,
            state,
            state_commitment,
            action_index,
            proof,
        } => Some((
            OperationKind::Release,
            predecessor,
            state,
            state_commitment,
            *action_index,
            proof,
        )),
        V2Operation::Commit { .. } | V2Operation::Reveal { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        operation::CanonicalTransaction,
        registration::{BondEvidence, RegistrationIntent},
        resolver::{FreshResolver, ResolveError},
        schedule,
        state::ProducerPosition,
    };
    use super::*;
    use orchard::circuit::state_note_binding::spend_auth_owner_key_bytes;
    use orchard::keys::{SpendAuthorizingKey, SpendingKey};
    use pasta_curves::{group::ff::PrimeField, pallas};
    use std::collections::BTreeMap;

    struct AcceptingProofs;

    impl V2StateProofVerifier for AcceptingProofs {
        fn verify_genesis(&self, _: &GenesisStatement, _: &[u8]) -> bool {
            true
        }

        fn verify_transition(&self, _: &TransitionStatement, _: &[u8]) -> bool {
            true
        }
    }

    struct AcceptingBond;

    impl BondProofVerifier for AcceptingBond {
        fn verify(&self, intent: &RegistrationIntent, evidence: &BondEvidence) -> bool {
            evidence.bond_tag == intent.bond_tag
        }
    }

    fn owner(seed: u8) -> [u8; 32] {
        let key = SpendingKey::from_bytes([seed; 32]).unwrap();
        let ask = SpendAuthorizingKey::from(&key);
        spend_auth_owner_key_bytes(&ask)
    }

    fn intent(seed: u8, name: &str, record: &[u8]) -> RegistrationIntent {
        RegistrationIntent {
            name: name.to_owned(),
            owner_pk: owner(seed),
            bond_tag: [seed.wrapping_add(0x40); 32],
            record: record.to_vec(),
            secret: [seed.wrapping_add(0x80); 32],
        }
    }

    fn field(value: u64) -> [u8; 32] {
        pallas::Base::from(value).to_repr()
    }

    fn transaction(
        tx_index: u32,
        txid: u8,
        actions: Vec<IronwoodActionRef>,
        operations: Vec<V2Operation>,
    ) -> CanonicalTransaction {
        CanonicalTransaction {
            tx_index,
            txid: [txid; 32],
            actions,
            operations,
        }
    }

    fn append(
        machine: &mut V2StateMachine,
        source: &mut BTreeMap<u32, CanonicalBlock>,
        transactions: Vec<CanonicalTransaction>,
    ) -> Result<AppliedBlock, ApplyError> {
        let tip = machine.tip();
        let block = CanonicalBlock {
            height: tip.height + 1,
            block_hash: [tip.height as u8 + 1; 32],
            prev_block_hash: tip.block_hash,
            transactions,
        };
        let applied = machine.apply_block(&block, &AcceptingProofs, &AcceptingBond)?;
        source.insert(block.height, block);
        Ok(applied)
    }

    fn advance_to(
        machine: &mut V2StateMachine,
        source: &mut BTreeMap<u32, CanonicalBlock>,
        height: u32,
    ) {
        while machine.tip().height < height {
            append(machine, source, Vec::new()).unwrap();
        }
    }

    fn commit(
        machine: &mut V2StateMachine,
        source: &mut BTreeMap<u32, CanonicalBlock>,
        intent: &RegistrationIntent,
        tx_index: u32,
        txid: u8,
    ) -> CommitRef {
        let commitment = intent.commitment().unwrap();
        let height = machine.tip().height + 1;
        let position = ProducerPosition::new(height, tx_index, [txid; 32]);
        append(
            machine,
            source,
            vec![transaction(
                tx_index,
                txid,
                Vec::new(),
                vec![V2Operation::Commit { commitment }],
            )],
        )
        .unwrap();
        CommitRef::new(position, commitment)
    }

    fn reveal_operation(
        intent: &RegistrationIntent,
        commit: CommitRef,
        state: StateData,
        commitment: [u8; 32],
        replacement_predecessor: Option<StateRef>,
    ) -> V2Operation {
        V2Operation::Reveal {
            intent: Box::new(intent.clone()),
            commit,
            replacement_predecessor,
            state,
            state_commitment: commitment,
            action_index: 0,
            bond: BondEvidence {
                proof: vec![1],
                anchor: field(9),
                bond_tag: intent.bond_tag,
                position: 10,
                position_floor: 0,
            },
            proof: vec![1],
        }
    }

    fn register(
        machine: &mut V2StateMachine,
        source: &mut BTreeMap<u32, CanonicalBlock>,
        intent: &RegistrationIntent,
        txid: u8,
    ) -> (u32, NameState, CommitRef) {
        let params = machine.params();
        let commit = commit(machine, source, intent, 0, txid);
        let name_id = intent.name_id().unwrap();
        let reveal_height =
            schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
        advance_to(machine, source, reveal_height - 1);
        let commitment = field(u64::from(txid) + 100);
        let state = StateData {
            name_id,
            owner_pk: intent.owner_pk,
            sequence: 0,
            record: intent.record.clone(),
            lease_expiry: params.lease_expiry(reveal_height).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let op = reveal_operation(intent, commit, state, commitment, None);
        let action = IronwoodActionRef {
            action_index: 0,
            nullifier: field(u64::from(txid) + 200),
            commitment,
        };
        append(
            machine,
            source,
            vec![transaction(0, txid.wrapping_add(1), vec![action], vec![op])],
        )
        .unwrap();
        (
            reveal_height,
            machine.head(name_id).unwrap().clone(),
            commit,
        )
    }

    fn state_after(
        previous: &NameState,
        record: &[u8],
        sequence: u64,
        lease_expiry: u32,
        status: StateStatus,
        terminal_height: u32,
    ) -> StateData {
        StateData {
            name_id: previous.data.name_id,
            owner_pk: previous.data.owner_pk,
            sequence,
            record: record.to_vec(),
            lease_expiry,
            status,
            terminal_height,
        }
    }

    fn transition_operation(
        kind: OperationKind,
        predecessor: StateRef,
        state: StateData,
        commitment: [u8; 32],
        action_index: u32,
    ) -> V2Operation {
        match kind {
            OperationKind::Update => V2Operation::Update {
                predecessor,
                state,
                state_commitment: commitment,
                action_index,
                proof: vec![1],
            },
            OperationKind::Renew => V2Operation::Renew {
                predecessor,
                state,
                state_commitment: commitment,
                action_index,
                proof: vec![1],
            },
            OperationKind::Release => V2Operation::Release {
                predecessor,
                state,
                state_commitment: commitment,
                action_index,
                proof: vec![1],
            },
        }
    }

    #[test]
    fn vertical_slice_registers_updates_renews_and_releases_one_name() {
        let params = V2Parameters::testing();
        let mut machine = V2StateMachine::new(params).unwrap();
        let mut source = BTreeMap::new();
        let alice = intent(1, "alice", b"record-0");
        let (reveal_height, state0, _) = register(&mut machine, &mut source, &alice, 10);
        let name_id = alice.name_id().unwrap();

        let state1 = state_after(
            &state0,
            b"record-1",
            1,
            state0.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let cm1 = field(301);
        let update1 = transition_operation(OperationKind::Update, state0.state_ref, state1, cm1, 0);
        append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                30,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(401),
                    commitment: cm1,
                }],
                vec![update1],
            )],
        )
        .unwrap();
        let state1 = machine.head(name_id).unwrap().clone();

        let state2 = state_after(
            &state1,
            b"record-2",
            2,
            state1.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let cm2 = field(302);
        append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                31,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(402),
                    commitment: cm2,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    state1.state_ref,
                    state2,
                    cm2,
                    0,
                )],
            )],
        )
        .unwrap();
        let state2 = machine.head(name_id).unwrap().clone();

        let renew_height =
            schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
        assert!(renew_height < state2.data.lease_expiry);
        advance_to(&mut machine, &mut source, renew_height - 1);
        let state3 = state_after(
            &state2,
            b"record-2",
            3,
            params.lease_expiry(renew_height).unwrap(),
            StateStatus::Active,
            0,
        );
        let cm3 = field(303);
        append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                32,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(403),
                    commitment: cm3,
                }],
                vec![transition_operation(
                    OperationKind::Renew,
                    state2.state_ref,
                    state3,
                    cm3,
                    0,
                )],
            )],
        )
        .unwrap();
        let state3 = machine.head(name_id).unwrap().clone();
        assert_eq!(state3.data.record, b"record-2");
        assert!(state3.data.lease_expiry > state2.data.lease_expiry);

        let update_height = renew_height + 1;
        advance_to(&mut machine, &mut source, update_height - 1);
        let state4 = state_after(
            &state3,
            b"record-3",
            4,
            state3.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let cm4 = field(304);
        append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                33,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(404),
                    commitment: cm4,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    state3.state_ref,
                    state4,
                    cm4,
                    0,
                )],
            )],
        )
        .unwrap();
        let state4 = machine.head(name_id).unwrap().clone();
        assert_eq!(state4.data.lease_expiry, state3.data.lease_expiry);

        let release_height = update_height + 1;
        let state5 = state_after(
            &state4,
            b"record-3",
            5,
            state4.data.lease_expiry,
            StateStatus::Released,
            release_height,
        );
        let cm5 = field(305);
        append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                34,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(405),
                    commitment: cm5,
                }],
                vec![transition_operation(
                    OperationKind::Release,
                    state4.state_ref,
                    state5,
                    cm5,
                    0,
                )],
            )],
        )
        .unwrap();
        assert_eq!(
            machine.resolution_at(name_id, machine.tip().height),
            ResolutionStatus::Released
        );
        let resolved = FreshResolver::new(params)
            .unwrap()
            .resolve("alice", &source, &AcceptingProofs, &AcceptingBond)
            .unwrap();
        assert_eq!(resolved.status, ResolutionStatus::Released);
        assert_eq!(resolved.state.unwrap().data.sequence, 5);
        assert!(resolved.stats.candidate_block_probes >= 1);
        assert!(resolved.stats.tail_blocks_scanned >= 2);
        assert!(resolved.stats.predecessor_chain_steps >= 5);

        let before_first_renew = source
            .iter()
            .filter(|(height, _)| **height <= reveal_height)
            .map(|(height, block)| (*height, block.clone()))
            .collect::<BTreeMap<_, _>>();
        let first_lookup = FreshResolver::new(params)
            .unwrap()
            .resolve(
                "alice",
                &before_first_renew,
                &AcceptingProofs,
                &AcceptingBond,
            )
            .unwrap();
        assert_eq!(first_lookup.status, ResolutionStatus::Active);
        assert_eq!(first_lookup.state.unwrap().data.sequence, 0);

        let mut no_anchor = source.clone();
        for block in no_anchor.values_mut() {
            for transaction in &mut block.transactions {
                transaction.operations.retain(|operation| {
                    !matches!(
                        operation,
                        V2Operation::Reveal { .. } | V2Operation::Renew { .. }
                    )
                });
            }
        }
        let missing = FreshResolver::new(params)
            .unwrap()
            .resolve("alice", &no_anchor, &AcceptingProofs, &AcceptingBond)
            .unwrap();
        assert_eq!(missing.status, ResolutionStatus::Missing);

        let mut reorged_anchor = source.clone();
        reorged_anchor
            .get_mut(&renew_height)
            .unwrap()
            .transactions
            .clear();
        reorged_anchor.get_mut(&renew_height).unwrap().block_hash = [0xee; 32];
        assert_eq!(
            FreshResolver::new(params).unwrap().resolve(
                "alice",
                &reorged_anchor,
                &AcceptingProofs,
                &AcceptingBond
            ),
            Err(ResolveError::InvalidLineage)
        );

        let mut reorged_predecessor = source.clone();
        reorged_predecessor
            .get_mut(&reveal_height)
            .unwrap()
            .transactions
            .clear();
        reorged_predecessor
            .get_mut(&reveal_height)
            .unwrap()
            .block_hash = [0xdd; 32];
        assert_eq!(
            FreshResolver::new(params).unwrap().resolve(
                "alice",
                &reorged_predecessor,
                &AcceptingProofs,
                &AcceptingBond
            ),
            Err(ResolveError::InvalidLineage)
        );
        assert!(reveal_height < machine.tip().height);
    }

    #[test]
    fn missed_renewal_and_release_have_non_payable_boundaries() {
        let params = V2Parameters::testing();
        let mut machine = V2StateMachine::new(params).unwrap();
        let mut source = BTreeMap::new();
        let alice = intent(10, "lease", b"record");
        let (_, state0, _) = register(&mut machine, &mut source, &alice, 90);
        let name_id = alice.name_id().unwrap();
        let expiry = state0.data.lease_expiry;

        let renewal_height =
            schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
        advance_to(&mut machine, &mut source, renewal_height - 1);
        let invalid_renewal =
            state_after(&state0, b"record", 1, expiry + 1, StateStatus::Active, 0);
        let invalid_renewal_error = append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                89,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(1099),
                    commitment: field(1100),
                }],
                vec![transition_operation(
                    OperationKind::Renew,
                    state0.state_ref,
                    invalid_renewal,
                    field(1100),
                    0,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(invalid_renewal_error, ApplyError::InvalidRenewal);

        advance_to(&mut machine, &mut source, expiry);
        assert_eq!(
            machine.resolution_at(name_id, expiry),
            ResolutionStatus::Grace
        );
        assert_eq!(
            machine.resolution_at(name_id, expiry + params.grace_period_blocks - 1),
            ResolutionStatus::Grace
        );
        advance_to(
            &mut machine,
            &mut source,
            expiry + params.grace_period_blocks,
        );
        assert_eq!(
            machine.resolution_at(name_id, machine.tip().height),
            ResolutionStatus::Expired
        );
        let stale_lookup = FreshResolver::new(params)
            .unwrap()
            .resolve("lease", &source, &AcceptingProofs, &AcceptingBond)
            .unwrap();
        assert_eq!(stale_lookup.status, ResolutionStatus::Missing);
        assert!(stale_lookup.state.is_none());

        let update = state_after(
            &state0,
            b"should-fail",
            1,
            state0.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let update_error = append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                91,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(1101),
                    commitment: field(1102),
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    state0.state_ref,
                    update,
                    field(1102),
                    0,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(update_error, ApplyError::InactiveLease);

        let mut release_machine = V2StateMachine::new(params).unwrap();
        let mut release_source = BTreeMap::new();
        let release_intent = intent(11, "release-lease", b"record");
        let (_, release_state, _) = register(
            &mut release_machine,
            &mut release_source,
            &release_intent,
            92,
        );
        let terminal_height = release_machine.tip().height + 1;
        let terminal = state_after(
            &release_state,
            b"record",
            1,
            release_state.data.lease_expiry,
            StateStatus::Released,
            terminal_height,
        );
        let terminal_commitment = field(1103);
        append(
            &mut release_machine,
            &mut release_source,
            vec![transaction(
                0,
                93,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(1104),
                    commitment: terminal_commitment,
                }],
                vec![transition_operation(
                    OperationKind::Release,
                    release_state.state_ref,
                    terminal,
                    terminal_commitment,
                    0,
                )],
            )],
        )
        .unwrap();
        let release_name = release_intent.name_id().unwrap();
        assert_eq!(
            release_machine.resolution_at(release_name, terminal_height),
            ResolutionStatus::Released
        );
        let release_claimable = terminal_height + params.reuse_delay_blocks;
        assert_eq!(
            release_machine.resolution_at(release_name, release_claimable - 1),
            ResolutionStatus::Released
        );
        assert_eq!(
            release_machine.resolution_at(release_name, release_claimable),
            ResolutionStatus::Expired
        );
    }

    #[test]
    fn registration_preserves_two_stage_maturity_slot_and_reclaim_boundaries() {
        let params = V2Parameters::testing();
        let mut machine = V2StateMachine::new(params).unwrap();
        let mut source = BTreeMap::new();
        let alice = intent(2, "alice", b"record");
        let commitment = alice.commitment().unwrap();
        let same_block_position = ProducerPosition::new(1, 0, [9; 32]);
        let same_block_state = StateData {
            name_id: alice.name_id().unwrap(),
            owner_pk: alice.owner_pk,
            sequence: 0,
            record: alice.record.clone(),
            lease_expiry: params.lease_expiry(1).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let same_block = reveal_operation(
            &alice,
            CommitRef::new(same_block_position, commitment),
            same_block_state,
            field(500),
            None,
        );
        let error = append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                9,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(501),
                    commitment: field(500),
                }],
                vec![V2Operation::Commit { commitment }, same_block],
            )],
        )
        .unwrap_err();
        assert_eq!(error, ApplyError::SameBlockCommitReveal);

        let commit_ref = commit(&mut machine, &mut source, &alice, 0, 10);
        let name_id = alice.name_id().unwrap();
        let reveal_height = schedule::next_anchor_height(name_id, 2, params).unwrap();
        advance_to(&mut machine, &mut source, reveal_height - 1);
        let mut wrong_intent = alice.clone();
        wrong_intent.secret[0] ^= 1;
        let state = StateData {
            name_id,
            owner_pk: wrong_intent.owner_pk,
            sequence: 0,
            record: wrong_intent.record.clone(),
            lease_expiry: params.lease_expiry(reveal_height).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let wrong_error = append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                11,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(502),
                    commitment: field(501),
                }],
                vec![reveal_operation(
                    &wrong_intent,
                    commit_ref,
                    state,
                    field(501),
                    None,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(wrong_error, ApplyError::CommitmentMismatch);

        let mut outside_machine = V2StateMachine::new(params).unwrap();
        let mut outside_source = BTreeMap::new();
        let outside_intent = intent(3, "outside", b"record");
        let outside_commit = commit(
            &mut outside_machine,
            &mut outside_source,
            &outside_intent,
            0,
            20,
        );
        let outside_name = outside_intent.name_id().unwrap();
        let outside_height = (2..=16)
            .find(|height| !schedule::is_anchor_height(outside_name, *height, params))
            .unwrap();
        advance_to(
            &mut outside_machine,
            &mut outside_source,
            outside_height - 1,
        );
        let outside_state = StateData {
            name_id: outside_name,
            owner_pk: outside_intent.owner_pk,
            sequence: 0,
            record: outside_intent.record.clone(),
            lease_expiry: params.lease_expiry(outside_height).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let outside_error = append(
            &mut outside_machine,
            &mut outside_source,
            vec![transaction(
                0,
                21,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(601),
                    commitment: field(600),
                }],
                vec![reveal_operation(
                    &outside_intent,
                    outside_commit,
                    outside_state,
                    field(600),
                    None,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(outside_error, ApplyError::RevealOutsideAnchor);

        let mut unavailable_machine = V2StateMachine::new(params).unwrap();
        let mut unavailable_source = BTreeMap::new();
        let unavailable_intent = intent(12, "unavailable", b"record");
        let (_, unavailable_head, _) = register(
            &mut unavailable_machine,
            &mut unavailable_source,
            &unavailable_intent,
            22,
        );
        let unavailable_name = unavailable_intent.name_id().unwrap();
        let unavailable_claimable = params
            .claimable_from(
                unavailable_head.data.status,
                unavailable_head.data.lease_expiry,
                unavailable_head.data.terminal_height,
            )
            .unwrap();
        let replacement_commit_height = schedule::next_anchor_height(
            unavailable_name,
            unavailable_machine.tip().height + 1,
            params,
        )
        .unwrap();
        let unavailable_replacement = intent(13, "unavailable", b"new-record");
        advance_to(
            &mut unavailable_machine,
            &mut unavailable_source,
            replacement_commit_height - 1,
        );
        let unavailable_commit = commit(
            &mut unavailable_machine,
            &mut unavailable_source,
            &unavailable_replacement,
            0,
            23,
        );
        assert_eq!(
            unavailable_commit.position.height,
            replacement_commit_height
        );
        let unavailable_reveal_height =
            schedule::next_anchor_height(unavailable_name, replacement_commit_height + 1, params)
                .unwrap();
        assert!(unavailable_reveal_height < unavailable_claimable);
        advance_to(
            &mut unavailable_machine,
            &mut unavailable_source,
            unavailable_reveal_height - 1,
        );
        let unavailable_state = StateData {
            name_id: unavailable_name,
            owner_pk: unavailable_replacement.owner_pk,
            sequence: 0,
            record: unavailable_replacement.record.clone(),
            lease_expiry: params.lease_expiry(unavailable_reveal_height).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let unavailable_error = append(
            &mut unavailable_machine,
            &mut unavailable_source,
            vec![transaction(
                0,
                24,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(650),
                    commitment: field(651),
                }],
                vec![reveal_operation(
                    &unavailable_replacement,
                    unavailable_commit,
                    unavailable_state,
                    field(651),
                    Some(unavailable_head.state_ref),
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(unavailable_error, ApplyError::NameUnavailable);

        let mut expiry_machine = V2StateMachine::new(params).unwrap();
        let mut expiry_source = BTreeMap::new();
        let expiry_intent = intent(4, "expired", b"record");
        let expiry_commit = commit(
            &mut expiry_machine,
            &mut expiry_source,
            &expiry_intent,
            0,
            30,
        );
        advance_to(&mut expiry_machine, &mut expiry_source, 16);
        assert!(expiry_machine.pending(expiry_commit.commitment).is_none());
        let expiry_name = expiry_intent.name_id().unwrap();
        let expiry_reveal = schedule::next_anchor_height(expiry_name, 17, params).unwrap();
        advance_to(&mut expiry_machine, &mut expiry_source, expiry_reveal - 1);
        let expiry_state = StateData {
            name_id: expiry_name,
            owner_pk: expiry_intent.owner_pk,
            sequence: 0,
            record: expiry_intent.record.clone(),
            lease_expiry: params.lease_expiry(expiry_reveal).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let expiry_error = append(
            &mut expiry_machine,
            &mut expiry_source,
            vec![transaction(
                0,
                31,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(701),
                    commitment: field(700),
                }],
                vec![reveal_operation(
                    &expiry_intent,
                    expiry_commit,
                    expiry_state,
                    field(700),
                    None,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(expiry_error, ApplyError::UnknownCommitment);

        let mut reclaim_machine = V2StateMachine::new(params).unwrap();
        let mut reclaim_source = BTreeMap::new();
        let reclaim_intent = intent(5, "reclaim", b"record");
        let (_, old_state, _) = register(
            &mut reclaim_machine,
            &mut reclaim_source,
            &reclaim_intent,
            40,
        );
        let claimable = params
            .claimable_from(
                old_state.data.status,
                old_state.data.lease_expiry,
                old_state.data.terminal_height,
            )
            .unwrap();
        advance_to(&mut reclaim_machine, &mut reclaim_source, claimable - 2);
        let replacement = intent(6, "reclaim", b"new-record");
        let replacement_commit = commit(
            &mut reclaim_machine,
            &mut reclaim_source,
            &replacement,
            0,
            41,
        );
        let replacement_name = replacement.name_id().unwrap();
        let replacement_height =
            schedule::next_anchor_height(replacement_name, claimable, params).unwrap();
        advance_to(
            &mut reclaim_machine,
            &mut reclaim_source,
            replacement_height - 1,
        );
        let replacement_state = StateData {
            name_id: replacement_name,
            owner_pk: replacement.owner_pk,
            sequence: 0,
            record: replacement.record.clone(),
            lease_expiry: params.lease_expiry(replacement_height).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let reclaim_error = append(
            &mut reclaim_machine,
            &mut reclaim_source,
            vec![transaction(
                0,
                42,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(801),
                    commitment: field(800),
                }],
                vec![reveal_operation(
                    &replacement,
                    replacement_commit,
                    replacement_state,
                    field(800),
                    Some(old_state.state_ref),
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(reclaim_error, ApplyError::CommitPredatesClaimability);

        let mut bond_machine = V2StateMachine::new(params).unwrap();
        let mut bond_source = BTreeMap::new();
        let bond_owner = intent(14, "bond-owner", b"record");
        register(&mut bond_machine, &mut bond_source, &bond_owner, 60);
        let mut duplicate_bond = intent(15, "bond-other", b"record");
        duplicate_bond.bond_tag = bond_owner.bond_tag;
        let duplicate_commit = commit(&mut bond_machine, &mut bond_source, &duplicate_bond, 0, 61);
        let duplicate_name = duplicate_bond.name_id().unwrap();
        let duplicate_reveal_height = schedule::next_anchor_height(
            duplicate_name,
            duplicate_commit.position.height + 1,
            params,
        )
        .unwrap();
        advance_to(
            &mut bond_machine,
            &mut bond_source,
            duplicate_reveal_height - 1,
        );
        let duplicate_state = StateData {
            name_id: duplicate_name,
            owner_pk: duplicate_bond.owner_pk,
            sequence: 0,
            record: duplicate_bond.record.clone(),
            lease_expiry: params.lease_expiry(duplicate_reveal_height).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let duplicate_error = append(
            &mut bond_machine,
            &mut bond_source,
            vec![transaction(
                0,
                62,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(1201),
                    commitment: field(1200),
                }],
                vec![reveal_operation(
                    &duplicate_bond,
                    duplicate_commit,
                    duplicate_state,
                    field(1200),
                    None,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(duplicate_error, ApplyError::BondAlreadyInUse);
    }

    #[test]
    fn lineage_and_same_action_binding_reject_stale_and_cross_action_inputs() {
        let params = V2Parameters::testing();
        let mut machine = V2StateMachine::new(params).unwrap();
        let mut source = BTreeMap::new();
        let alice = intent(7, "alice", b"record");
        let (_, state0, _) = register(&mut machine, &mut source, &alice, 50);
        let name_id = alice.name_id().unwrap();
        let valid_state = state_after(
            &state0,
            b"changed",
            1,
            state0.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let valid_cm = field(901);
        let mut wrong_predecessor = state0.state_ref;
        wrong_predecessor.producer_tx_index += 1;
        let stale_error = append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                51,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(902),
                    commitment: valid_cm,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    wrong_predecessor,
                    valid_state.clone(),
                    valid_cm,
                    0,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(stale_error, ApplyError::StalePredecessor);

        let cross_action_error = append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                52,
                vec![
                    IronwoodActionRef {
                        action_index: 0,
                        nullifier: field(903),
                        commitment: field(904),
                    },
                    IronwoodActionRef {
                        action_index: 1,
                        nullifier: field(905),
                        commitment: valid_cm,
                    },
                ],
                vec![transition_operation(
                    OperationKind::Update,
                    state0.state_ref,
                    valid_state.clone(),
                    valid_cm,
                    0,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(cross_action_error, ApplyError::ActionCommitmentMismatch);

        append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                53,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(906),
                    commitment: valid_cm,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    state0.state_ref,
                    valid_state,
                    valid_cm,
                    0,
                )],
            )],
        )
        .unwrap();
        let current = machine.head(name_id).unwrap().clone();
        let stale_state = state_after(
            &current,
            b"other",
            2,
            current.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let stale_again = append(
            &mut machine,
            &mut source,
            vec![transaction(
                0,
                54,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(907),
                    commitment: field(908),
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    state0.state_ref,
                    stale_state,
                    field(908),
                    0,
                )],
            )],
        )
        .unwrap_err();
        assert_eq!(stale_again, ApplyError::StalePredecessor);
    }

    #[test]
    fn unrelated_names_commute_and_schedule_gap_is_formally_bounded() {
        let params = V2Parameters::testing();
        let mut machine = V2StateMachine::new(params).unwrap();
        let mut source = BTreeMap::new();
        let alice = intent(8, "alice", b"alice");
        let bob = intent(9, "bob", b"bob");
        let (_, alice0, _) = register(&mut machine, &mut source, &alice, 60);
        let (_, bob0, _) = register(&mut machine, &mut source, &bob, 70);
        let alice1 = state_after(
            &alice0,
            b"alice-1",
            1,
            alice0.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let bob1 = state_after(
            &bob0,
            b"bob-1",
            1,
            bob0.data.lease_expiry,
            StateStatus::Active,
            0,
        );
        let alice_cm = field(1001);
        let bob_cm = field(1002);
        let applied = append(
            &mut machine,
            &mut source,
            vec![
                transaction(
                    0,
                    80,
                    vec![IronwoodActionRef {
                        action_index: 0,
                        nullifier: field(1003),
                        commitment: alice_cm,
                    }],
                    vec![transition_operation(
                        OperationKind::Update,
                        alice0.state_ref,
                        alice1,
                        alice_cm,
                        0,
                    )],
                ),
                transaction(
                    1,
                    81,
                    vec![IronwoodActionRef {
                        action_index: 0,
                        nullifier: field(1004),
                        commitment: bob_cm,
                    }],
                    vec![transition_operation(
                        OperationKind::Update,
                        bob0.state_ref,
                        bob1,
                        bob_cm,
                        0,
                    )],
                ),
            ],
        )
        .unwrap();
        assert_eq!(applied.operations.len(), 2);
        assert_eq!(
            machine
                .head(alice.name_id().unwrap())
                .unwrap()
                .data
                .sequence,
            1
        );
        assert_eq!(
            machine.head(bob.name_id().unwrap()).unwrap().data.sequence,
            1
        );

        let max_gap = params.max_anchor_gap().unwrap();
        for epoch in 0..128 {
            let left = schedule::slot_height(alice.name_id().unwrap(), epoch, params).unwrap();
            let right = schedule::slot_height(alice.name_id().unwrap(), epoch + 1, params).unwrap();
            assert!(right - left <= max_gap);
            assert!(right > left);
        }
        assert!(
            schedule::candidate_anchor_heights(alice.name_id().unwrap(), 100, params).len() <= 3
        );
    }
}
