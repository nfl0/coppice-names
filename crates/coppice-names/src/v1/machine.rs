//! Canonical Names v1 state-machine replay over typed Ironwood effects.

use super::{
    lease::{Lifecycle, V1Parameters},
    operation::{
        ActionViewError, CanonicalBlock, CanonicalTransaction, ChainTip, OperationKind, V1Operation,
    },
    registration::CommitRef,
    state::{NameId, NameState, StateData, StateError, StateRef, StateStatus},
    transition::{GenesisStatement, StatementError, TransitionStatement, V1StateProofVerifier},
};
use std::collections::{BTreeMap, BTreeSet};

/// Errors from canonical v1 block application.
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
    /// The disclosed registration intent is malformed.
    InvalidRegistration,
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
    /// An earlier carrier message in this transaction already claimed the
    /// selected physical Ironwood action.
    ActionAlreadyClaimed,
    /// A state proof did not verify.
    InvalidStateProof,
    /// The selected action commitment is not the declared successor commitment.
    ActionCommitmentMismatch,
    /// The selected action does not spend the accepted head's authenticated future nullifier.
    ActionNullifierMismatch,
    /// The predecessor reference does not identify the current head.
    StalePredecessor,
    /// No current head exists for a non-genesis operation.
    MissingPredecessor,
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
    /// Every v1 message processed in canonical order. A rejection is local to
    /// that message; it never vetoes an otherwise canonical Zcash block.
    pub operations: Vec<AppliedOperation>,
    /// Number of pending commitments retained after end-of-block expiry.
    pub pending_commitments: usize,
}

/// Canonical application result for one carried v1 message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedOperation {
    /// Transaction index containing the message.
    pub tx_index: u32,
    /// Message index within the transaction carrier.
    pub operation_index: u32,
    /// Deterministic Names acceptance or rejection.
    pub result: AppliedOperationResult,
}

/// Per-message Names result. [`ApplyError`] is also used for fatal canonical
/// input errors, but `apply_block` returns it only before message execution or
/// for broken block continuity/effect shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppliedOperationResult {
    /// A hidden COMMIT was retained or a visible state operation was applied.
    Accepted(Option<(NameId, AppliedOperationKind)>),
    /// The message was ignored as invalid application data.
    Rejected(ApplyError),
}

/// Operation kinds accepted by one v1 block, including genesis REVEAL.
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

/// Derived v1 application state. It is not serialized into Core and has no
/// global root consumed by operations.
#[derive(Clone, Debug)]
pub struct V1StateMachine {
    params: V1Parameters,
    tip: ChainTip,
    pending: BTreeMap<[u8; 32], CommitRef>,
    heads: BTreeMap<NameId, NameState>,
    current_by_nullifier: BTreeMap<[u8; 32], BTreeSet<NameId>>,
}

impl V1StateMachine {
    /// Creates an empty v1 state machine at the block before activation.
    ///
    /// The all-zero predecessor is retained for deterministic synthetic
    /// chains used by the existing unit tests. Real canonical replay should
    /// use [`Self::from_activation_parent`] with the activation block's
    /// authenticated predecessor hash.
    pub fn new(params: V1Parameters) -> Result<Self, super::lease::LeaseParameterError> {
        Self::from_activation_parent(params, [0; 32])
    }

    /// Creates an empty v1 state machine immediately before activation using
    /// the canonical hash of the activation block's predecessor.
    ///
    /// This does not weaken block continuity: the first block passed to
    /// [`Self::apply_block`] must still have this hash in its
    /// `prev_block_hash` field, and all later blocks must chain from the
    /// authenticated tip in the usual way.
    pub fn from_activation_parent(
        params: V1Parameters,
        parent_block_hash: [u8; 32],
    ) -> Result<Self, super::lease::LeaseParameterError> {
        params.validate()?;
        Ok(Self {
            tip: ChainTip {
                height: params.activation_height - 1,
                block_hash: parent_block_hash,
            },
            params,
            pending: BTreeMap::new(),
            heads: BTreeMap::new(),
            current_by_nullifier: BTreeMap::new(),
        })
    }

    /// Returns the immutable Names v1 parameters.
    pub const fn params(&self) -> V1Parameters {
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

    /// Applies a canonical block atomically after v1 proof and policy checks.
    pub fn apply_block<P>(
        &mut self,
        block: &CanonicalBlock,
        proofs: &P,
    ) -> Result<AppliedBlock, ApplyError>
    where
        P: V1StateProofVerifier,
    {
        let mut next = self.clone();
        let applied = next.apply_block_inner(block, proofs)?;
        *self = next;
        Ok(applied)
    }

    fn apply_block_inner<P>(
        &mut self,
        block: &CanonicalBlock,
        proofs: &P,
    ) -> Result<AppliedBlock, ApplyError>
    where
        P: V1StateProofVerifier,
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

        let mut results = Vec::new();
        for transaction in &block.transactions {
            validate_action_order(transaction)?;
            if !transaction.has_canonical_operation_order() {
                return Err(ApplyError::NonCanonicalOperationOrder);
            }
            for (operation_index, operation) in transaction.operations.iter().enumerate() {
                // Semantic rejection is operation-atomic. In particular an
                // invalid proof must not consume a pending COMMIT, action
                // index, or application-side nullifier before a later valid
                // operation is processed.
                let before = self.clone();
                let outcome = if !transaction.is_first_action_claim(operation_index) {
                    Err(ApplyError::ActionAlreadyClaimed)
                } else {
                    match operation {
                        V1Operation::Commit { commitment } => {
                            let position = transaction.position(block.height);
                            let commit =
                                CommitRef::new(position, operation_index as u32, *commitment);
                            if self.pending.contains_key(commitment) {
                                Err(ApplyError::DuplicateCommitment)
                            } else {
                                self.pending.insert(*commitment, commit);
                                Ok(None)
                            }
                        }
                        V1Operation::Reveal { .. } => self
                            .apply_reveal(
                                block,
                                transaction,
                                operation_index as u32,
                                operation,
                                proofs,
                            )
                            .map(|state| Some((state.data.name_id, AppliedOperationKind::Reveal))),
                        V1Operation::Update { .. }
                        | V1Operation::Renew { .. }
                        | V1Operation::Release { .. } => self
                            .apply_transition(
                                block,
                                transaction,
                                operation_index as u32,
                                operation,
                                proofs,
                            )
                            .map(Some),
                    }
                };
                let result = match outcome {
                    Ok(accepted) => AppliedOperationResult::Accepted(accepted),
                    Err(error) => {
                        if is_fatal_canonical_error(&error) {
                            return Err(error);
                        }
                        *self = before;
                        AppliedOperationResult::Rejected(error)
                    }
                };
                results.push(AppliedOperation {
                    tx_index: transaction.tx_index,
                    operation_index: operation_index as u32,
                    result,
                });
            }
            for action in &transaction.actions {
                if let Some(names) = self.current_by_nullifier.remove(&action.nullifier) {
                    for name_id in names {
                        if let Some(head) = self.heads.get_mut(&name_id)
                            && head.state_ref.nullifier == action.nullifier
                            && head.abandoned_height.is_none()
                            && head.data.status == StateStatus::Active
                            && self.params.lifecycle(&head.data, block.height)
                                != Lifecycle::Claimable
                        {
                            head.abandon(block.height);
                        }
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
            operations: results,
            pending_commitments: self.pending.len(),
        })
    }

    fn apply_reveal<P>(
        &mut self,
        block: &CanonicalBlock,
        transaction: &CanonicalTransaction,
        operation_index: u32,
        operation: &V1Operation,
        proofs: &P,
    ) -> Result<NameState, ApplyError>
    where
        P: V1StateProofVerifier,
    {
        let V1Operation::Reveal {
            intent,
            commit,
            replacement_predecessor,
            state,
            state_commitment,
            state_nullifier,
            action_index,
            proof,
        } = operation
        else {
            unreachable!("apply_reveal called with non-reveal")
        };
        let name_id = intent
            .name_id()
            .map_err(|_| ApplyError::InvalidRegistration)?;
        // Representation and configured record bounds are canonical statement
        // preprocessing. Genesis formation itself is enforced by the proof.
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
        if let Some(previous) = self.heads.get(&name_id) {
            let claimable =
                claimable_from_head(self.params, previous).ok_or(ApplyError::ArithmeticOverflow)?;
            if block.height < claimable {
                return Err(ApplyError::NameUnavailable);
            }
            if pending.position.height < claimable {
                return Err(ApplyError::CommitPredatesClaimability);
            }
            match replacement_predecessor {
                Some(reference) if *reference == previous.state_ref => {}
                None if self
                    .no_predecessor_reset_eligible(previous, pending.position.height)? => {}
                Some(_) => return Err(ApplyError::InvalidReplacementReference),
                None => return Err(ApplyError::InvalidReplacementReference),
            }
        } else if replacement_predecessor.is_some() {
            return Err(ApplyError::UnexpectedReplacementReference);
        }

        let action = transaction
            .action(*action_index)
            .ok_or(ApplyError::ActionCommitmentMismatch)?;
        if action.commitment != *state_commitment {
            return Err(ApplyError::ActionCommitmentMismatch);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            *action_index,
            operation_index,
            *state_commitment,
            *state_nullifier,
        );
        let name_state = NameState::new(state.clone(), *state_commitment, state_ref)?;
        let statement =
            GenesisStatement::from_reveal(intent, &name_state, action, block.height, self.params)?;
        if !proofs.verify_genesis(&statement, proof) {
            return Err(ApplyError::InvalidStateProof);
        }
        self.pending.remove(&commit.commitment);
        self.replace_head(name_id, name_state.clone());
        Ok(name_state)
    }

    /// Returns whether a hidden COMMIT made at `commit_height` can safely use
    /// the bounded history-reset path instead of an explicit terminal head.
    /// The comparison is deliberately against the COMMIT height, not REVEAL.
    fn no_predecessor_reset_eligible(
        &self,
        previous: &NameState,
        commit_height: u32,
    ) -> Result<bool, ApplyError> {
        let horizon = self
            .params
            .reset_horizon()
            .map_err(|_| ApplyError::ArithmeticOverflow)?;
        let Some(anchor) = self.params.anchor_height(previous.data.lease_expiry) else {
            return Err(ApplyError::ArithmeticOverflow);
        };
        // At exactly `anchor + horizon` every active/grace or release path
        // from that anchor is claimable. Therefore only a strictly newer
        // anchor can still make this COMMIT pre-claimability.
        Ok(anchor <= commit_height.saturating_sub(horizon))
    }

    fn apply_transition<P>(
        &mut self,
        block: &CanonicalBlock,
        transaction: &CanonicalTransaction,
        operation_index: u32,
        operation: &V1Operation,
        proofs: &P,
    ) -> Result<(NameId, AppliedOperationKind), ApplyError>
    where
        P: V1StateProofVerifier,
    {
        let (kind, predecessor, state, state_commitment, state_nullifier, action_index, proof) =
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
        if current.abandoned_height.is_some() {
            return Err(ApplyError::StalePredecessor);
        }
        // Representation and configured record bounds are canonical statement
        // preprocessing. Local transition legality is enforced by the proof.
        self.params.validate_state(state)?;
        let action = transaction
            .action(action_index)
            .ok_or(ApplyError::ActionCommitmentMismatch)?;
        if action.commitment != *state_commitment {
            return Err(ApplyError::ActionCommitmentMismatch);
        }
        if action.nullifier != current.state_ref.nullifier {
            return Err(ApplyError::ActionNullifierMismatch);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            action_index,
            operation_index,
            *state_commitment,
            *state_nullifier,
        );
        let successor = NameState::new(state.clone(), *state_commitment, state_ref)?;
        let statement = TransitionStatement::from_states(
            &current,
            &successor,
            action,
            kind,
            block.height,
            self.params,
        )?;
        if !proofs.verify_transition(&statement, proof) {
            return Err(ApplyError::InvalidStateProof);
        }
        self.replace_head(name_id, successor);
        let applied_kind = match kind {
            OperationKind::Update => AppliedOperationKind::Update,
            OperationKind::Renew => AppliedOperationKind::Renew,
            OperationKind::Release => AppliedOperationKind::Release,
        };
        Ok((name_id, applied_kind))
    }

    /// Returns a derived resolution without consulting a provider index.
    pub fn resolution_at(&self, name_id: NameId, height: u32) -> ResolutionStatus {
        let Some(state) = self.heads.get(&name_id) else {
            return ResolutionStatus::Missing;
        };
        if let Some(abandoned) = state.abandoned_height {
            return if self
                .params
                .head_claimable_from(&state.data, Some(abandoned))
                .is_some_and(|claimable| height >= claimable)
            {
                ResolutionStatus::Expired
            } else {
                ResolutionStatus::Abandoned
            };
        }
        match self.params.lifecycle(&state.data, height) {
            Lifecycle::Active => ResolutionStatus::Active,
            Lifecycle::Stale => ResolutionStatus::Stale,
            Lifecycle::Grace => ResolutionStatus::Grace,
            Lifecycle::Released => ResolutionStatus::Released,
            Lifecycle::Claimable => ResolutionStatus::Expired,
        }
    }

    fn replace_head(&mut self, name_id: NameId, successor: NameState) {
        if let Some(predecessor) = self.heads.get(&name_id) {
            let nullifier = predecessor.state_ref.nullifier;
            if let Some(names) = self.current_by_nullifier.get_mut(&nullifier) {
                names.remove(&name_id);
                if names.is_empty() {
                    self.current_by_nullifier.remove(&nullifier);
                }
            }
        }
        if successor.data.status == StateStatus::Active {
            self.current_by_nullifier
                .entry(successor.state_ref.nullifier)
                .or_default()
                .insert(name_id);
        }
        self.heads.insert(name_id, successor);
    }
}

fn is_fatal_canonical_error(error: &ApplyError) -> bool {
    matches!(error, ApplyError::ArithmeticOverflow)
}

/// Resolver-visible status for a derived state head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionStatus {
    /// A live, payable name state.
    Active,
    /// The owner can still renew before lease expiry, but the last anchor is
    /// outside the payable discovery window.
    Stale,
    /// An expired active lease still inside its grace period.
    Grace,
    /// An explicitly released state waiting for reuse.
    Released,
    /// The authenticated current state note was spent without an accepted
    /// Names successor and is waiting for the reuse delay.
    Abandoned,
    /// The state exists but is no longer active/payable and is reclaimable.
    Expired,
    /// No state head is known.
    Missing,
}

fn claimable_from_head(params: V1Parameters, state: &NameState) -> Option<u32> {
    params.head_claimable_from(&state.data, state.abandoned_height)
}

fn validate_action_order(transaction: &CanonicalTransaction) -> Result<(), ApplyError> {
    for (expected, action) in transaction.actions.iter().enumerate() {
        if action.action_index != expected as u32 {
            return Err(ApplyError::ActionView(ActionViewError::NonCanonicalIndex));
        }
    }
    Ok(())
}

type TransitionParts<'a> = Option<(
    OperationKind,
    &'a StateRef,
    &'a StateData,
    &'a [u8; 32],
    &'a [u8; 32],
    u32,
    &'a [u8],
)>;

fn transition_parts(operation: &V1Operation) -> TransitionParts<'_> {
    match operation {
        V1Operation::Update {
            predecessor,
            state,
            state_commitment,
            state_nullifier,
            action_index,
            proof,
        } => Some((
            OperationKind::Update,
            predecessor,
            state,
            state_commitment,
            state_nullifier,
            *action_index,
            proof,
        )),
        V1Operation::Renew {
            predecessor,
            state,
            state_commitment,
            state_nullifier,
            action_index,
            proof,
        } => Some((
            OperationKind::Renew,
            predecessor,
            state,
            state_commitment,
            state_nullifier,
            *action_index,
            proof,
        )),
        V1Operation::Release {
            predecessor,
            state,
            state_commitment,
            state_nullifier,
            action_index,
            proof,
        } => Some((
            OperationKind::Release,
            predecessor,
            state,
            state_commitment,
            state_nullifier,
            *action_index,
            proof,
        )),
        V1Operation::Commit { .. } | V1Operation::Reveal { .. } => None,
    }
}

#[cfg(test)]
#[path = "tests/machine.rs"]
mod tests;
