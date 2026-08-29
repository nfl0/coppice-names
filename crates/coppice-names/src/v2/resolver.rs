//! Fresh Names v2 resolution from ordinary canonical block acquisition.

use super::{
    lease::{Lifecycle, V2Parameters},
    machine::ResolutionStatus,
    operation::{CanonicalBlock, CanonicalTransaction, ChainTip, OperationKind, V2Operation},
    registration::{CommitRef, RegistrationIntent},
    schedule,
    state::{NameId, NameState, StateData, StateRef, StateStatus},
    transition::{GenesisStatement, TransitionStatement, V2StateProofVerifier},
};
use std::collections::{BTreeMap, BTreeSet};

/// The ordinary canonical acquisition surface required by a fresh resolver.
pub trait CanonicalSource {
    /// Returns the source’s current canonical tip.
    fn tip(&self) -> ChainTip;
    /// Returns one canonical block body by height, as ordinary RPC acquisition would.
    fn block(&self, height: u32) -> Option<CanonicalBlock>;
}

impl CanonicalSource for BTreeMap<u32, CanonicalBlock> {
    fn tip(&self) -> ChainTip {
        self.iter()
            .next_back()
            .map(|(_, block)| block.tip())
            .unwrap_or(ChainTip {
                height: 0,
                block_hash: [0; 32],
            })
    }

    fn block(&self, height: u32) -> Option<CanonicalBlock> {
        self.get(&height).cloned()
    }
}

/// Errors that mean a discovered operation cannot authenticate a Names lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The input name is not canonical.
    InvalidName,
    /// The experimental parameters are invalid.
    InvalidParameters,
    /// A canonical block or transaction required by resolution is absent,
    /// malformed, or internally inconsistent. This is fatal source/history
    /// corruption, never an untrusted-claim rejection.
    InvalidLineage,
    /// A producer operation does not satisfy its deterministic state policy,
    /// including an operation-provided predecessor/replacement reference that
    /// does not authenticate to an accepted Names producer. Only the
    /// containing operation is unaccepted.
    InvalidOperation,
    /// A checked height relation overflowed.
    ArithmeticOverflow,
}

/// Acquisition and verification counts returned with one fresh lookup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolutionStats {
    /// Candidate scheduled block bodies probed for REVEAL/RENEW anchors.
    pub candidate_block_probes: u32,
    /// Blocks after the selected anchor scanned for arbitrary-height updates.
    pub tail_blocks_scanned: u32,
    /// Producer blocks fetched while following this name’s predecessor chain.
    pub lineage_block_probes: u32,
    /// Number of predecessor state references authenticated.
    pub predecessor_chain_steps: u32,
}

/// Result of a fresh lookup, including explicit inactive/missing status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolutionResult {
    /// Active, grace, released, expired, or missing.
    pub status: ResolutionStatus,
    /// The latest state, including non-payable terminal/expired state when known.
    pub state: Option<NameState>,
    /// The latest authenticated REVEAL/RENEW anchor.
    pub anchor: Option<StateRef>,
    /// Acquisition and lineage work performed.
    pub stats: ResolutionStats,
}

/// Fresh resolver for the experimental v2 schedule and lineage.
#[derive(Clone, Copy, Debug)]
pub struct FreshResolver {
    params: V2Parameters,
}

impl FreshResolver {
    /// Constructs a resolver after validating schedule and lease parameters.
    pub fn new(params: V2Parameters) -> Result<Self, ResolveError> {
        params
            .validate()
            .map_err(|_| ResolveError::InvalidParameters)?;
        Ok(Self { params })
    }

    /// Returns the parameters used by this resolver.
    pub const fn params(&self) -> V2Parameters {
        self.params
    }

    /// Resolves a canonical name from only the canonical tip and block bodies.
    pub fn resolve<S, P>(
        self,
        name: &str,
        source: &S,
        proofs: &P,
    ) -> Result<ResolutionResult, ResolveError>
    where
        S: CanonicalSource,
        P: V2StateProofVerifier,
    {
        let name_id = super::state::name_id(name).map_err(|_| ResolveError::InvalidName)?;
        let tip = source.tip();
        if tip.height >= self.params.activation_height {
            let tip_block = source
                .block(tip.height)
                .ok_or(ResolveError::InvalidLineage)?;
            validate_block_shape(&tip_block, tip.height)?;
            if tip_block.block_hash != tip.block_hash {
                return Err(ResolveError::InvalidLineage);
            }
        }
        let mut auth = Authenticator {
            params: self.params,
            source,
            proofs,
            stats: ResolutionStats::default(),
            cache: BTreeMap::new(),
            visiting: BTreeSet::new(),
        };
        let fresh_lower = tip
            .height
            .saturating_sub(
                self.params
                    .max_anchor_age()
                    .map_err(|_| ResolveError::InvalidParameters)?,
            )
            .max(self.params.activation_height);
        let mut replay = auth.replay_name_window(name_id, fresh_lower, tip.height)?;
        if replay.anchor.is_none() {
            let reset_lower = tip
                .height
                .saturating_sub(
                    self.params
                        .reset_horizon()
                        .map_err(|_| ResolveError::InvalidParameters)?,
                )
                .max(self.params.activation_height);
            replay = auth.replay_name_window(name_id, reset_lower, tip.height)?;
        }
        let Some(state) = replay.state else {
            return Ok(ResolutionResult {
                status: ResolutionStatus::Missing,
                state: None,
                anchor: None,
                stats: auth.stats,
            });
        };

        let status = if let Some(abandoned) = state.abandoned_height {
            if self
                .params
                .head_claimable_from(&state.data, Some(abandoned))
                .is_some_and(|claimable| tip.height >= claimable)
            {
                ResolutionStatus::Expired
            } else {
                ResolutionStatus::Abandoned
            }
        } else {
            match self.params.lifecycle(&state.data, tip.height) {
                Lifecycle::Active => ResolutionStatus::Active,
                Lifecycle::Stale => ResolutionStatus::Stale,
                Lifecycle::Grace => ResolutionStatus::Grace,
                Lifecycle::Released => ResolutionStatus::Released,
                Lifecycle::Claimable => ResolutionStatus::Expired,
            }
        };
        Ok(ResolutionResult {
            status,
            state: Some(state),
            anchor: replay.anchor,
            stats: auth.stats,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct NameWindowReplay {
    state: Option<NameState>,
    anchor: Option<StateRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MessagePosition {
    height: u32,
    tx_index: u32,
    operation_index: u32,
}

struct Authenticator<'a, S, P> {
    params: V2Parameters,
    source: &'a S,
    proofs: &'a P,
    stats: ResolutionStats,
    cache: BTreeMap<StateRef, NameState>,
    visiting: BTreeSet<StateRef>,
}

/// Outcome of authenticating an operation-provided canonical reference claim.
///
/// The distinction keeps untrusted-claim failures nonfatal: they make only
/// the containing operation unaccepted. Canonical source/history integrity
/// failures reached while authenticating remain fatal `ResolveError`s.
enum ClaimAuthentication<T> {
    /// The claim authenticates to the exact accepted producer it identifies.
    Authenticated(T),
    /// The claim does not authenticate to an accepted Names producer.
    Unauthenticated,
}

impl<'a, S, P> Authenticator<'a, S, P>
where
    S: CanonicalSource,
    P: V2StateProofVerifier,
{
    /// Replays only this name's visible operations in canonical block,
    /// transaction, and carrier-message order. A rejected Names message is
    /// skipped; absent or structurally inconsistent canonical block data is
    /// still fatal.
    fn replay_name_window(
        &mut self,
        name_id: NameId,
        start_height: u32,
        tip_height: u32,
    ) -> Result<NameWindowReplay, ResolveError> {
        self.replay_name_range(
            name_id,
            start_height,
            MessagePosition {
                height: tip_height,
                tx_index: u32::MAX,
                operation_index: u32::MAX,
            },
        )
    }

    fn replay_name_range(
        &mut self,
        name_id: NameId,
        start_height: u32,
        end: MessagePosition,
    ) -> Result<NameWindowReplay, ResolveError> {
        let mut replay = NameWindowReplay::default();
        let mut previous_hash = None;
        for height in start_height..=end.height {
            let block = self
                .source
                .block(height)
                .ok_or(ResolveError::InvalidLineage)?;
            validate_block_shape(&block, height)?;
            if previous_hash.is_some_and(|hash| block.prev_block_hash != hash) {
                return Err(ResolveError::InvalidLineage);
            }
            previous_hash = Some(block.block_hash);
            if schedule::is_anchor_height(name_id, height, self.params) {
                self.stats.candidate_block_probes = self
                    .stats
                    .candidate_block_probes
                    .checked_add(1)
                    .ok_or(ResolveError::ArithmeticOverflow)?;
            }
            if height > start_height {
                self.stats.tail_blocks_scanned = self
                    .stats
                    .tail_blocks_scanned
                    .checked_add(1)
                    .ok_or(ResolveError::ArithmeticOverflow)?;
            }
            for transaction in &block.transactions {
                for (operation_index, operation) in transaction.operations.iter().enumerate() {
                    let position = MessagePosition {
                        height,
                        tx_index: transaction.tx_index,
                        operation_index: operation_index as u32,
                    };
                    if position > end {
                        continue;
                    }
                    if operation.name_id() != Some(name_id) {
                        continue;
                    }
                    if !transaction.is_first_action_claim(operation_index) {
                        continue;
                    }
                    let candidate = match operation {
                        V2Operation::Commit { .. } => continue,
                        V2Operation::Reveal { .. } => {
                            self.authenticate_reveal(&block, transaction, operation)
                        }
                        V2Operation::Update { .. }
                        | V2Operation::Renew { .. }
                        | V2Operation::Release { .. } => {
                            self.authenticate_transition(&block, transaction, operation)
                        }
                    };
                    let successor = match candidate {
                        Ok(successor) => successor,
                        Err(ResolveError::InvalidOperation | ResolveError::InvalidName) => {
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    let accepted = match operation {
                        V2Operation::Reveal {
                            replacement_predecessor,
                            commit,
                            ..
                        } => match &replay.state {
                            Some(current) => {
                                let claimable = self
                                    .params
                                    .head_claimable_from(&current.data, current.abandoned_height)
                                    .ok_or(ResolveError::ArithmeticOverflow)?;
                                replacement_predecessor == &Some(current.state_ref)
                                    && block.height >= claimable
                                    && commit.position.height >= claimable
                            }
                            None => replacement_predecessor.is_none(),
                        },
                        V2Operation::Update { predecessor, .. }
                        | V2Operation::Renew { predecessor, .. }
                        | V2Operation::Release { predecessor, .. } => match replay.state.as_ref() {
                            Some(current) => {
                                current.abandoned_height.is_none()
                                    && current.state_ref == *predecessor
                            }
                            // `authenticate_transition` has already established that this
                            // predecessor is an accepted Names producer. This bounded replay
                            // may start after that producer, but must never bootstrap from a
                            // merely proof-valid Ironwood note.
                            None => true,
                        },
                        V2Operation::Commit { .. } => false,
                    };
                    if !accepted {
                        continue;
                    }
                    if matches!(
                        operation,
                        V2Operation::Reveal { .. } | V2Operation::Renew { .. }
                    ) {
                        replay.anchor = Some(successor.state_ref);
                    }
                    replay.state = Some(successor);
                }
                if let Some(current) = replay.state.as_mut()
                    && current.abandoned_height.is_none()
                    && current.data.status == StateStatus::Active
                    && self.params.lifecycle(&current.data, height) != Lifecycle::Claimable
                    && transaction
                        .actions
                        .iter()
                        .any(|action| action.nullifier == current.state_ref.nullifier)
                {
                    current.abandon(height);
                }
            }
        }
        Ok(replay)
    }

    /// Authenticates a producer as an accepted Names state head at its exact
    /// canonical carrier-message position. Proof validity alone is never a
    /// substitute for this replay check.
    ///
    /// Failures attributable to the untrusted claim itself are reported as
    /// [`ClaimAuthentication::Unauthenticated`]. Canonical source/history
    /// integrity failures reached while authenticating — absent blocks inside
    /// the required canonical range, malformed shapes, or broken chain
    /// linkage encountered during the recursive replay — propagate as fatal
    /// `ResolveError`s.
    fn authenticate_accepted_state_ref(
        &mut self,
        reference: StateRef,
    ) -> Result<ClaimAuthentication<Box<NameState>>, ResolveError> {
        if let Some(state) = self.cache.get(&reference) {
            return Ok(ClaimAuthentication::Authenticated(Box::new(state.clone())));
        }
        if !self.visiting.insert(reference) {
            // Circular ancestry is constructible only by the untrusted claims
            // themselves; canonical acceptance never depends on a later
            // producer.
            return Ok(ClaimAuthentication::Unauthenticated);
        }
        self.stats.lineage_block_probes = self
            .stats
            .lineage_block_probes
            .checked_add(1)
            .ok_or(ResolveError::ArithmeticOverflow)?;
        let result = (|| -> Result<ClaimAuthentication<Box<NameState>>, ResolveError> {
            let tip = self.source.tip();
            if reference.producer_height < self.params.activation_height
                || reference.producer_height > tip.height
            {
                // No accepted Names producer can exist outside the canonical
                // source range, so the claim fails on its face.
                return Ok(ClaimAuthentication::Unauthenticated);
            }
            // Inside the canonical range a complete source must carry every
            // block; a missing block is source corruption, not a claim
            // failure.
            let block = self
                .source
                .block(reference.producer_height)
                .ok_or(ResolveError::InvalidLineage)?;
            validate_block_shape(&block, reference.producer_height)?;
            let Some(transaction) =
                exact_transaction(&block, reference.producer_tx_index, reference.producer_txid)
            else {
                return Ok(ClaimAuthentication::Unauthenticated);
            };
            let Some(action) = transaction.action(reference.producer_action_index) else {
                return Ok(ClaimAuthentication::Unauthenticated);
            };
            if action.commitment != reference.commitment {
                return Ok(ClaimAuthentication::Unauthenticated);
            }
            let Some(operation) = transaction
                .operations
                .get(reference.producer_operation_index as usize)
            else {
                return Ok(ClaimAuthentication::Unauthenticated);
            };
            if !transaction.is_first_action_claim(reference.producer_operation_index as usize)
                || operation.action_index() != Some(reference.producer_action_index)
                || operation.state_commitment() != Some(reference.commitment)
                || operation.state_nullifier() != Some(reference.nullifier)
            {
                return Ok(ClaimAuthentication::Unauthenticated);
            }
            let Some(name_id) = operation.name_id() else {
                return Ok(ClaimAuthentication::Unauthenticated);
            };
            let state = self.replay_name_through(
                name_id,
                MessagePosition {
                    height: reference.producer_height,
                    tx_index: reference.producer_tx_index,
                    operation_index: reference.producer_operation_index,
                },
            )?;
            match state {
                Some(state) if state.state_ref == reference => {
                    Ok(ClaimAuthentication::Authenticated(Box::new(state)))
                }
                _ => Ok(ClaimAuthentication::Unauthenticated),
            }
        })();
        self.visiting.remove(&reference);
        if let Ok(ClaimAuthentication::Authenticated(state)) = &result {
            self.cache.insert(reference, state.as_ref().clone());
        }
        result
    }

    fn replay_name_through(
        &mut self,
        name_id: NameId,
        end: MessagePosition,
    ) -> Result<Option<NameState>, ResolveError> {
        let lower = end
            .height
            .saturating_sub(
                self.params
                    .reset_horizon()
                    .map_err(|_| ResolveError::InvalidParameters)?,
            )
            .max(self.params.activation_height);
        Ok(self.replay_name_range(name_id, lower, end)?.state)
    }

    fn authenticate_reveal(
        &mut self,
        block: &CanonicalBlock,
        transaction: &CanonicalTransaction,
        operation: &V2Operation,
    ) -> Result<NameState, ResolveError> {
        let V2Operation::Reveal {
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
            return Err(ResolveError::InvalidOperation);
        };
        validate_intent(intent)?;
        let name_id = intent.name_id().map_err(|_| ResolveError::InvalidName)?;
        // Representation and configured record bounds are canonical statement
        // preprocessing. Genesis formation itself is enforced by the proof.
        self.params
            .validate_state(state)
            .map_err(|_| ResolveError::InvalidOperation)?;
        if intent
            .commitment()
            .map_err(|_| ResolveError::InvalidOperation)?
            != commit.commitment
        {
            return Err(ResolveError::InvalidOperation);
        }
        let current_operation_index = operation_index(transaction, operation)?;
        if commit.position.height >= block.height {
            return Err(ResolveError::InvalidOperation);
        }
        match self.authenticate_accepted_commit(*commit)? {
            ClaimAuthentication::Authenticated(()) => {}
            ClaimAuthentication::Unauthenticated => {
                return Err(ResolveError::InvalidOperation);
            }
        }
        let maturity = commit
            .position
            .height
            .checked_add(1)
            .ok_or(ResolveError::InvalidOperation)?;
        let expiry = commit
            .position
            .height
            .checked_add(self.params.commit_ttl_blocks)
            .ok_or(ResolveError::InvalidOperation)?;
        if block.height < maturity || block.height > expiry {
            return Err(ResolveError::InvalidOperation);
        }
        if let Some(previous_ref) = replacement_predecessor {
            if !state_ref_precedes(
                *previous_ref,
                MessagePosition {
                    height: block.height,
                    tx_index: transaction.tx_index,
                    operation_index: current_operation_index,
                },
            ) {
                return Err(ResolveError::InvalidOperation);
            }
            let mut previous = match self.authenticate_accepted_state_ref(*previous_ref)? {
                ClaimAuthentication::Authenticated(previous) => previous,
                ClaimAuthentication::Unauthenticated => {
                    return Err(ResolveError::InvalidOperation);
                }
            };
            if let Some(height) = self.find_nullifier_spend_height(
                previous.state_ref.nullifier,
                previous.state_ref.producer_height,
                block.height,
            )? && previous.data.status == StateStatus::Active
                && self.params.lifecycle(&previous.data, height) != Lifecycle::Claimable
            {
                previous.abandon(height);
            }
            let claimable = self
                .params
                .head_claimable_from(&previous.data, previous.abandoned_height)
                .ok_or(ResolveError::ArithmeticOverflow)?;
            if previous.data.name_id != name_id
                || block.height < claimable
                || commit.position.height < claimable
            {
                return Err(ResolveError::InvalidOperation);
            }
        } else if !self.no_predecessor_reset_eligible(name_id, commit.position.height)? {
            return Err(ResolveError::InvalidOperation);
        }
        let action = transaction
            .action(*action_index)
            .ok_or(ResolveError::InvalidOperation)?;
        if action.commitment != *state_commitment {
            return Err(ResolveError::InvalidOperation);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            *action_index,
            current_operation_index,
            *state_commitment,
            *state_nullifier,
        );
        let name_state = NameState::new(state.clone(), *state_commitment, state_ref)
            .map_err(|_| ResolveError::InvalidOperation)?;
        let statement =
            GenesisStatement::from_reveal(intent, &name_state, action, block.height, self.params)
                .map_err(|_| ResolveError::InvalidOperation)?;
        if !self.proofs.verify_genesis(&statement, proof) {
            return Err(ResolveError::InvalidOperation);
        }
        Ok(name_state)
    }

    fn find_nullifier_spend_height(
        &self,
        nullifier: [u8; 32],
        start_height: u32,
        end_height: u32,
    ) -> Result<Option<u32>, ResolveError> {
        let mut previous_hash = None;
        for height in start_height..=end_height {
            let block = self
                .source
                .block(height)
                .ok_or(ResolveError::InvalidLineage)?;
            validate_block_shape(&block, height)?;
            if previous_hash.is_some_and(|hash| block.prev_block_hash != hash) {
                return Err(ResolveError::InvalidLineage);
            }
            previous_hash = Some(block.block_hash);
            if block.transactions.iter().any(|transaction| {
                transaction
                    .actions
                    .iter()
                    .any(|action| action.nullifier == nullifier)
            }) {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    /// Verifies that `commit` names the exact message which was admitted to
    /// the finite pending-COMMIT set. Seeing the same bytes elsewhere in the
    /// transaction is deliberately insufficient.
    fn authenticate_accepted_commit(
        &mut self,
        commit: CommitRef,
    ) -> Result<ClaimAuthentication<()>, ResolveError> {
        let tip = self.source.tip();
        if commit.position.height < self.params.activation_height
            || commit.position.height > tip.height
        {
            return Ok(ClaimAuthentication::Unauthenticated);
        }
        let exact_block = self
            .source
            .block(commit.position.height)
            .ok_or(ResolveError::InvalidLineage)?;
        validate_block_shape(&exact_block, commit.position.height)?;
        let Some(exact_transaction) =
            exact_transaction(&exact_block, commit.position.tx_index, commit.position.txid)
        else {
            return Ok(ClaimAuthentication::Unauthenticated);
        };
        if !matches!(
            exact_transaction.operations.get(commit.operation_index as usize),
            Some(V2Operation::Commit { commitment }) if *commitment == commit.commitment
        ) {
            return Ok(ClaimAuthentication::Unauthenticated);
        }
        let lower = commit
            .position
            .height
            .saturating_sub(self.params.commit_ttl_blocks)
            .max(self.params.activation_height);
        let mut pending = BTreeMap::<[u8; 32], CommitRef>::new();
        let mut previous_hash = None;
        for height in lower..=commit.position.height {
            let block = self
                .source
                .block(height)
                .ok_or(ResolveError::InvalidLineage)?;
            validate_block_shape(&block, height)?;
            if previous_hash.is_some_and(|hash| block.prev_block_hash != hash) {
                return Err(ResolveError::InvalidLineage);
            }
            previous_hash = Some(block.block_hash);
            for transaction in &block.transactions {
                for (operation_index, operation) in transaction.operations.iter().enumerate() {
                    let position = MessagePosition {
                        height,
                        tx_index: transaction.tx_index,
                        operation_index: operation_index as u32,
                    };
                    let target = position
                        == MessagePosition {
                            height: commit.position.height,
                            tx_index: commit.position.tx_index,
                            operation_index: commit.operation_index,
                        };
                    match operation {
                        V2Operation::Commit { commitment } => {
                            let candidate = CommitRef::new(
                                transaction.position(height),
                                operation_index as u32,
                                *commitment,
                            );
                            let accepted = !pending.contains_key(commitment);
                            if accepted {
                                pending.insert(*commitment, candidate);
                            }
                            if target {
                                return if candidate == commit && accepted {
                                    Ok(ClaimAuthentication::Authenticated(()))
                                } else {
                                    Ok(ClaimAuthentication::Unauthenticated)
                                };
                            }
                        }
                        V2Operation::Reveal {
                            commit: consumed, ..
                        } if pending.contains_key(&consumed.commitment) => {
                            if self.state_operation_is_accepted(&block, transaction, operation)? {
                                pending.remove(&consumed.commitment);
                            }
                        }
                        _ => {
                            if target {
                                return Ok(ClaimAuthentication::Unauthenticated);
                            }
                        }
                    }
                }
            }
            pending.retain(|_, pending_commit| {
                pending_commit
                    .position
                    .height
                    .checked_add(self.params.commit_ttl_blocks)
                    .is_some_and(|expiry| expiry > height)
            });
        }
        Ok(ClaimAuthentication::Unauthenticated)
    }

    fn state_operation_is_accepted(
        &mut self,
        block: &CanonicalBlock,
        transaction: &CanonicalTransaction,
        operation: &V2Operation,
    ) -> Result<bool, ResolveError> {
        let Some(action_index) = operation.action_index() else {
            return Ok(false);
        };
        let Some(commitment) = operation.state_commitment() else {
            return Ok(false);
        };
        let Some(nullifier) = operation.state_nullifier() else {
            return Ok(false);
        };
        let Ok(index) = operation_index(transaction, operation) else {
            return Err(ResolveError::InvalidLineage);
        };
        match self.authenticate_accepted_state_ref(StateRef::new(
            transaction.position(block.height),
            action_index,
            index,
            commitment,
            nullifier,
        ))? {
            ClaimAuthentication::Authenticated(_) => Ok(true),
            ClaimAuthentication::Unauthenticated => Ok(false),
        }
    }

    /// Authenticates the bounded no-predecessor COMMIT rule at the COMMIT
    /// height. The range begins at activation when there is not yet a full
    /// reset horizon of v2 history; no trusted snapshot is involved.
    fn no_predecessor_reset_eligible(
        &mut self,
        name_id: NameId,
        commit_height: u32,
    ) -> Result<bool, ResolveError> {
        let horizon = self
            .params
            .reset_horizon()
            .map_err(|_| ResolveError::InvalidParameters)?;
        let candidates = schedule::candidate_anchor_heights_with_age(
            name_id,
            commit_height,
            self.params,
            horizon,
        );
        let harmless_at_or_before = commit_height.saturating_sub(horizon);
        for height in candidates {
            if height < self.params.activation_height || height <= harmless_at_or_before {
                continue;
            }
            self.stats.candidate_block_probes = self
                .stats
                .candidate_block_probes
                .checked_add(1)
                .ok_or(ResolveError::ArithmeticOverflow)?;
            let block = self
                .source
                .block(height)
                .ok_or(ResolveError::InvalidLineage)?;
            validate_block_shape(&block, height)?;
            for transaction in &block.transactions {
                for operation in &transaction.operations {
                    if operation.name_id() != Some(name_id)
                        || !matches!(
                            operation,
                            V2Operation::Reveal { .. } | V2Operation::Renew { .. }
                        )
                    {
                        continue;
                    }
                    let valid = self.state_operation_is_accepted(&block, transaction, operation)?;
                    if valid {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    fn authenticate_transition(
        &mut self,
        block: &CanonicalBlock,
        transaction: &CanonicalTransaction,
        operation: &V2Operation,
    ) -> Result<NameState, ResolveError> {
        self.stats.predecessor_chain_steps = self
            .stats
            .predecessor_chain_steps
            .checked_add(1)
            .ok_or(ResolveError::ArithmeticOverflow)?;
        let Some((
            kind,
            predecessor_ref,
            state,
            state_commitment,
            state_nullifier,
            action_index,
            proof,
        )) = transition_parts(operation)
        else {
            return Err(ResolveError::InvalidOperation);
        };
        let current_operation_index = operation_index(transaction, operation)?;
        if !state_ref_precedes(
            *predecessor_ref,
            MessagePosition {
                height: block.height,
                tx_index: transaction.tx_index,
                operation_index: current_operation_index,
            },
        ) {
            return Err(ResolveError::InvalidOperation);
        }
        // A predecessor claim that does not authenticate to an accepted Names
        // producer makes this operation unaccepted, exactly as replay treats
        // it; it never poisons resolution of the name itself. Structural
        // source/history failures propagate and remain fatal.
        let predecessor = match self.authenticate_accepted_state_ref(*predecessor_ref)? {
            ClaimAuthentication::Authenticated(predecessor) => predecessor,
            ClaimAuthentication::Unauthenticated => return Err(ResolveError::InvalidOperation),
        };
        if predecessor.state_ref != *predecessor_ref || predecessor.abandoned_height.is_some() {
            return Err(ResolveError::InvalidOperation);
        }
        // Representation and configured record bounds are canonical statement
        // preprocessing. Local transition legality is enforced by the proof.
        self.params
            .validate_state(state)
            .map_err(|_| ResolveError::InvalidOperation)?;
        let action = transaction
            .action(action_index)
            .ok_or(ResolveError::InvalidOperation)?;
        if action.nullifier != predecessor.state_ref.nullifier {
            return Err(ResolveError::InvalidOperation);
        }
        if action.commitment != *state_commitment {
            return Err(ResolveError::InvalidOperation);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            action_index,
            current_operation_index,
            *state_commitment,
            *state_nullifier,
        );
        let successor = NameState::new(state.clone(), *state_commitment, state_ref)
            .map_err(|_| ResolveError::InvalidOperation)?;
        let statement = TransitionStatement::from_states(
            &predecessor,
            &successor,
            action,
            kind,
            block.height,
            self.params,
        )
        .map_err(|_| ResolveError::InvalidOperation)?;
        if !self.proofs.verify_transition(&statement, proof) {
            return Err(ResolveError::InvalidOperation);
        }
        Ok(successor)
    }
}

fn validate_intent(intent: &RegistrationIntent) -> Result<(), ResolveError> {
    intent
        .name_id()
        .map(|_| ())
        .map_err(|_| ResolveError::InvalidName)
}

fn exact_transaction(
    block: &CanonicalBlock,
    tx_index: u32,
    txid: [u8; 32],
) -> Option<&CanonicalTransaction> {
    block
        .transactions
        .iter()
        .find(|transaction| transaction.tx_index == tx_index && transaction.txid == txid)
}

fn state_ref_precedes(reference: StateRef, consumer: MessagePosition) -> bool {
    MessagePosition {
        height: reference.producer_height,
        tx_index: reference.producer_tx_index,
        operation_index: reference.producer_operation_index,
    } < consumer
}

fn validate_block_shape(block: &CanonicalBlock, expected_height: u32) -> Result<(), ResolveError> {
    if block.height != expected_height
        || block
            .transactions
            .windows(2)
            .any(|pair| pair[0].tx_index >= pair[1].tx_index)
        || block.transactions.iter().any(|transaction| {
            transaction
                .actions
                .iter()
                .enumerate()
                .any(|(index, action)| action.action_index != index as u32)
                || !transaction.has_canonical_operation_order()
        })
    {
        Err(ResolveError::InvalidLineage)
    } else {
        Ok(())
    }
}

fn operation_index(
    transaction: &CanonicalTransaction,
    operation: &V2Operation,
) -> Result<u32, ResolveError> {
    transaction
        .operations
        .iter()
        .position(|candidate| core::ptr::eq(candidate, operation))
        .and_then(|index| u32::try_from(index).ok())
        .ok_or(ResolveError::InvalidLineage)
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

fn transition_parts(operation: &V2Operation) -> TransitionParts<'_> {
    match operation {
        V2Operation::Update {
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
        V2Operation::Renew {
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
        V2Operation::Release {
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
        V2Operation::Commit { .. } | V2Operation::Reveal { .. } => None,
    }
}
