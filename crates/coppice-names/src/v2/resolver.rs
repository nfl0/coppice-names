//! Fresh Names v2 resolution from ordinary canonical block acquisition.

use super::{
    lease::{Lifecycle, V2Parameters},
    machine::ResolutionStatus,
    operation::{CanonicalBlock, CanonicalTransaction, ChainTip, OperationKind, V2Operation},
    registration::{BondProofVerifier, RegistrationIntent},
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
    /// A canonical block or transaction referenced by an operation is absent or mismatched.
    InvalidLineage,
    /// A producer operation does not satisfy its deterministic state policy.
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
    pub fn resolve<S, P, B>(
        self,
        name: &str,
        source: &S,
        proofs: &P,
        bonds: &B,
    ) -> Result<ResolutionResult, ResolveError>
    where
        S: CanonicalSource,
        P: V2StateProofVerifier,
        B: BondProofVerifier,
    {
        let name_id = super::state::name_id(name).map_err(|_| ResolveError::InvalidName)?;
        let tip = source.tip();
        let mut auth = Authenticator {
            params: self.params,
            source,
            proofs,
            bonds,
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

        let status = match self.params.lifecycle(&state.data, tip.height) {
            Lifecycle::Active => ResolutionStatus::Active,
            Lifecycle::Stale => ResolutionStatus::Stale,
            Lifecycle::Grace => ResolutionStatus::Grace,
            Lifecycle::Released => ResolutionStatus::Released,
            Lifecycle::Claimable => ResolutionStatus::Expired,
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

struct Authenticator<'a, S, P, B> {
    params: V2Parameters,
    source: &'a S,
    proofs: &'a P,
    bonds: &'a B,
    stats: ResolutionStats,
    cache: BTreeMap<StateRef, NameState>,
    visiting: BTreeSet<StateRef>,
}

impl<'a, S, P, B> Authenticator<'a, S, P, B>
where
    S: CanonicalSource,
    P: V2StateProofVerifier,
    B: BondProofVerifier,
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
        let mut replay = NameWindowReplay::default();
        let mut previous_hash = None;
        for height in start_height..=tip_height {
            let block = self
                .source
                .block(height)
                .ok_or(ResolveError::InvalidLineage)?;
            if block.height != height
                || previous_hash.is_some_and(|hash| block.prev_block_hash != hash)
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
                for operation in &transaction.operations {
                    if operation.name_id() != Some(name_id) {
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
                    let Ok(successor) = candidate else {
                        continue;
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
                                    .claimable_from(
                                        current.data.status,
                                        current.data.lease_expiry,
                                        current.data.terminal_height,
                                    )
                                    .ok_or(ResolveError::ArithmeticOverflow)?;
                                replacement_predecessor == &Some(current.state_ref)
                                    && block.height >= claimable
                                    && commit.position.height >= claimable
                            }
                            None => replacement_predecessor.is_none(),
                        },
                        V2Operation::Update { predecessor, .. }
                        | V2Operation::Renew { predecessor, .. }
                        | V2Operation::Release { predecessor, .. } => replay
                            .state
                            .as_ref()
                            .map(|current| current.state_ref == *predecessor)
                            .unwrap_or(true),
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
            }
        }
        Ok(replay)
    }

    fn authenticate_state_ref(&mut self, reference: StateRef) -> Result<NameState, ResolveError> {
        if let Some(state) = self.cache.get(&reference) {
            return Ok(state.clone());
        }
        if !self.visiting.insert(reference) {
            return Err(ResolveError::InvalidLineage);
        }
        self.stats.lineage_block_probes = self
            .stats
            .lineage_block_probes
            .checked_add(1)
            .ok_or(ResolveError::ArithmeticOverflow)?;
        let result = (|| {
            let block = self
                .source
                .block(reference.producer_height)
                .ok_or(ResolveError::InvalidLineage)?;
            let transaction =
                exact_transaction(&block, reference.producer_tx_index, reference.producer_txid)
                    .ok_or(ResolveError::InvalidLineage)?;
            let action = transaction
                .action(reference.producer_action_index)
                .ok_or(ResolveError::InvalidLineage)?;
            if action.commitment != reference.commitment {
                return Err(ResolveError::InvalidLineage);
            }
            let operation = transaction
                .operations
                .iter()
                .find(|operation| {
                    operation.action_index() == Some(reference.producer_action_index)
                        && operation.state_commitment() == Some(reference.commitment)
                })
                .ok_or(ResolveError::InvalidLineage)?;
            match operation {
                V2Operation::Reveal { .. } => {
                    self.authenticate_reveal(&block, transaction, operation)
                }
                V2Operation::Update { .. }
                | V2Operation::Renew { .. }
                | V2Operation::Release { .. } => {
                    self.authenticate_transition(&block, transaction, operation)
                }
                V2Operation::Commit { .. } => Err(ResolveError::InvalidLineage),
            }
        })();
        self.visiting.remove(&reference);
        if let Ok(state) = &result {
            if state.state_ref != reference {
                return Err(ResolveError::InvalidLineage);
            }
            self.cache.insert(reference, state.clone());
        }
        result
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
            action_index,
            bond,
            proof,
        } = operation
        else {
            return Err(ResolveError::InvalidOperation);
        };
        validate_intent(intent)?;
        let name_id = intent.name_id().map_err(|_| ResolveError::InvalidName)?;
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
                    .ok_or(ResolveError::ArithmeticOverflow)?
        {
            return Err(ResolveError::InvalidOperation);
        }
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
        let commit_block = self
            .source
            .block(commit.position.height)
            .ok_or(ResolveError::InvalidLineage)?;
        let commit_transaction = exact_transaction(
            &commit_block,
            commit.position.tx_index,
            commit.position.txid,
        )
        .ok_or(ResolveError::InvalidLineage)?;
        if !commit_transaction.operations.iter().any(|candidate| {
            matches!(candidate, V2Operation::Commit { commitment } if *commitment == commit.commitment)
        }) {
            return Err(ResolveError::InvalidLineage);
        }
        let maturity = commit
            .position
            .height
            .checked_add(1)
            .ok_or(ResolveError::ArithmeticOverflow)?;
        let expiry = commit
            .position
            .height
            .checked_add(self.params.commit_ttl_blocks)
            .ok_or(ResolveError::ArithmeticOverflow)?;
        if block.height == commit.position.height {
            return Err(ResolveError::InvalidOperation);
        }
        if block.height < maturity || block.height > expiry {
            return Err(ResolveError::InvalidOperation);
        }
        if !schedule::is_anchor_height(name_id, block.height, self.params) {
            return Err(ResolveError::InvalidOperation);
        }
        if bond.bond_tag != intent.bond_tag || !self.bonds.verify(intent, bond) {
            return Err(ResolveError::InvalidOperation);
        }
        if let Some(previous_ref) = replacement_predecessor {
            let previous = self.authenticate_state_ref(*previous_ref)?;
            let claimable = self
                .params
                .claimable_from(
                    previous.data.status,
                    previous.data.lease_expiry,
                    previous.data.terminal_height,
                )
                .ok_or(ResolveError::ArithmeticOverflow)?;
            if previous.data.name_id != name_id
                || self.params.lifecycle(&previous.data, block.height) != Lifecycle::Claimable
                || commit.position.height < claimable
            {
                return Err(ResolveError::InvalidOperation);
            }
        } else if !self.no_predecessor_reset_eligible(name_id, commit.position.height)? {
            return Err(ResolveError::InvalidOperation);
        }
        let action = transaction
            .action(*action_index)
            .ok_or(ResolveError::InvalidLineage)?;
        if action.commitment != *state_commitment {
            return Err(ResolveError::InvalidLineage);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            *action_index,
            *state_commitment,
        );
        let name_state = NameState::new(state.clone(), *state_commitment, state_ref)
            .map_err(|_| ResolveError::InvalidOperation)?;
        let statement = GenesisStatement::from_state(&name_state, action)
            .map_err(|_| ResolveError::InvalidOperation)?;
        if !self.proofs.verify_genesis(&statement, proof) {
            return Err(ResolveError::InvalidOperation);
        }
        Ok(name_state)
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
                    let valid = match operation {
                        V2Operation::Reveal { .. } => self
                            .authenticate_reveal(&block, transaction, operation)
                            .is_ok(),
                        V2Operation::Renew { .. } => self
                            .authenticate_transition(&block, transaction, operation)
                            .is_ok(),
                        _ => false,
                    };
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
        let Some((kind, predecessor_ref, state, state_commitment, action_index, proof)) =
            transition_parts(operation)
        else {
            return Err(ResolveError::InvalidOperation);
        };
        let predecessor = self.authenticate_state_ref(*predecessor_ref)?;
        if predecessor.data.name_id != state.name_id
            || predecessor.data.owner_pk != state.owner_pk
            || predecessor.state_ref != *predecessor_ref
            || predecessor.data.status != StateStatus::Active
            || block.height >= predecessor.data.lease_expiry
        {
            return Err(ResolveError::InvalidOperation);
        }
        let expected_sequence = predecessor
            .data
            .sequence
            .checked_add(1)
            .ok_or(ResolveError::InvalidOperation)?;
        if state.sequence != expected_sequence {
            return Err(ResolveError::InvalidOperation);
        }
        match kind {
            OperationKind::Update => {
                if state.status != StateStatus::Active
                    || state.terminal_height != 0
                    || state.lease_expiry != predecessor.data.lease_expiry
                    || state.record == predecessor.data.record
                {
                    return Err(ResolveError::InvalidOperation);
                }
            }
            OperationKind::Renew => {
                let expected_expiry = self
                    .params
                    .lease_expiry(block.height)
                    .ok_or(ResolveError::ArithmeticOverflow)?;
                if state.status != StateStatus::Active
                    || state.terminal_height != 0
                    || state.record != predecessor.data.record
                    || !schedule::is_anchor_height(state.name_id, block.height, self.params)
                    || state.lease_expiry != expected_expiry
                    || state.lease_expiry <= predecessor.data.lease_expiry
                {
                    return Err(ResolveError::InvalidOperation);
                }
            }
            OperationKind::Release => {
                if state.status != StateStatus::Released
                    || state.terminal_height != block.height
                    || state.record != predecessor.data.record
                    || state.lease_expiry != predecessor.data.lease_expiry
                {
                    return Err(ResolveError::InvalidOperation);
                }
            }
        }
        self.params
            .validate_state(state)
            .map_err(|_| ResolveError::InvalidOperation)?;
        let action = transaction
            .action(action_index)
            .ok_or(ResolveError::InvalidLineage)?;
        if action.commitment != *state_commitment {
            return Err(ResolveError::InvalidLineage);
        }
        let state_ref = StateRef::new(
            transaction.position(block.height),
            action_index,
            *state_commitment,
        );
        let successor = NameState::new(state.clone(), *state_commitment, state_ref)
            .map_err(|_| ResolveError::InvalidOperation)?;
        let statement =
            TransitionStatement::from_states(&predecessor, &successor, action, kind, block.height)
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
