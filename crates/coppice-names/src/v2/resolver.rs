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
        let (mut state, anchor, anchor_position) =
            match auth.find_latest_anchor(name_id, tip.height)? {
                Some(found) => found,
                None => {
                    return Ok(ResolutionResult {
                        status: ResolutionStatus::Missing,
                        state: None,
                        anchor: None,
                        stats: auth.stats,
                    });
                }
            };

        let start = anchor_position.height;
        let mut height = start;
        while height <= tip.height {
            if height > start {
                auth.stats.tail_blocks_scanned = auth
                    .stats
                    .tail_blocks_scanned
                    .checked_add(1)
                    .ok_or(ResolveError::ArithmeticOverflow)?;
            }
            if let Some(block) = source.block(height) {
                let after_anchor = height > start;
                for transaction in &block.transactions {
                    for (operation_index, operation) in transaction.operations.iter().enumerate() {
                        if !after_anchor
                            && (transaction.tx_index < anchor_position.tx_index
                                || (transaction.tx_index == anchor_position.tx_index
                                    && operation_index <= anchor_position.operation_index))
                        {
                            continue;
                        }
                        if operation.name_id() != Some(name_id) || operation.kind().is_none() {
                            continue;
                        }
                        let Some(predecessor) = transition_predecessor(operation) else {
                            continue;
                        };
                        if predecessor != state.state_ref {
                            if is_competing_or_later_producer(predecessor, state.state_ref) {
                                return Err(ResolveError::InvalidLineage);
                            }
                            continue;
                        }
                        let successor =
                            auth.authenticate_transition(&block, transaction, operation)?;
                        state = successor;
                    }
                }
            }
            if height == tip.height {
                break;
            }
            height = height
                .checked_add(1)
                .ok_or(ResolveError::ArithmeticOverflow)?;
        }

        let status = match self.params.lifecycle(&state.data, tip.height) {
            Lifecycle::Active => ResolutionStatus::Active,
            Lifecycle::Grace => ResolutionStatus::Grace,
            Lifecycle::Released => ResolutionStatus::Released,
            Lifecycle::Claimable => ResolutionStatus::Expired,
        };
        Ok(ResolutionResult {
            status,
            state: Some(state),
            anchor: Some(anchor),
            stats: auth.stats,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EventPosition {
    height: u32,
    tx_index: u32,
    operation_index: usize,
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
    fn find_latest_anchor(
        &mut self,
        name_id: NameId,
        tip_height: u32,
    ) -> Result<Option<(NameState, StateRef, EventPosition)>, ResolveError> {
        let candidates = schedule::candidate_anchor_heights(name_id, tip_height, self.params);
        for height in candidates.into_iter().rev() {
            self.stats.candidate_block_probes = self
                .stats
                .candidate_block_probes
                .checked_add(1)
                .ok_or(ResolveError::ArithmeticOverflow)?;
            let Some(block) = self.source.block(height) else {
                continue;
            };
            for (transaction_index, transaction) in block.transactions.iter().enumerate().rev() {
                for (operation_index, operation) in transaction.operations.iter().enumerate().rev()
                {
                    if operation.name_id() != Some(name_id)
                        || !matches!(
                            operation,
                            V2Operation::Reveal { .. } | V2Operation::Renew { .. }
                        )
                    {
                        continue;
                    }
                    let state = match operation {
                        V2Operation::Reveal { .. } => {
                            self.authenticate_reveal(&block, transaction, operation)?
                        }
                        V2Operation::Renew { .. } => {
                            self.authenticate_transition(&block, transaction, operation)?
                        }
                        _ => unreachable!(),
                    };
                    let reference = state.state_ref;
                    return Ok(Some((
                        state,
                        reference,
                        EventPosition {
                            height,
                            tx_index: block.transactions[transaction_index].tx_index,
                            operation_index,
                        },
                    )));
                }
            }
        }
        Ok(None)
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
            || !predecessor.is_active_at(block.height)
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

fn transition_predecessor(operation: &V2Operation) -> Option<StateRef> {
    match operation {
        V2Operation::Update { predecessor, .. }
        | V2Operation::Renew { predecessor, .. }
        | V2Operation::Release { predecessor, .. } => Some(*predecessor),
        V2Operation::Commit { .. } | V2Operation::Reveal { .. } => None,
    }
}

/// Returns true for a competing producer at the current position or any
/// later producer. A changed txid at the same block/transaction/action slot
/// is also a reorg-sensitive conflict, not an older harmless stale spend.
fn is_competing_or_later_producer(candidate: StateRef, current: StateRef) -> bool {
    (
        candidate.producer_height,
        candidate.producer_tx_index,
        candidate.producer_txid,
        candidate.producer_action_index,
    ) >= (
        current.producer_height,
        current.producer_tx_index,
        current.producer_txid,
        current.producer_action_index,
    )
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
