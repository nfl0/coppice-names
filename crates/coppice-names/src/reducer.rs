//! Deterministic canonical Names reducer.

use std::collections::{BTreeMap, VecDeque};

use crate::{
    codec::Operation,
    protocol::{CanonicalUa, CommitRef, Commitment, FieldElement, Name, NameId, Network, StateRef},
    schedule::Parameters,
    statement::{RefreshStatement, RevealStatement},
};
use serde::{Deserialize, Serialize};

const REDUCER_SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// One authenticated Ironwood action in canonical transaction order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub action_index: u32,
    pub nullifier: FieldElement,
    pub commitment: FieldElement,
}

/// One transaction after Core authentication and Names decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub actions: Vec<Action>,
    /// `None` includes transactions with no Names bulletin and malformed or
    /// ambiguous Names bulletins. Their authenticated actions remain visible.
    pub operation: Option<Operation>,
}

/// One authenticated canonical block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub height: u32,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub transactions: Vec<Transaction>,
}

/// Narrow cryptographic boundary consumed by canonical replay.
pub trait ProofVerifier {
    fn verify_reveal(&self, statement: &RevealStatement, proof: &[u8]) -> bool;
    fn verify_refresh(&self, statement: &RefreshStatement, proof: &[u8]) -> bool;
}

/// Current accepted state head for one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub name: Name,
    pub ua: CanonicalUa,
    pub producer: StateRef,
    pub commitment: FieldElement,
    pub future_nf: FieldElement,
    pub producer_epoch: u32,
    pub expiry_height: u32,
    pub terminal_height: Option<u32>,
}

impl Head {
    pub fn lifecycle(&self, height: u32, parameters: Parameters) -> Lifecycle {
        let terminal = self
            .terminal_height
            .or_else(|| (height >= self.expiry_height).then_some(self.expiry_height));
        match terminal {
            None => Lifecycle::Active,
            Some(terminal_height) => match parameters.claimable(terminal_height) {
                Ok(claimable_height) if height >= claimable_height => Lifecycle::Claimable,
                _ => Lifecycle::Cooldown,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Active,
    Cooldown,
    Claimable,
    Missing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub lifecycle: Lifecycle,
    pub ua: Option<CanonicalUa>,
    pub head: Option<Head>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    Commit,
    Reveal,
    Refresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyError {
    InvalidParameters,
    WrongHeight,
    WrongPreviousHash,
    NonCanonicalTransactionIndex,
    NonCanonicalActionIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackError {
    NoAppliedBlock,
    BeyondRetention,
    WrongTipHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizationError {
    BeyondTip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    Encoding,
    UnsupportedFormat,
    ParametersMismatch,
    NameMismatch,
    InvalidState,
    InvalidHistory,
}

#[derive(Serialize, Deserialize)]
struct StoredReducer {
    format_version: u32,
    parameters: StoredParameters,
    next_height: Option<u32>,
    tip_height: Option<u32>,
    previous_hash: [u8; 32],
    commits: Vec<(CommitRef, [u8; 32])>,
    heads: Vec<([u8; 32], StoredHead)>,
    history: Vec<StoredUndo>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct StoredParameters {
    deployment_id: [u8; 32],
    activation_height: u32,
    epoch_blocks: u32,
    window_blocks: u32,
    commit_maturity_blocks: u32,
    commit_ttl_blocks: u32,
    lease_blocks: u32,
    cooldown_blocks: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredHead {
    name: String,
    ua: String,
    producer: StateRef,
    commitment: [u8; 32],
    future_nf: [u8; 32],
    producer_epoch: u32,
    expiry_height: u32,
    terminal_height: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct StoredUndo {
    height: u32,
    hash: [u8; 32],
    previous_hash: [u8; 32],
    previous_next_height: Option<u32>,
    previous_tip_height: Option<u32>,
    commits: Vec<(CommitRef, Option<[u8; 32]>)>,
    heads: Vec<([u8; 32], Option<StoredHead>)>,
}

struct Undo {
    height: u32,
    hash: [u8; 32],
    previous_hash: [u8; 32],
    previous_next_height: Option<u32>,
    previous_tip_height: Option<u32>,
    commits: BTreeMap<CommitRef, Option<Commitment>>,
    heads: BTreeMap<NameId, Option<Head>>,
}

/// Full canonical state. No global state root or externally trusted index is
/// part of protocol authority.
pub struct Reducer<V> {
    parameters: Parameters,
    verifier: V,
    next_height: Option<u32>,
    tip_height: Option<u32>,
    previous_hash: [u8; 32],
    commits: BTreeMap<CommitRef, Commitment>,
    heads: BTreeMap<NameId, Head>,
    history: VecDeque<Undo>,
}

impl<V: ProofVerifier> Reducer<V> {
    pub fn new(
        parameters: Parameters,
        activation_parent_hash: [u8; 32],
        verifier: V,
    ) -> Result<Self, ApplyError> {
        let parameters = parameters
            .validate()
            .map_err(|_| ApplyError::InvalidParameters)?;
        Ok(Self {
            next_height: Some(parameters.activation_height),
            tip_height: None,
            parameters,
            verifier,
            previous_hash: activation_parent_hash,
            commits: BTreeMap::new(),
            heads: BTreeMap::new(),
            history: VecDeque::new(),
        })
    }

    pub fn apply_block(&mut self, block: &Block) -> Result<Vec<Accepted>, ApplyError> {
        if Some(block.height) != self.next_height {
            return Err(ApplyError::WrongHeight);
        }
        if block.prev_hash != self.previous_hash {
            return Err(ApplyError::WrongPreviousHash);
        }
        let mut previous_tx_index = None;
        for transaction in &block.transactions {
            if previous_tx_index.is_some_and(|previous| transaction.tx_index <= previous) {
                return Err(ApplyError::NonCanonicalTransactionIndex);
            }
            previous_tx_index = Some(transaction.tx_index);
            for (action_index, action) in transaction.actions.iter().enumerate() {
                if action.action_index != u32::try_from(action_index).unwrap_or(u32::MAX) {
                    return Err(ApplyError::NonCanonicalActionIndex);
                }
            }
        }

        let mut undo = self.new_undo(block.height, block.hash);
        self.prune_commits(block.height, &mut undo);
        let mut accepted = Vec::new();
        for transaction in &block.transactions {
            self.mark_expired(block.height, &mut undo);
            if let Some(value) = self.apply_transaction(block.height, transaction, &mut undo) {
                accepted.push(value);
            }
        }
        self.mark_expired(block.height, &mut undo);
        self.next_height = block.height.checked_add(1);
        self.tip_height = Some(block.height);
        self.previous_hash = block.hash;
        self.history.push_back(undo);
        Ok(accepted)
    }

    /// Reverts exactly the current canonical tip without replaying older state.
    pub fn rollback_tip(&mut self, expected_hash: [u8; 32]) -> Result<(), RollbackError> {
        let undo = self.history.back().ok_or_else(|| {
            if self.tip_height.is_some() {
                RollbackError::BeyondRetention
            } else {
                RollbackError::NoAppliedBlock
            }
        })?;
        if undo.hash != expected_hash || self.previous_hash != expected_hash {
            return Err(RollbackError::WrongTipHash);
        }
        let undo = self.history.pop_back().expect("checked nonempty history");
        for (commit_ref, previous) in undo.commits {
            match previous {
                Some(commitment) => {
                    self.commits.insert(commit_ref, commitment);
                }
                None => {
                    self.commits.remove(&commit_ref);
                }
            }
        }
        for (name_id, previous) in undo.heads {
            match previous {
                Some(head) => {
                    self.heads.insert(name_id, head);
                }
                None => {
                    self.heads.remove(&name_id);
                }
            }
        }
        self.previous_hash = undo.previous_hash;
        self.next_height = undo.previous_next_height;
        self.tip_height = undo.previous_tip_height;
        Ok(())
    }

    /// Permanently drops rollback journals at or below a finalized height.
    pub fn finalize_through(&mut self, height: u32) -> Result<(), FinalizationError> {
        if self.tip_height.is_none_or(|tip| height > tip) {
            return Err(FinalizationError::BeyondTip);
        }
        while self
            .history
            .front()
            .is_some_and(|undo| undo.height <= height)
        {
            self.history.pop_front();
        }
        Ok(())
    }

    /// Serializes deterministic replay state and retained rollback journals.
    /// The bytes are derived cache data, not a consensus-authenticated state
    /// commitment; hosts must integrity-protect them or replay on restore.
    pub fn save_snapshot(&self) -> Result<Vec<u8>, SnapshotError> {
        let stored = StoredReducer {
            format_version: REDUCER_SNAPSHOT_FORMAT_VERSION,
            parameters: self.parameters.into(),
            next_height: self.next_height,
            tip_height: self.tip_height,
            previous_hash: self.previous_hash,
            commits: self
                .commits
                .iter()
                .map(|(reference, commitment)| (*reference, commitment.to_bytes()))
                .collect(),
            heads: self
                .heads
                .iter()
                .map(|(name_id, head)| (name_id.to_bytes(), head.into()))
                .collect(),
            history: self.history.iter().map(StoredUndo::from).collect(),
        };
        serde_json::to_vec(&stored).map_err(|_| SnapshotError::Encoding)
    }

    /// Restores structurally validated replay state under independently
    /// supplied protocol parameters and network selection.
    pub fn load_snapshot(
        parameters: Parameters,
        network: Network,
        verifier: V,
        bytes: &[u8],
    ) -> Result<Self, SnapshotError> {
        let parameters = parameters
            .validate()
            .map_err(|_| SnapshotError::ParametersMismatch)?;
        let stored: StoredReducer =
            serde_json::from_slice(bytes).map_err(|_| SnapshotError::Encoding)?;
        if stored.format_version != REDUCER_SNAPSHOT_FORMAT_VERSION {
            return Err(SnapshotError::UnsupportedFormat);
        }
        if stored.parameters != StoredParameters::from(parameters) {
            return Err(SnapshotError::ParametersMismatch);
        }
        validate_tip(parameters, stored.next_height, stored.tip_height)?;

        let mut commits = BTreeMap::new();
        for (reference, bytes) in stored.commits {
            let commitment =
                Commitment::from_bytes(bytes).map_err(|_| SnapshotError::InvalidState)?;
            validate_commit(parameters, stored.tip_height, reference)?;
            if commits.insert(reference, commitment).is_some() {
                return Err(SnapshotError::InvalidState);
            }
        }

        let mut heads = BTreeMap::new();
        for (name_id, stored_head) in stored.heads {
            let name_id = NameId::from_bytes(name_id).map_err(|_| SnapshotError::InvalidState)?;
            let head = restore_head(parameters, network, stored.tip_height, stored_head)?;
            if head.name.id() != Ok(name_id) || heads.insert(name_id, head).is_some() {
                return Err(SnapshotError::InvalidState);
            }
        }

        let mut history = VecDeque::new();
        for stored_undo in stored.history {
            let undo = restore_undo(parameters, network, stored.tip_height, stored_undo)?;
            history.push_back(undo);
        }
        validate_history(stored.tip_height, stored.previous_hash, &history)?;

        Ok(Self {
            parameters,
            verifier,
            next_height: stored.next_height,
            tip_height: stored.tip_height,
            previous_hash: stored.previous_hash,
            commits,
            heads,
            history,
        })
    }

    pub(crate) fn is_exact_for(&self, name_id: NameId) -> bool {
        self.heads.keys().all(|candidate| *candidate == name_id)
            && self
                .history
                .iter()
                .all(|undo| undo.heads.keys().all(|candidate| *candidate == name_id))
    }

    pub fn resolve(&self, name: &Name, height: u32) -> Resolution {
        let Ok(name_id) = name.id() else {
            return Resolution {
                lifecycle: Lifecycle::Missing,
                ua: None,
                head: None,
            };
        };
        let Some(head) = self.heads.get(&name_id) else {
            return Resolution {
                lifecycle: Lifecycle::Missing,
                ua: None,
                head: None,
            };
        };
        let lifecycle = head.lifecycle(height, self.parameters);
        Resolution {
            ua: (lifecycle == Lifecycle::Active).then(|| head.ua.clone()),
            lifecycle,
            head: Some(head.clone()),
        }
    }

    fn remember_commit(&self, undo: &mut Undo, commit_ref: CommitRef) {
        undo.commits
            .entry(commit_ref)
            .or_insert_with(|| self.commits.get(&commit_ref).copied());
    }

    fn new_undo(&self, height: u32, hash: [u8; 32]) -> Undo {
        Undo {
            height,
            hash,
            previous_hash: self.previous_hash,
            previous_next_height: self.next_height,
            previous_tip_height: self.tip_height,
            commits: BTreeMap::new(),
            heads: BTreeMap::new(),
        }
    }

    fn remember_head(&self, undo: &mut Undo, name_id: NameId) {
        undo.heads
            .entry(name_id)
            .or_insert_with(|| self.heads.get(&name_id).cloned());
    }

    fn prune_commits(&mut self, height: u32, undo: &mut Undo) {
        let expired: Vec<_> = self
            .commits
            .keys()
            .copied()
            .filter(|commit_ref| {
                height
                    .checked_sub(commit_ref.height)
                    .is_some_and(|age| age >= self.parameters.commit_ttl_blocks)
            })
            .collect();
        for commit_ref in expired {
            self.remember_commit(undo, commit_ref);
            self.commits.remove(&commit_ref);
        }
    }

    fn mark_expired(&mut self, height: u32, undo: &mut Undo) {
        let expired: Vec<_> = self
            .heads
            .iter()
            .filter(|(_, head)| head.terminal_height.is_none() && height >= head.expiry_height)
            .map(|(name_id, _)| *name_id)
            .collect();
        for name_id in expired {
            self.remember_head(undo, name_id);
            if let Some(head) = self.heads.get_mut(&name_id) {
                head.terminal_height = Some(head.expiry_height);
            }
        }
    }

    fn apply_transaction(
        &mut self,
        height: u32,
        transaction: &Transaction,
        undo: &mut Undo,
    ) -> Option<Accepted> {
        let spent: Vec<(NameId, StateRef)> = self
            .heads
            .iter()
            .filter(|(_, head)| {
                transaction
                    .actions
                    .iter()
                    .any(|action| action.nullifier == head.future_nf)
            })
            .map(|(name_id, head)| (*name_id, head.producer))
            .collect();

        let result = match transaction.operation.as_ref() {
            Some(Operation::Commit { commitment }) => {
                let commit_ref = CommitRef {
                    height,
                    tx_index: transaction.tx_index,
                    txid: transaction.txid,
                };
                self.remember_commit(undo, commit_ref);
                self.commits.insert(commit_ref, *commitment);
                Some(Accepted::Commit)
            }
            Some(operation @ Operation::Reveal { .. }) => self
                .apply_reveal(height, transaction, operation, undo)
                .map(|_| Accepted::Reveal),
            Some(operation @ Operation::Refresh { .. }) => self
                .apply_refresh(height, transaction, operation, undo)
                .map(|_| Accepted::Refresh),
            None => None,
        };

        for (name_id, spent_producer) in spent {
            if let Some(head) = self.heads.get_mut(&name_id)
                && head.producer == spent_producer
            {
                undo.heads
                    .entry(name_id)
                    .or_insert_with(|| Some(head.clone()));
                head.terminal_height.get_or_insert(height);
            }
        }
        result
    }

    fn apply_reveal(
        &mut self,
        height: u32,
        transaction: &Transaction,
        operation: &Operation,
        undo: &mut Undo,
    ) -> Option<NameId> {
        let Operation::Reveal {
            name,
            commit,
            ua,
            action_index,
            successor_future_nf,
            proof,
        } = operation
        else {
            return None;
        };
        let name_id = name.id().ok()?;
        if self
            .heads
            .get(&name_id)
            .is_some_and(|head| head.lifecycle(height, self.parameters) != Lifecycle::Claimable)
        {
            return None;
        }
        if !self.parameters.accepts_operation(name_id, height)
            || !self.parameters.accepts_commit(commit.height, height)
        {
            return None;
        }
        let commitment = *self.commits.get(commit)?;
        let action = transaction
            .actions
            .get(usize::try_from(*action_index).ok()?)?;
        if action.action_index != *action_index {
            return None;
        }
        let epoch = self.parameters.epoch(height).ok()?;
        let statement = RevealStatement {
            deployment_id: self.parameters.deployment_id,
            name_id,
            inclusion_epoch: epoch,
            commitment,
            commit_ref: *commit,
            ua: ua.clone(),
            action_index: *action_index,
            action_nullifier: action.nullifier,
            action_commitment: action.commitment,
            successor_future_nf: *successor_future_nf,
        };
        if !self.verifier.verify_reveal(&statement, proof) {
            return None;
        }
        let expiry_height = self.parameters.expiry(height).ok()?;
        self.remember_head(undo, name_id);
        self.heads.insert(
            name_id,
            Head {
                name: name.clone(),
                ua: ua.clone(),
                producer: StateRef {
                    height,
                    tx_index: transaction.tx_index,
                    txid: transaction.txid,
                    action_index: *action_index,
                },
                commitment: action.commitment,
                future_nf: *successor_future_nf,
                producer_epoch: epoch,
                expiry_height,
                terminal_height: None,
            },
        );
        Some(name_id)
    }

    fn apply_refresh(
        &mut self,
        height: u32,
        transaction: &Transaction,
        operation: &Operation,
        undo: &mut Undo,
    ) -> Option<NameId> {
        let Operation::Refresh {
            name,
            predecessor,
            ua,
            action_index,
            successor_future_nf,
            proof,
        } = operation
        else {
            return None;
        };
        let name_id = name.id().ok()?;
        let predecessor_head = self.heads.get(&name_id)?.clone();
        let epoch = self.parameters.epoch(height).ok()?;
        if predecessor_head.lifecycle(height, self.parameters) != Lifecycle::Active
            || predecessor_head.producer != *predecessor
            || predecessor_head.producer_epoch >= epoch
            || !self.parameters.accepts_operation(name_id, height)
        {
            return None;
        }
        let action = transaction
            .actions
            .get(usize::try_from(*action_index).ok()?)?;
        if action.action_index != *action_index || action.nullifier != predecessor_head.future_nf {
            return None;
        }
        let statement = RefreshStatement {
            deployment_id: self.parameters.deployment_id,
            name_id,
            predecessor_ref: *predecessor,
            predecessor_commitment: predecessor_head.commitment,
            predecessor_future_nf: predecessor_head.future_nf,
            predecessor_epoch: predecessor_head.producer_epoch,
            inclusion_epoch: epoch,
            ua: ua.clone(),
            action_index: *action_index,
            action_nullifier: action.nullifier,
            action_commitment: action.commitment,
            successor_future_nf: *successor_future_nf,
        };
        if !self.verifier.verify_refresh(&statement, proof) {
            return None;
        }
        let expiry_height = self.parameters.expiry(height).ok()?;
        self.remember_head(undo, name_id);
        self.heads.insert(
            name_id,
            Head {
                name: name.clone(),
                ua: ua.clone(),
                producer: StateRef {
                    height,
                    tx_index: transaction.tx_index,
                    txid: transaction.txid,
                    action_index: *action_index,
                },
                commitment: action.commitment,
                future_nf: *successor_future_nf,
                producer_epoch: epoch,
                expiry_height,
                terminal_height: None,
            },
        );
        Some(name_id)
    }
}

impl From<Parameters> for StoredParameters {
    fn from(value: Parameters) -> Self {
        Self {
            deployment_id: value.deployment_id,
            activation_height: value.activation_height,
            epoch_blocks: value.epoch_blocks,
            window_blocks: value.window_blocks,
            commit_maturity_blocks: value.commit_maturity_blocks,
            commit_ttl_blocks: value.commit_ttl_blocks,
            lease_blocks: value.lease_blocks,
            cooldown_blocks: value.cooldown_blocks,
        }
    }
}

impl From<&Head> for StoredHead {
    fn from(value: &Head) -> Self {
        Self {
            name: value.name.as_str().to_owned(),
            ua: value.ua.as_str().to_owned(),
            producer: value.producer,
            commitment: value.commitment.to_bytes(),
            future_nf: value.future_nf.to_bytes(),
            producer_epoch: value.producer_epoch,
            expiry_height: value.expiry_height,
            terminal_height: value.terminal_height,
        }
    }
}

impl From<&Undo> for StoredUndo {
    fn from(value: &Undo) -> Self {
        Self {
            height: value.height,
            hash: value.hash,
            previous_hash: value.previous_hash,
            previous_next_height: value.previous_next_height,
            previous_tip_height: value.previous_tip_height,
            commits: value
                .commits
                .iter()
                .map(|(reference, commitment)| (*reference, commitment.map(Commitment::to_bytes)))
                .collect(),
            heads: value
                .heads
                .iter()
                .map(|(name_id, head)| (name_id.to_bytes(), head.as_ref().map(StoredHead::from)))
                .collect(),
        }
    }
}

fn validate_tip(
    parameters: Parameters,
    next_height: Option<u32>,
    tip_height: Option<u32>,
) -> Result<(), SnapshotError> {
    match tip_height {
        None if next_height == Some(parameters.activation_height) => Ok(()),
        Some(tip) if tip >= parameters.activation_height && next_height == tip.checked_add(1) => {
            Ok(())
        }
        _ => Err(SnapshotError::InvalidState),
    }
}

fn validate_commit(
    parameters: Parameters,
    tip_height: Option<u32>,
    reference: CommitRef,
) -> Result<(), SnapshotError> {
    let tip = tip_height.ok_or(SnapshotError::InvalidState)?;
    if reference.height < parameters.activation_height
        || reference.height > tip
        || tip - reference.height >= parameters.commit_ttl_blocks
    {
        return Err(SnapshotError::InvalidState);
    }
    Ok(())
}

fn restore_head(
    parameters: Parameters,
    network: Network,
    tip_height: Option<u32>,
    stored: StoredHead,
) -> Result<Head, SnapshotError> {
    let tip = tip_height.ok_or(SnapshotError::InvalidState)?;
    let name = Name::parse(&stored.name).map_err(|_| SnapshotError::InvalidState)?;
    let ua = CanonicalUa::parse(network, &stored.ua).map_err(|_| SnapshotError::InvalidState)?;
    let commitment =
        FieldElement::from_bytes(stored.commitment).map_err(|_| SnapshotError::InvalidState)?;
    let future_nf =
        FieldElement::from_bytes(stored.future_nf).map_err(|_| SnapshotError::InvalidState)?;
    let expected_epoch = parameters
        .epoch(stored.producer.height)
        .map_err(|_| SnapshotError::InvalidState)?;
    let expected_expiry = parameters
        .expiry(stored.producer.height)
        .map_err(|_| SnapshotError::InvalidState)?;
    if stored.producer.height > tip
        || stored.producer_epoch != expected_epoch
        || stored.expiry_height != expected_expiry
        || stored
            .terminal_height
            .is_some_and(|height| height < stored.producer.height || height > tip)
    {
        return Err(SnapshotError::InvalidState);
    }
    Ok(Head {
        name,
        ua,
        producer: stored.producer,
        commitment,
        future_nf,
        producer_epoch: stored.producer_epoch,
        expiry_height: stored.expiry_height,
        terminal_height: stored.terminal_height,
    })
}

fn restore_undo(
    parameters: Parameters,
    network: Network,
    tip_height: Option<u32>,
    stored: StoredUndo,
) -> Result<Undo, SnapshotError> {
    let expected_previous_tip = if stored.height == parameters.activation_height {
        None
    } else {
        stored.height.checked_sub(1)
    };
    if Some(stored.height) > tip_height
        || stored.previous_next_height != Some(stored.height)
        || stored.previous_tip_height != expected_previous_tip
    {
        return Err(SnapshotError::InvalidHistory);
    }

    let mut commits = BTreeMap::new();
    for (reference, previous) in stored.commits {
        let previous = previous
            .map(Commitment::from_bytes)
            .transpose()
            .map_err(|_| SnapshotError::InvalidHistory)?;
        if reference.height > stored.height
            || (previous.is_some()
                && validate_commit(parameters, stored.previous_tip_height, reference).is_err())
            || commits.insert(reference, previous).is_some()
        {
            return Err(SnapshotError::InvalidHistory);
        }
    }

    let mut heads = BTreeMap::new();
    for (name_id, previous) in stored.heads {
        let name_id = NameId::from_bytes(name_id).map_err(|_| SnapshotError::InvalidHistory)?;
        let previous = previous
            .map(|head| restore_head(parameters, network, stored.previous_tip_height, head))
            .transpose()
            .map_err(|_| SnapshotError::InvalidHistory)?;
        if previous
            .as_ref()
            .is_some_and(|head| head.name.id() != Ok(name_id))
            || heads.insert(name_id, previous).is_some()
        {
            return Err(SnapshotError::InvalidHistory);
        }
    }

    Ok(Undo {
        height: stored.height,
        hash: stored.hash,
        previous_hash: stored.previous_hash,
        previous_next_height: stored.previous_next_height,
        previous_tip_height: stored.previous_tip_height,
        commits,
        heads,
    })
}

fn validate_history(
    tip_height: Option<u32>,
    previous_hash: [u8; 32],
    history: &VecDeque<Undo>,
) -> Result<(), SnapshotError> {
    let Some(last) = history.back() else {
        return Ok(());
    };
    if Some(last.height) != tip_height || last.hash != previous_hash {
        return Err(SnapshotError::InvalidHistory);
    }
    let ordered: Vec<_> = history.iter().collect();
    for pair in ordered.windows(2) {
        if pair[0].height.checked_add(1) != Some(pair[1].height)
            || pair[1].previous_hash != pair[0].hash
        {
            return Err(SnapshotError::InvalidHistory);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Name, Network};
    use pasta_curves::{group::ff::PrimeField, pallas};

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    struct AcceptProofs;
    impl ProofVerifier for AcceptProofs {
        fn verify_reveal(&self, _: &RevealStatement, proof: &[u8]) -> bool {
            proof == [1]
        }
        fn verify_refresh(&self, _: &RefreshStatement, proof: &[u8]) -> bool {
            proof == [1]
        }
    }

    fn field(value: u64) -> FieldElement {
        FieldElement::from_bytes(pallas::Base::from(value).to_repr()).unwrap()
    }

    fn parameters() -> Parameters {
        Parameters {
            deployment_id: [7; 32],
            activation_height: 0,
            epoch_blocks: 20,
            window_blocks: 4,
            commit_maturity_blocks: 4,
            commit_ttl_blocks: 10,
            lease_blocks: 50,
            cooldown_blocks: 20,
        }
    }

    fn ua() -> CanonicalUa {
        CanonicalUa::parse(Network::Regtest, UA).unwrap()
    }

    fn apply_transaction(
        reducer: &mut Reducer<AcceptProofs>,
        height: u32,
        transaction: &Transaction,
    ) -> Option<Accepted> {
        let mut undo = reducer.new_undo(height, [0; 32]);
        reducer.apply_transaction(height, transaction, &mut undo)
    }

    #[test]
    fn block_accepts_sparse_canonical_transaction_indices_only_in_order() {
        let transactions = [2, 7, 11]
            .map(|tx_index| Transaction {
                tx_index,
                txid: [tx_index as u8; 32],
                actions: vec![],
                operation: None,
            })
            .to_vec();
        let block = |transactions| Block {
            height: 0,
            hash: [1; 32],
            prev_hash: [0; 32],
            transactions,
        };

        let mut reducer = Reducer::new(parameters(), [0; 32], AcceptProofs).unwrap();
        assert!(reducer.apply_block(&block(transactions.clone())).is_ok());

        for invalid in [
            vec![transactions[0].clone(), transactions[0].clone()],
            vec![transactions[2].clone(), transactions[1].clone()],
        ] {
            let mut reducer = Reducer::new(parameters(), [0; 32], AcceptProofs).unwrap();
            assert_eq!(
                reducer.apply_block(&block(invalid)),
                Err(ApplyError::NonCanonicalTransactionIndex)
            );
        }
    }

    #[test]
    fn accepted_refresh_advances_and_unmatched_spend_terminates() {
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        let parameters = parameters();
        let reveal_height = (0..20)
            .find(|height| parameters.accepts_operation(name_id, *height))
            .unwrap();
        let commit_height = reveal_height.checked_sub(4).unwrap_or(reveal_height + 16);
        let reveal_height = if commit_height > reveal_height {
            reveal_height + 20
        } else {
            reveal_height
        };
        let commit_ref = CommitRef {
            height: commit_height,
            tx_index: 0,
            txid: [1; 32],
        };
        let commitment = Commitment::from_bytes(pallas::Base::from(9).to_repr()).unwrap();
        let mut reducer = Reducer::new(parameters, [0; 32], AcceptProofs).unwrap();
        reducer.commits.insert(commit_ref, commitment);
        let reveal = Transaction {
            tx_index: 0,
            txid: [2; 32],
            actions: vec![Action {
                action_index: 0,
                nullifier: field(10),
                commitment: field(11),
            }],
            operation: Some(Operation::Reveal {
                name: name.clone(),
                commit: commit_ref,
                ua: ua(),
                action_index: 0,
                successor_future_nf: field(12),
                proof: vec![1],
            }),
        };
        assert_eq!(
            apply_transaction(&mut reducer, reveal_height, &reveal),
            Some(Accepted::Reveal)
        );
        let predecessor = reducer.heads[&name_id].producer;
        let refresh_height = (reveal_height + 20..reveal_height + 40)
            .find(|height| parameters.accepts_operation(name_id, *height))
            .unwrap();
        let refresh = Transaction {
            tx_index: 0,
            txid: [3; 32],
            actions: vec![Action {
                action_index: 0,
                nullifier: field(12),
                commitment: field(13),
            }],
            operation: Some(Operation::Refresh {
                name: name.clone(),
                predecessor,
                ua: ua(),
                action_index: 0,
                successor_future_nf: field(14),
                proof: vec![1],
            }),
        };
        assert_eq!(
            apply_transaction(&mut reducer, refresh_height, &refresh),
            Some(Accepted::Refresh)
        );
        assert_eq!(
            reducer.resolve(&name, refresh_height).lifecycle,
            Lifecycle::Active
        );

        let spend_height = refresh_height + 1;
        let spend = Transaction {
            tx_index: 0,
            txid: [4; 32],
            actions: vec![Action {
                action_index: 0,
                nullifier: field(14),
                commitment: field(15),
            }],
            operation: None,
        };
        assert_eq!(apply_transaction(&mut reducer, spend_height, &spend), None);
        assert_eq!(
            reducer.resolve(&name, spend_height).lifecycle,
            Lifecycle::Cooldown
        );
        assert!(reducer.resolve(&name, spend_height).ua.is_none());
        assert_eq!(
            reducer.resolve(&name, spend_height + 20).lifecycle,
            Lifecycle::Claimable
        );
    }

    #[test]
    fn invalid_refresh_spending_current_head_terminates_transaction_locally() {
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        let parameters = parameters();
        let mut reducer = Reducer::new(parameters, [0; 32], AcceptProofs).unwrap();
        reducer.heads.insert(
            name_id,
            Head {
                name: name.clone(),
                ua: ua(),
                producer: StateRef {
                    height: 1,
                    tx_index: 0,
                    txid: [1; 32],
                    action_index: 0,
                },
                commitment: field(2),
                future_nf: field(3),
                producer_epoch: 0,
                expiry_height: 51,
                terminal_height: None,
            },
        );
        let transaction = Transaction {
            tx_index: 0,
            txid: [4; 32],
            actions: vec![Action {
                action_index: 0,
                nullifier: field(3),
                commitment: field(5),
            }],
            operation: Some(Operation::Refresh {
                name: name.clone(),
                predecessor: StateRef {
                    height: 2,
                    tx_index: 0,
                    txid: [9; 32],
                    action_index: 0,
                },
                ua: ua(),
                action_index: 0,
                successor_future_nf: field(6),
                proof: vec![1],
            }),
        };
        assert_eq!(apply_transaction(&mut reducer, 25, &transaction), None);
        assert_eq!(reducer.heads[&name_id].terminal_height, Some(25));
    }

    #[test]
    fn reclaim_spending_expired_head_does_not_terminate_new_head() {
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        let parameters = parameters();
        let reveal_height = (20..100)
            .find(|height| parameters.accepts_operation(name_id, *height))
            .unwrap();
        let commit_ref = CommitRef {
            height: reveal_height - parameters.commit_maturity_blocks,
            tx_index: 0,
            txid: [7; 32],
        };
        let mut reducer = Reducer::new(parameters, [0; 32], AcceptProofs).unwrap();
        reducer.heads.insert(
            name_id,
            Head {
                name: name.clone(),
                ua: ua(),
                producer: StateRef {
                    height: 1,
                    tx_index: 0,
                    txid: [1; 32],
                    action_index: 0,
                },
                commitment: field(2),
                future_nf: field(3),
                producer_epoch: 0,
                expiry_height: 2,
                terminal_height: Some(2),
            },
        );
        reducer.commits.insert(
            commit_ref,
            Commitment::from_bytes(pallas::Base::from(8).to_repr()).unwrap(),
        );

        let reclaim = Transaction {
            tx_index: 0,
            txid: [9; 32],
            actions: vec![Action {
                action_index: 0,
                nullifier: field(3),
                commitment: field(10),
            }],
            operation: Some(Operation::Reveal {
                name: name.clone(),
                commit: commit_ref,
                ua: ua(),
                action_index: 0,
                successor_future_nf: field(11),
                proof: vec![1],
            }),
        };

        assert_eq!(
            apply_transaction(&mut reducer, reveal_height, &reclaim),
            Some(Accepted::Reveal)
        );
        let head = &reducer.heads[&name_id];
        assert_eq!(head.producer.txid, reclaim.txid);
        assert_eq!(head.terminal_height, None);
        assert_eq!(head.lifecycle(reveal_height, parameters), Lifecycle::Active);
    }

    #[test]
    fn final_u32_block_is_applied_without_wrapping_height() {
        let parameters = Parameters {
            activation_height: u32::MAX,
            ..parameters()
        };
        let mut reducer = Reducer::new(parameters, [1; 32], AcceptProofs).unwrap();
        let block = Block {
            height: u32::MAX,
            hash: [2; 32],
            prev_hash: [1; 32],
            transactions: vec![],
        };

        assert_eq!(reducer.apply_block(&block), Ok(vec![]));
        assert_eq!(reducer.next_height, None);
        assert_eq!(reducer.apply_block(&block), Err(ApplyError::WrongHeight));
    }

    #[test]
    fn rollback_restores_head_and_accepts_alternate_branch() {
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        let parameters = Parameters {
            activation_height: 25,
            ..parameters()
        };
        let mut reducer = Reducer::new(parameters, [1; 32], AcceptProofs).unwrap();
        let original = Head {
            name: name.clone(),
            ua: ua(),
            producer: StateRef {
                height: 1,
                tx_index: 0,
                txid: [2; 32],
                action_index: 0,
            },
            commitment: field(3),
            future_nf: field(4),
            producer_epoch: 0,
            expiry_height: 50,
            terminal_height: None,
        };
        reducer.heads.insert(name_id, original.clone());
        let abandoned = Block {
            height: 25,
            hash: [5; 32],
            prev_hash: [1; 32],
            transactions: vec![Transaction {
                tx_index: 0,
                txid: [6; 32],
                actions: vec![Action {
                    action_index: 0,
                    nullifier: field(4),
                    commitment: field(7),
                }],
                operation: None,
            }],
        };
        reducer.apply_block(&abandoned).unwrap();
        assert_eq!(reducer.heads[&name_id].terminal_height, Some(25));

        assert_eq!(
            reducer.rollback_tip([8; 32]),
            Err(RollbackError::WrongTipHash)
        );
        assert_eq!(reducer.heads[&name_id].terminal_height, Some(25));
        reducer.rollback_tip(abandoned.hash).unwrap();
        assert_eq!(reducer.heads[&name_id], original);

        let alternate = Block {
            height: 25,
            hash: [9; 32],
            prev_hash: [1; 32],
            transactions: vec![],
        };
        reducer.apply_block(&alternate).unwrap();
        assert_eq!(reducer.resolve(&name, 25).lifecycle, Lifecycle::Active);
        assert_eq!(
            reducer.finalize_through(26),
            Err(FinalizationError::BeyondTip)
        );
        reducer.finalize_through(25).unwrap();
        assert_eq!(
            reducer.rollback_tip(alternate.hash),
            Err(RollbackError::BeyondRetention)
        );
    }

    #[test]
    fn rollback_restores_commit_pruned_at_ttl_boundary() {
        let parameters = Parameters {
            deployment_id: [7; 32],
            activation_height: 0,
            epoch_blocks: 10,
            window_blocks: 1,
            commit_maturity_blocks: 1,
            commit_ttl_blocks: 3,
            lease_blocks: 20,
            cooldown_blocks: 10,
        };
        let mut reducer = Reducer::new(parameters, [0; 32], AcceptProofs).unwrap();
        let commitment = Commitment::from_bytes(pallas::Base::from(9).to_repr()).unwrap();
        let commit_ref = CommitRef {
            height: 0,
            tx_index: 0,
            txid: [10; 32],
        };
        let commit_block = Block {
            height: 0,
            hash: [1; 32],
            prev_hash: [0; 32],
            transactions: vec![Transaction {
                tx_index: 0,
                txid: commit_ref.txid,
                actions: vec![],
                operation: Some(Operation::Commit { commitment }),
            }],
        };
        reducer.apply_block(&commit_block).unwrap();
        for height in 1_u32..=3 {
            let block = Block {
                height,
                hash: [u8::try_from(height + 1).unwrap(); 32],
                prev_hash: [u8::try_from(height).unwrap(); 32],
                transactions: vec![],
            };
            reducer.apply_block(&block).unwrap();
        }
        assert!(!reducer.commits.contains_key(&commit_ref));

        reducer.rollback_tip([4; 32]).unwrap();
        assert_eq!(reducer.commits.get(&commit_ref), Some(&commitment));
        reducer.rollback_tip([3; 32]).unwrap();
        reducer.rollback_tip([2; 32]).unwrap();
        reducer.rollback_tip([1; 32]).unwrap();
        assert!(!reducer.commits.contains_key(&commit_ref));
        assert_eq!(
            reducer.rollback_tip([0; 32]),
            Err(RollbackError::NoAppliedBlock)
        );
    }
}
