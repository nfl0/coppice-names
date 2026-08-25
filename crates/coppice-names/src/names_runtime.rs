//! Production Coppice Names v1 application replay over generic Core context.
//!
//! Names consumes generic routed application envelopes and canonical effects
//! emitted by Core; it does not own canonical Zcash replay or fork choice.

use crate::{
    authorization,
    bond::V1BondVerifier,
    bond_tag,
    config::{DeploymentParameters, DeploymentValidationError},
    envelope::Operation,
    names_application::{
        NamesCoreCompatibilityError, NamesDeploymentId, names_v1_application_descriptor,
        names_v1_core_runtime_parameters, validate_names_v1_core_compatibility,
    },
    pending, recent_spent,
    record::NameStatus,
    reveal::{self, AuthenticatedIronwoodCheckpoint, RevealValidationError},
    state::{CoppiceState, StateMutationError},
    state_root::{self, StateRootInput},
};
pub use coppice::replay::{
    CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreIronwoodCheckpoint, CoreReplay,
    CoreReplayActivationCheckpoint, CoreReplayConfiguration, CoreReplayConfigurationError,
    CoreReplayError, CoreReplayTip, CoreRewindError, IronwoodFrontier,
};
use coppice::{
    application::{ApplicationDescriptor, ApplicationTip, CoppiceApplication},
    compositor::{CoppiceRuntime, CoppiceRuntimeError, CoppiceRuntimeRewindError},
    runtime::{
        CanonicalRuntime, CoreRuntime, CoreRuntimeConfigurationError, CoreRuntimeSnapshotError,
        RuntimeBlockContext,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesProtocolRejection {
    InvalidName,
    InvalidAddress,
    InvalidOwnerKey,
    DuplicateCommitment,
    UnknownCommitment,
    CommitmentNotMature,
    CommitmentExpired,
    NameUnavailable,
    CommitPredatesClaimEpoch,
    InvalidSequence,
    InvalidSignature,
    BondAlreadyInUse,
    BondRecentlySpent,
    InvalidBondAnchorHeight,
    UnknownBondAnchor,
    InvalidBondProof,
    OversizedProof,
    MalformedCarrier,
    MalformedOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesTransactionOutcome {
    NoOperation,
    Applied,
    Rejected(NamesProtocolRejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamesAppliedBlock {
    pub tip: ApplicationTip,
    pub name_tree_root: [u8; 32],
    pub pending_root: [u8; 32],
    pub recent_spent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub transaction_outcomes: Vec<NamesTransactionOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesApplicationError {
    NonSequentialHeight,
    PredecessorMismatch,
    MissingRequiredCheckpoint,
    StateInvariantFailure,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesRewindError {
    BeforeActivation,
    BeyondTip,
    SnapshotMissing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesRuntimeInitializationError {
    InvalidDeployment(DeploymentValidationError),
    Compatibility(NamesCoreCompatibilityError),
    CoreReplayConfiguration(CoreReplayConfigurationError),
    CoreReplay(CoreReplayError),
    CoreRuntime(CoreRuntimeConfigurationError),
    ActivationMismatch,
    InitialTipMismatch,
    InitialCheckpointMismatch,
    CoreRetentionMismatch,
    ArithmeticOverflow,
    StateInvariantFailure,
    VerifierInitializationFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesRuntimeError {
    Core(CoreReplayError),
    Names(NamesApplicationError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesRuntimeRewindError {
    Core(CoreRewindError),
    Names(NamesRewindError),
}

pub const NAMES_APPLICATION_SNAPSHOT_FORMAT_VERSION: u32 = 1;
pub const NAMES_RUNTIME_SNAPSHOT_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesRuntimeSnapshotError {
    Encoding,
    UnsupportedFormat,
    RuntimeMismatch,
    ApplicationMismatch,
    DeploymentMismatch,
    TipMismatch,
    RootMismatch,
    InvalidState,
    InvalidHistory,
    MissingCoreCheckpoint,
    Core(CoreRuntimeSnapshotError),
    Initialization,
    VerifierInitializationFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamesRuntimeAppliedBlock {
    pub core: RuntimeBlockContext,
    pub names: NamesAppliedBlock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NamesStateUndo {
    names: Vec<(String, Option<crate::record::NameRecord>)>,
    pending: Vec<([u8; 32], Option<pending::ChainPosition>)>,
    recent_spent: Vec<([u8; 32], Option<u32>)>,
}

impl NamesStateUndo {
    fn between(before: &CoppiceState, after: &CoppiceState) -> Self {
        Self {
            names: map_undo(&before.names, &after.names),
            pending: map_undo(&before.pending, &after.pending),
            recent_spent: map_undo(&before.recent_spent, &after.recent_spent),
        }
    }

    fn apply_to(&self, state: &CoppiceState) -> Result<CoppiceState, NamesRewindError> {
        let mut names = state.names.clone();
        let mut pending = state.pending.clone();
        let mut recent_spent = state.recent_spent.clone();
        apply_map_undo(&mut names, &self.names);
        apply_map_undo(&mut pending, &self.pending);
        apply_map_undo(&mut recent_spent, &self.recent_spent);
        CoppiceState::from_authoritative_parts(names, pending, recent_spent)
            .map_err(|_| NamesRewindError::SnapshotMissing)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NamesUndo {
    applied_tip: ApplicationTip,
    prior_tip: ApplicationTip,
    state: NamesStateUndo,
    prior_state_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredApplicationTip {
    height: u32,
    block_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredNamesState {
    names: Vec<(String, crate::record::NameRecord)>,
    pending: Vec<([u8; 32], pending::ChainPosition)>,
    recent_spent: Vec<([u8; 32], u32)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredNamesStateUndo {
    names: Vec<(String, Option<crate::record::NameRecord>)>,
    pending: Vec<([u8; 32], Option<pending::ChainPosition>)>,
    recent_spent: Vec<([u8; 32], Option<u32>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredNamesUndo {
    applied_tip: StoredApplicationTip,
    prior_tip: StoredApplicationTip,
    state: StoredNamesStateUndo,
    prior_state_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredNamesApplication {
    format_version: u32,
    application_id: [u8; 32],
    application_version: u16,
    deployment_id: [u8; 32],
    tip: StoredApplicationTip,
    state: StoredNamesState,
    state_root: [u8; 32],
    undo: Vec<StoredNamesUndo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredNamesRuntime {
    format_version: u32,
    runtime_id: [u8; 32],
    application_id: [u8; 32],
    application_version: u16,
    tip: StoredApplicationTip,
    ironwood_root: [u8; 32],
    ironwood_tree_size: u32,
    application_state_root: [u8; 32],
    core_snapshot: Vec<u8>,
    application_snapshot: Vec<u8>,
}

/// Names-specific deterministic state machine. It consumes Core contexts but
/// neither owns canonical Zcash replay nor selects a fork.
pub struct NamesApplication {
    deployment: DeploymentParameters,
    deployment_id: NamesDeploymentId,
    descriptor: ApplicationDescriptor,
    state: CoppiceState,
    tip: ApplicationTip,
    state_root: [u8; 32],
    verifier: V1BondVerifier,
    retention_blocks: u32,
    history: BTreeMap<u32, NamesUndo>,
}

impl Clone for NamesApplication {
    fn clone(&self) -> Self {
        Self {
            deployment: self.deployment.clone(),
            deployment_id: self.deployment_id,
            descriptor: self.descriptor,
            state: self.state.clone(),
            tip: self.tip,
            state_root: self.state_root,
            // Verifier construction is deterministic public setup and has no
            // application state. Keeping it out of the clone boundary avoids
            // assuming upstream proving-key internals are Clone.
            verifier: V1BondVerifier::new().expect("frozen Coppice Names verifier must initialize"),
            retention_blocks: self.retention_blocks,
            history: self.history.clone(),
        }
    }
}

impl NamesApplication {
    fn new(
        deployment: DeploymentParameters,
        core: &CoreRuntime,
    ) -> Result<Self, NamesRuntimeInitializationError> {
        let deployment_id = NamesDeploymentId::from_bytes(
            deployment
                .validate()
                .map_err(NamesRuntimeInitializationError::InvalidDeployment)?,
        );
        validate_names_v1_core_compatibility(
            core.parameters(),
            &deployment,
            names_v1_application_descriptor(deployment.activation_height),
        )
        .map_err(NamesRuntimeInitializationError::Compatibility)?;
        let replay = core.replay();
        if deployment.activation_height != replay.configuration().activation_height() {
            return Err(NamesRuntimeInitializationError::ActivationMismatch);
        }
        let activation_checkpoint_height = deployment
            .activation_height
            .checked_sub(1)
            .ok_or(NamesRuntimeInitializationError::ArithmeticOverflow)?;
        let core_tip = replay.tip();
        if core_tip.height != activation_checkpoint_height {
            return Err(NamesRuntimeInitializationError::InitialTipMismatch);
        }
        let checkpoint = replay
            .ironwood_checkpoints()
            .get(&activation_checkpoint_height)
            .copied()
            .ok_or(NamesRuntimeInitializationError::InitialCheckpointMismatch)?;
        if checkpoint.tree_size as usize != replay.ironwood_frontier().size()
            || checkpoint.root != replay.ironwood_frontier().root().to_bytes()
        {
            return Err(NamesRuntimeInitializationError::InitialCheckpointMismatch);
        }
        let retention_blocks = names_v1_replay_retention_blocks(&deployment)?;
        if replay.configuration().retention_blocks() != retention_blocks {
            return Err(NamesRuntimeInitializationError::CoreRetentionMismatch);
        }
        let tip = ApplicationTip {
            height: core_tip.height,
            block_hash: core_tip.block_hash,
        };
        let state = CoppiceState::default();
        let state_root = calculate_state_root(&deployment, deployment_id, &state, tip, checkpoint)?;
        let verifier = V1BondVerifier::new()
            .map_err(|_| NamesRuntimeInitializationError::VerifierInitializationFailure)?;
        Ok(Self {
            descriptor: names_v1_application_descriptor(deployment.activation_height),
            deployment,
            deployment_id,
            state,
            tip,
            state_root,
            verifier,
            retention_blocks,
            history: BTreeMap::new(),
        })
    }

    pub fn deployment(&self) -> &DeploymentParameters {
        &self.deployment
    }

    pub fn deployment_id(&self) -> NamesDeploymentId {
        self.deployment_id
    }

    pub fn state(&self) -> &CoppiceState {
        &self.state
    }

    pub fn descriptor(&self) -> ApplicationDescriptor {
        self.descriptor
    }

    pub fn tip(&self) -> ApplicationTip {
        self.tip
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn oldest_rewind_height(&self) -> u32 {
        self.history
            .first_key_value()
            .map_or(self.tip.height, |(_, undo)| undo.prior_tip.height)
    }

    pub fn has_rewind_snapshot(&self, height: u32) -> bool {
        height == self.tip.height
            || (height >= self.oldest_rewind_height() && height < self.tip.height)
    }

    pub fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
        if height == self.tip.height {
            Some(self.tip)
        } else {
            height
                .checked_add(1)
                .and_then(|next| self.history.get(&next))
                .map(|undo| undo.prior_tip)
        }
    }

    fn save_snapshot(&self, core: &CoreRuntime) -> Result<Vec<u8>, NamesRuntimeSnapshotError> {
        validate_names_core_position(self.tip, core)?;
        validate_names_state_shape(&self.state, &self.deployment, self.tip.height)?;
        let checkpoint = core
            .ironwood_checkpoints()
            .get(&self.tip.height)
            .copied()
            .ok_or(NamesRuntimeSnapshotError::MissingCoreCheckpoint)?;
        let expected_root = calculate_state_root(
            &self.deployment,
            self.deployment_id,
            &self.state,
            self.tip,
            checkpoint,
        )
        .map_err(|_| NamesRuntimeSnapshotError::InvalidState)?;
        if expected_root != self.state_root {
            return Err(NamesRuntimeSnapshotError::RootMismatch);
        }
        let stored = StoredNamesApplication {
            format_version: NAMES_APPLICATION_SNAPSHOT_FORMAT_VERSION,
            application_id: self.descriptor.key.id.to_bytes(),
            application_version: self.descriptor.key.version,
            deployment_id: self.deployment_id.to_bytes(),
            tip: store_application_tip(self.tip),
            state: store_names_state(&self.state),
            state_root: self.state_root,
            undo: self
                .history
                .values()
                .map(|undo| StoredNamesUndo {
                    applied_tip: store_application_tip(undo.applied_tip),
                    prior_tip: store_application_tip(undo.prior_tip),
                    state: StoredNamesStateUndo {
                        names: undo.state.names.clone(),
                        pending: undo.state.pending.clone(),
                        recent_spent: undo.state.recent_spent.clone(),
                    },
                    prior_state_root: undo.prior_state_root,
                })
                .collect(),
        };
        serde_json::to_vec(&stored).map_err(|_| NamesRuntimeSnapshotError::Encoding)
    }

    fn load_snapshot(
        deployment: DeploymentParameters,
        core: &CoreRuntime,
        bytes: &[u8],
    ) -> Result<Self, NamesRuntimeSnapshotError> {
        let stored: StoredNamesApplication =
            serde_json::from_slice(bytes).map_err(|_| NamesRuntimeSnapshotError::Encoding)?;
        if stored.format_version != NAMES_APPLICATION_SNAPSHOT_FORMAT_VERSION {
            return Err(NamesRuntimeSnapshotError::UnsupportedFormat);
        }
        let descriptor = names_v1_application_descriptor(deployment.activation_height);
        if stored.application_id != descriptor.key.id.to_bytes()
            || stored.application_version != descriptor.key.version
        {
            return Err(NamesRuntimeSnapshotError::ApplicationMismatch);
        }
        let deployment_id = NamesDeploymentId::from_parameters(&deployment)
            .map_err(|_| NamesRuntimeSnapshotError::DeploymentMismatch)?;
        if stored.deployment_id != deployment_id.to_bytes() {
            return Err(NamesRuntimeSnapshotError::DeploymentMismatch);
        }
        validate_names_v1_core_compatibility(core.parameters(), &deployment, descriptor)
            .map_err(|_| NamesRuntimeSnapshotError::Initialization)?;
        let tip = restore_application_tip(stored.tip);
        validate_names_core_position(tip, core)?;
        let state = restore_names_state(stored.state, &deployment, tip.height)?;
        let retention_blocks = names_v1_replay_retention_blocks(&deployment)
            .map_err(|_| NamesRuntimeSnapshotError::Initialization)?;
        if core.configuration().retention_blocks() != retention_blocks
            || stored.undo.len() > retention_blocks as usize
        {
            return Err(NamesRuntimeSnapshotError::InvalidHistory);
        }
        let mut history = BTreeMap::new();
        for stored_undo in stored.undo {
            if has_duplicate_or_unsorted_keys(&stored_undo.state.names)
                || has_duplicate_or_unsorted_keys(&stored_undo.state.pending)
                || has_duplicate_or_unsorted_keys(&stored_undo.state.recent_spent)
            {
                return Err(NamesRuntimeSnapshotError::InvalidHistory);
            }
            let applied_tip = restore_application_tip(stored_undo.applied_tip);
            let prior_tip = restore_application_tip(stored_undo.prior_tip);
            if prior_tip.height.checked_add(1) != Some(applied_tip.height) {
                return Err(NamesRuntimeSnapshotError::InvalidHistory);
            }
            if history
                .insert(
                    applied_tip.height,
                    NamesUndo {
                        applied_tip,
                        prior_tip,
                        state: NamesStateUndo {
                            names: stored_undo.state.names,
                            pending: stored_undo.state.pending,
                            recent_spent: stored_undo.state.recent_spent,
                        },
                        prior_state_root: stored_undo.prior_state_root,
                    },
                )
                .is_some()
            {
                return Err(NamesRuntimeSnapshotError::InvalidHistory);
            }
        }
        let expected_oldest = tip.height.saturating_sub(history.len() as u32);
        if history
            .keys()
            .copied()
            .ne(expected_oldest.saturating_add(1)..=tip.height)
        {
            return Err(NamesRuntimeSnapshotError::InvalidHistory);
        }
        let verifier = V1BondVerifier::new()
            .map_err(|_| NamesRuntimeSnapshotError::VerifierInitializationFailure)?;
        let application = Self {
            deployment,
            deployment_id,
            descriptor,
            state,
            tip,
            state_root: stored.state_root,
            verifier,
            retention_blocks,
            history,
        };
        validate_names_core_history_boundary(&application, core)?;
        application.validate_snapshot_history(core)?;
        Ok(application)
    }

    fn validate_snapshot_history(
        &self,
        core: &CoreRuntime,
    ) -> Result<(), NamesRuntimeSnapshotError> {
        let mut validation_core = core.clone();
        let mut state = self.state.clone();
        let mut tip = self.tip;
        let mut expected_root = self.state_root;
        let mut history = self.history.clone();
        loop {
            validate_names_core_position(tip, &validation_core)?;
            validate_names_state_shape(&state, &self.deployment, tip.height)?;
            let checkpoint = validation_core
                .ironwood_checkpoints()
                .get(&tip.height)
                .copied()
                .ok_or(NamesRuntimeSnapshotError::MissingCoreCheckpoint)?;
            let computed = calculate_state_root(
                &self.deployment,
                self.deployment_id,
                &state,
                tip,
                checkpoint,
            )
            .map_err(|_| NamesRuntimeSnapshotError::InvalidState)?;
            if computed != expected_root {
                return Err(NamesRuntimeSnapshotError::RootMismatch);
            }
            let Some(undo) = history.remove(&tip.height) else {
                break;
            };
            if undo.applied_tip != tip {
                return Err(NamesRuntimeSnapshotError::InvalidHistory);
            }
            state = undo
                .state
                .apply_to(&state)
                .map_err(|_| NamesRuntimeSnapshotError::InvalidState)?;
            tip = undo.prior_tip;
            expected_root = undo.prior_state_root;
            validation_core
                .rewind_to(tip.height)
                .map_err(|_| NamesRuntimeSnapshotError::InvalidHistory)?;
        }
        if !history.is_empty() {
            return Err(NamesRuntimeSnapshotError::InvalidHistory);
        }
        validate_names_core_history_boundary(self, core)?;
        Ok(())
    }

    fn apply_operation(
        &self,
        state: &mut CoppiceState,
        block: &coppice::replay::CoreBlockContext,
        tx_index: u32,
        operation: &Operation,
    ) -> Result<NamesTransactionOutcome, NamesApplicationError> {
        let rejection = match operation {
            Operation::Commit { commitment } => match state.apply_prevalidated_commit(
                *commitment,
                pending::ChainPosition {
                    block_height: block.height(),
                    tx_index,
                },
            ) {
                Ok(()) => return Ok(NamesTransactionOutcome::Applied),
                Err(StateMutationError::DuplicateCommitment) => {
                    NamesProtocolRejection::DuplicateCommitment
                }
                Err(error) => return Err(map_state_fatal(error)),
            },
            Operation::Reveal {
                name,
                owner_pk,
                bond_anchor_height,
                bond_proof,
                address,
                ..
            } => {
                if !crate::envelope::valid_name(name) {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidName,
                    ));
                }
                if crate::owner::parse_v1_owner_key(*owner_pk).is_err() {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidOwnerKey,
                    ));
                }
                if reveal::canonical_v1_address(address, &self.deployment).is_err() {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidAddress,
                    ));
                }
                if bond_proof.len() > reveal::MAX_BOND_PROOF_LEN {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::OversizedProof,
                    ));
                }
                let commitment = reveal_commitment(&self.deployment, operation)
                    .ok_or(NamesApplicationError::StateInvariantFailure)?;
                let Some(committed_at) = state.pending.get(&commitment).copied() else {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::UnknownCommitment,
                    ));
                };
                if *bond_anchor_height < committed_at.block_height
                    || *bond_anchor_height >= block.height()
                {
                    return Ok(NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::InvalidBondAnchorHeight,
                    ));
                }
                let anchor = block
                    .prior_ironwood_checkpoint(*bond_anchor_height)
                    .map(authenticated_checkpoint)
                    .ok_or(NamesApplicationError::MissingRequiredCheckpoint)?;
                let floor_height = (self.deployment.activation_height - 1).max(
                    committed_at
                        .block_height
                        .saturating_sub(self.deployment.bond_note_max_age_blocks),
                );
                let floor = block
                    .prior_ironwood_checkpoint(floor_height)
                    .map(authenticated_checkpoint)
                    .ok_or(NamesApplicationError::MissingRequiredCheckpoint)?;
                match reveal::validate_v1_reveal(
                    state,
                    &self.deployment,
                    block.height(),
                    anchor,
                    floor,
                    &self.verifier,
                    operation,
                ) {
                    Ok(validated) => {
                        state
                            .apply_prevalidated_reveal(validated)
                            .map_err(map_state_fatal)?;
                        return Ok(NamesTransactionOutcome::Applied);
                    }
                    Err(error) => map_reveal_rejection(error)?,
                }
            }
            Operation::Update {
                name,
                sequence,
                address,
                ..
            } => {
                if !crate::envelope::valid_name(name) {
                    NamesProtocolRejection::InvalidName
                } else {
                    let Some(current) = state.names.get(name) else {
                        return Ok(NamesTransactionOutcome::Rejected(
                            NamesProtocolRejection::NameUnavailable,
                        ));
                    };
                    if current.status != NameStatus::Active {
                        NamesProtocolRejection::NameUnavailable
                    } else if reveal::canonical_v1_address(address, &self.deployment).is_err() {
                        NamesProtocolRejection::InvalidAddress
                    } else if current.sequence.checked_add(1) != Some(*sequence) {
                        NamesProtocolRejection::InvalidSequence
                    } else if !authorization::verify_v1(
                        self.deployment_id.to_bytes(),
                        operation,
                        current,
                    ) {
                        NamesProtocolRejection::InvalidSignature
                    } else {
                        state
                            .apply_prevalidated_update(name, *sequence, address.clone())
                            .map_err(map_state_fatal)?;
                        return Ok(NamesTransactionOutcome::Applied);
                    }
                }
            }
            Operation::Release { name, sequence, .. } => {
                if !crate::envelope::valid_name(name) {
                    NamesProtocolRejection::InvalidName
                } else {
                    let Some(current) = state.names.get(name) else {
                        return Ok(NamesTransactionOutcome::Rejected(
                            NamesProtocolRejection::NameUnavailable,
                        ));
                    };
                    if current.status != NameStatus::Active {
                        NamesProtocolRejection::NameUnavailable
                    } else if current.sequence.checked_add(1) != Some(*sequence) {
                        NamesProtocolRejection::InvalidSequence
                    } else if !authorization::verify_v1(
                        self.deployment_id.to_bytes(),
                        operation,
                        current,
                    ) {
                        NamesProtocolRejection::InvalidSignature
                    } else {
                        state
                            .apply_prevalidated_release(name, *sequence, block.height())
                            .map_err(map_state_fatal)?;
                        return Ok(NamesTransactionOutcome::Applied);
                    }
                }
            }
        };
        Ok(NamesTransactionOutcome::Rejected(rejection))
    }
}

impl CoppiceApplication for NamesApplication {
    type BlockOutput = NamesAppliedBlock;
    type ApplyError = NamesApplicationError;
    type RewindError = NamesRewindError;

    fn descriptor(&self) -> ApplicationDescriptor {
        self.descriptor
    }

    fn tip(&self) -> ApplicationTip {
        self.tip
    }

    fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    fn apply_block(
        &mut self,
        block: &coppice::application::ApplicationBlockContext,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        let core = block
            .core()
            .ok_or(NamesApplicationError::StateInvariantFailure)?;
        if self.tip.height.checked_add(1) != Some(core.height()) {
            return Err(NamesApplicationError::NonSequentialHeight);
        }
        if self.tip.block_hash != core.prev_block_hash() {
            return Err(NamesApplicationError::PredecessorMismatch);
        }

        let mut state = self.state.clone();
        let mut transaction_outcomes = Vec::with_capacity(block.transactions().len());
        for routed in block.transactions() {
            let transaction = routed.core();
            for nullifier in transaction.ironwood_effects().nullifiers() {
                let bond_tag = bond_tag::derive_v1_bond_tag(nullifier)
                    .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
                state
                    .process_prevalidated_bond_tag(bond_tag, core.height())
                    .map_err(map_state_fatal)?;
            }
            let outcome = match routed.payload() {
                None => NamesTransactionOutcome::NoOperation,
                Some(payload) => match crate::envelope::decode_operation(payload) {
                    Ok(operation) => {
                        self.apply_operation(&mut state, core, transaction.tx_index(), &operation)?
                    }
                    Err(_) => NamesTransactionOutcome::Rejected(
                        NamesProtocolRejection::MalformedOperation,
                    ),
                },
            };
            transaction_outcomes.push(outcome);
        }

        state
            .expire_pending_at_end_of_block(core.height(), self.deployment.commit_ttl_blocks)
            .map_err(map_state_fatal)?;
        let (oldest_retained_height, _) = state
            .prune_recent_spent_at_end_of_block(
                self.deployment.activation_height,
                core.height(),
                self.deployment.bond_note_max_age_blocks,
                self.deployment.commit_ttl_blocks,
            )
            .map_err(map_state_fatal)?;
        let name_tree_root = state
            .name_tree_root()
            .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let pending_root = state
            .pending_root()
            .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let recent_spent_root = state
            .recent_spent_root(oldest_retained_height)
            .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let checkpoint = core.ironwood_checkpoint();
        let state_root = state_root::state_root(&StateRootInput {
            deployment_id: self.deployment_id.to_bytes(),
            height: core.height(),
            block_hash: core.block_hash(),
            ironwood_tree_size: checkpoint.tree_size,
            ironwood_root: checkpoint.root,
            name_tree_root,
            pending_root,
            recent_spent_root,
        })
        .map_err(|_| NamesApplicationError::StateInvariantFailure)?;
        let tip = ApplicationTip {
            height: core.height(),
            block_hash: core.block_hash(),
        };
        let undo = NamesUndo {
            applied_tip: tip,
            prior_tip: self.tip,
            state: NamesStateUndo::between(&self.state, &state),
            prior_state_root: self.state_root,
        };

        self.state = state;
        self.tip = tip;
        self.state_root = state_root;
        self.history.insert(core.height(), undo);
        let oldest_undo = core
            .height()
            .saturating_sub(self.retention_blocks)
            .saturating_add(1);
        self.history.retain(|height, _| *height >= oldest_undo);

        Ok(NamesAppliedBlock {
            tip,
            name_tree_root,
            pending_root,
            recent_spent_root,
            state_root,
            transaction_outcomes,
        })
    }

    fn rewind_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        let activation_checkpoint_height = self.deployment.activation_height - 1;
        if height < activation_checkpoint_height {
            return Err(NamesRewindError::BeforeActivation);
        }
        if height > self.tip.height {
            return Err(NamesRewindError::BeyondTip);
        }
        if height < self.oldest_rewind_height() {
            return Err(NamesRewindError::SnapshotMissing);
        }

        let mut state = self.state.clone();
        let mut tip = self.tip;
        let mut state_root = self.state_root;
        let mut history = self.history.clone();
        while tip.height > height {
            let undo = history
                .remove(&tip.height)
                .ok_or(NamesRewindError::SnapshotMissing)?;
            if tip != undo.applied_tip {
                return Err(NamesRewindError::SnapshotMissing);
            }
            state = undo.state.apply_to(&state)?;
            tip = undo.prior_tip;
            state_root = undo.prior_state_root;
        }
        self.state = state;
        self.tip = tip;
        self.state_root = state_root;
        self.history = history;
        Ok(())
    }

    fn rewind_retention_blocks(&self) -> u32 {
        self.retention_blocks
    }

    fn oldest_rewind_height(&self) -> u32 {
        self.oldest_rewind_height()
    }

    fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
        self.retained_tip_at(height)
    }
}

/// Production composition of generic Core replay and Coppice Names v1.
pub struct NamesRuntime {
    core: CoreRuntime,
    names: NamesApplication,
}

impl NamesRuntime {
    pub fn from_core(
        core: CoreRuntime,
        deployment: DeploymentParameters,
    ) -> Result<Self, NamesRuntimeInitializationError> {
        let names = NamesApplication::new(deployment, &core)?;
        Ok(Self { core, names })
    }

    pub fn core(&self) -> &CoreRuntime {
        &self.core
    }

    pub fn names(&self) -> &NamesApplication {
        &self.names
    }

    pub fn deployment(&self) -> &DeploymentParameters {
        self.names.deployment()
    }

    pub fn names_deployment_id(&self) -> NamesDeploymentId {
        self.names.deployment_id()
    }

    pub fn state(&self) -> &CoppiceState {
        self.names.state()
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.names.state_root()
    }

    pub fn tip(&self) -> coppice::replay::CoreReplayTip {
        self.core.tip()
    }

    pub fn ironwood_frontier(&self) -> &coppice::replay::IronwoodFrontier {
        self.core.ironwood_frontier()
    }

    pub fn ironwood_checkpoints(&self) -> &BTreeMap<u32, CoreIronwoodCheckpoint> {
        self.core.ironwood_checkpoints()
    }

    pub fn oldest_rewind_height(&self) -> u32 {
        debug_assert_eq!(
            self.core.oldest_rewind_height(),
            self.names.oldest_rewind_height()
        );
        self.core.oldest_rewind_height()
    }

    pub fn reorg_retention_blocks(&self) -> u32 {
        self.core.configuration().retention_blocks()
    }

    pub fn has_rewind_snapshot(&self, height: u32) -> bool {
        self.core.has_rewind_snapshot(height) && self.names.has_rewind_snapshot(height)
    }

    pub fn retained_tip_at(&self, height: u32) -> Option<coppice::replay::CoreReplayTip> {
        let core = self.core.retained_tip_at(height)?;
        let names = self.names.retained_tip_at(height)?;
        (core.height == names.height && core.block_hash == names.block_hash).then_some(core)
    }

    pub fn apply_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<NamesRuntimeAppliedBlock, NamesRuntimeError> {
        let mut runtime = CoppiceRuntime::new(self.core.clone(), self.names.clone())
            .map_err(|_| NamesRuntimeError::Names(NamesApplicationError::StateInvariantFailure))?;
        let applied = runtime.apply_block(block).map_err(|error| match error {
            CoppiceRuntimeError::Core(error) => NamesRuntimeError::Core(error),
            CoppiceRuntimeError::Applications(_) => {
                NamesRuntimeError::Names(NamesApplicationError::StateInvariantFailure)
            }
        })?;
        let (core, names) = runtime.into_parts();
        self.core = core;
        self.names = names;
        Ok(NamesRuntimeAppliedBlock {
            core: applied.core,
            names: applied.applications,
        })
    }

    pub fn rewind_to(&mut self, height: u32) -> Result<(), NamesRuntimeRewindError> {
        let mut runtime = CoppiceRuntime::new(self.core.clone(), self.names.clone())
            .map_err(|_| NamesRuntimeRewindError::Names(NamesRewindError::SnapshotMissing))?;
        runtime.rewind_to(height).map_err(|error| match error {
            CoppiceRuntimeRewindError::Core(error) => NamesRuntimeRewindError::Core(error),
            CoppiceRuntimeRewindError::Applications(_) => {
                NamesRuntimeRewindError::Names(NamesRewindError::SnapshotMissing)
            }
        })?;
        let (core, names) = runtime.into_parts();
        self.core = core;
        self.names = names;
        Ok(())
    }

    pub fn save_snapshot(&self) -> Result<Vec<u8>, NamesRuntimeSnapshotError> {
        validate_names_core_position(self.names.tip, &self.core)?;
        let checkpoint = self
            .core
            .ironwood_checkpoints()
            .get(&self.names.tip.height)
            .copied()
            .ok_or(NamesRuntimeSnapshotError::MissingCoreCheckpoint)?;
        let stored = StoredNamesRuntime {
            format_version: NAMES_RUNTIME_SNAPSHOT_FORMAT_VERSION,
            runtime_id: self.core.runtime_id().to_bytes(),
            application_id: self.names.descriptor.key.id.to_bytes(),
            application_version: self.names.descriptor.key.version,
            tip: store_application_tip(self.names.tip),
            ironwood_root: checkpoint.root,
            ironwood_tree_size: checkpoint.tree_size,
            application_state_root: self.names.state_root,
            core_snapshot: self
                .core
                .save_snapshot()
                .map_err(NamesRuntimeSnapshotError::Core)?,
            application_snapshot: self.names.save_snapshot(&self.core)?,
        };
        serde_json::to_vec(&stored).map_err(|_| NamesRuntimeSnapshotError::Encoding)
    }

    pub fn load_snapshot(
        deployment: DeploymentParameters,
        bytes: &[u8],
    ) -> Result<Self, NamesRuntimeSnapshotError> {
        let stored: StoredNamesRuntime =
            serde_json::from_slice(bytes).map_err(|_| NamesRuntimeSnapshotError::Encoding)?;
        if stored.format_version != NAMES_RUNTIME_SNAPSHOT_FORMAT_VERSION {
            return Err(NamesRuntimeSnapshotError::UnsupportedFormat);
        }
        let parameters = names_v1_core_runtime_parameters(&deployment)
            .map_err(|_| NamesRuntimeSnapshotError::Initialization)?;
        if stored.runtime_id != parameters.core_runtime_id().to_bytes() {
            return Err(NamesRuntimeSnapshotError::RuntimeMismatch);
        }
        let descriptor = names_v1_application_descriptor(deployment.activation_height);
        if stored.application_id != descriptor.key.id.to_bytes()
            || stored.application_version != descriptor.key.version
        {
            return Err(NamesRuntimeSnapshotError::ApplicationMismatch);
        }
        let retention = names_v1_replay_retention_blocks(&deployment)
            .map_err(|_| NamesRuntimeSnapshotError::Initialization)?;
        let configuration = CoreReplayConfiguration::new(deployment.activation_height, retention)
            .map_err(|_| NamesRuntimeSnapshotError::Initialization)?;
        let core = CoreRuntime::load_snapshot(parameters, configuration, &stored.core_snapshot)
            .map_err(NamesRuntimeSnapshotError::Core)?;
        let names =
            NamesApplication::load_snapshot(deployment, &core, &stored.application_snapshot)?;
        if store_application_tip(names.tip).height != stored.tip.height
            || names.tip.block_hash != stored.tip.block_hash
            || names.state_root != stored.application_state_root
        {
            return Err(NamesRuntimeSnapshotError::TipMismatch);
        }
        let checkpoint = core
            .ironwood_checkpoints()
            .get(&names.tip.height)
            .ok_or(NamesRuntimeSnapshotError::MissingCoreCheckpoint)?;
        if checkpoint.root != stored.ironwood_root
            || checkpoint.tree_size != stored.ironwood_tree_size
        {
            return Err(NamesRuntimeSnapshotError::RootMismatch);
        }
        Ok(Self { core, names })
    }
}

impl CanonicalRuntime for NamesRuntime {
    type BlockOutput = NamesRuntimeAppliedBlock;
    type ApplyError = NamesRuntimeError;
    type RewindError = NamesRuntimeRewindError;

    fn core_parameters(&self) -> &coppice::identity::ValidatedCoreRuntimeParameters {
        self.core.parameters()
    }

    fn rendezvous(&self) -> &coppice::carrier::CoreRendezvous {
        self.core.rendezvous()
    }

    fn tip(&self) -> coppice::replay::CoreReplayTip {
        self.tip()
    }

    fn oldest_rewind_height(&self) -> u32 {
        self.oldest_rewind_height()
    }

    fn retained_tip_at(&self, height: u32) -> Option<coppice::replay::CoreReplayTip> {
        self.retained_tip_at(height)
    }

    fn apply_canonical_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        self.apply_block(block)
    }

    fn rewind_canonical_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        self.rewind_to(height)
    }
}

impl NamesRuntime {
    pub fn new(
        deployment: DeploymentParameters,
        checkpoint: CoreReplayActivationCheckpoint,
    ) -> Result<Self, NamesRuntimeInitializationError> {
        Self::from_names_deployment(deployment, checkpoint)
    }

    pub fn from_names_deployment(
        deployment: DeploymentParameters,
        checkpoint: CoreReplayActivationCheckpoint,
    ) -> Result<Self, NamesRuntimeInitializationError> {
        let parameters = names_v1_core_runtime_parameters(&deployment)
            .map_err(NamesRuntimeInitializationError::Compatibility)?;
        let retention = names_v1_replay_retention_blocks(&deployment)?;
        let configuration = CoreReplayConfiguration::new(deployment.activation_height, retention)
            .map_err(NamesRuntimeInitializationError::CoreReplayConfiguration)?;
        let replay = CoreReplay::new(configuration, checkpoint)
            .map_err(NamesRuntimeInitializationError::CoreReplay)?;
        let core = CoreRuntime::new(parameters, replay)
            .map_err(NamesRuntimeInitializationError::CoreRuntime)?;
        Self::from_core(core, deployment)
    }
}

pub fn names_v1_replay_retention_blocks(
    deployment: &DeploymentParameters,
) -> Result<u32, NamesRuntimeInitializationError> {
    deployment
        .bond_note_max_age_blocks
        .checked_add(deployment.commit_ttl_blocks)
        .and_then(|value| value.checked_add(1))
        .ok_or(NamesRuntimeInitializationError::ArithmeticOverflow)
}

fn reveal_commitment(deployment: &DeploymentParameters, operation: &Operation) -> Option<[u8; 32]> {
    let Operation::Reveal {
        name,
        owner_pk,
        bond_tag,
        address,
        secret,
        ..
    } = operation
    else {
        return None;
    };
    crate::registration::registration_commitment(
        deployment, name, *owner_pk, *bond_tag, address, *secret,
    )
    .ok()
}

fn authenticated_checkpoint(checkpoint: CoreIronwoodCheckpoint) -> AuthenticatedIronwoodCheckpoint {
    AuthenticatedIronwoodCheckpoint {
        height: checkpoint.height,
        root: checkpoint.root,
        tree_size: checkpoint.tree_size,
    }
}

fn store_application_tip(tip: ApplicationTip) -> StoredApplicationTip {
    StoredApplicationTip {
        height: tip.height,
        block_hash: tip.block_hash,
    }
}

fn restore_application_tip(tip: StoredApplicationTip) -> ApplicationTip {
    ApplicationTip {
        height: tip.height,
        block_hash: tip.block_hash,
    }
}

fn store_names_state(state: &CoppiceState) -> StoredNamesState {
    StoredNamesState {
        names: state
            .names
            .iter()
            .map(|(name, record)| (name.clone(), record.clone()))
            .collect(),
        pending: state
            .pending
            .iter()
            .map(|(commitment, position)| (*commitment, *position))
            .collect(),
        recent_spent: state
            .recent_spent
            .iter()
            .map(|(tag, height)| (*tag, *height))
            .collect(),
    }
}

fn restore_names_state(
    stored: StoredNamesState,
    deployment: &DeploymentParameters,
    tip_height: u32,
) -> Result<CoppiceState, NamesRuntimeSnapshotError> {
    if has_duplicate_or_unsorted_keys(&stored.names)
        || has_duplicate_or_unsorted_keys(&stored.pending)
        || has_duplicate_or_unsorted_keys(&stored.recent_spent)
    {
        return Err(NamesRuntimeSnapshotError::InvalidState);
    }
    let names = stored.names.into_iter().collect::<BTreeMap<_, _>>();
    let pending = stored.pending.into_iter().collect::<BTreeMap<_, _>>();
    let recent_spent = stored.recent_spent.into_iter().collect::<BTreeMap<_, _>>();
    let state = CoppiceState::from_authoritative_parts(names, pending, recent_spent)
        .map_err(|_| NamesRuntimeSnapshotError::InvalidState)?;
    validate_names_state_shape(&state, deployment, tip_height)?;
    Ok(state)
}

/// Validates the complete persisted Names state shape at one canonical tip.
/// This helper is shared by current and rewound states so undo validation
/// cannot silently accept a state that ordinary snapshot loading would reject.
fn validate_names_state_shape(
    state: &CoppiceState,
    deployment: &DeploymentParameters,
    tip_height: u32,
) -> Result<(), NamesRuntimeSnapshotError> {
    if state.names.iter().any(|(name, record)| {
        !crate::envelope::valid_name(name)
            || crate::owner::parse_v1_owner_key(record.owner_pk).is_err()
            || reveal::canonical_v1_address(&record.address, deployment).is_err()
            || matches!(
                record.status,
                NameStatus::Released { terminal_height: 0 }
                    | NameStatus::BondSpent { terminal_height: 0 }
            )
    }) || state.pending.values().any(|position| {
        position.block_height < deployment.activation_height || position.block_height > tip_height
    }) {
        return Err(NamesRuntimeSnapshotError::InvalidState);
    }

    let retention_floor = recent_spent::oldest_retained_height(
        deployment.activation_height,
        tip_height,
        deployment.bond_note_max_age_blocks,
        deployment.commit_ttl_blocks,
    )
    .map_err(|_| NamesRuntimeSnapshotError::InvalidState)?;
    if state
        .recent_spent
        .values()
        .any(|height| *height < retention_floor || *height > tip_height)
    {
        return Err(NamesRuntimeSnapshotError::InvalidState);
    }

    // Rebuilding the authoritative index must reproduce the complete state,
    // including the private active-bond index used by transition validation.
    let rebuilt = CoppiceState::from_authoritative_parts(
        state.names.clone(),
        state.pending.clone(),
        state.recent_spent.clone(),
    )
    .map_err(|_| NamesRuntimeSnapshotError::InvalidState)?;
    if rebuilt != *state {
        return Err(NamesRuntimeSnapshotError::InvalidState);
    }
    Ok(())
}

fn validate_names_core_history_boundary(
    names: &NamesApplication,
    core: &CoreRuntime,
) -> Result<(), NamesRuntimeSnapshotError> {
    if names.oldest_rewind_height() != core.oldest_rewind_height() {
        return Err(NamesRuntimeSnapshotError::InvalidHistory);
    }
    let height = names.oldest_rewind_height();
    let names_tip = names
        .retained_tip_at(height)
        .ok_or(NamesRuntimeSnapshotError::InvalidHistory)?;
    let core_tip = core
        .retained_tip_at(height)
        .ok_or(NamesRuntimeSnapshotError::InvalidHistory)?;
    if names_tip.height != core_tip.height || names_tip.block_hash != core_tip.block_hash {
        return Err(NamesRuntimeSnapshotError::InvalidHistory);
    }
    Ok(())
}

fn validate_names_core_position(
    names_tip: ApplicationTip,
    core: &CoreRuntime,
) -> Result<(), NamesRuntimeSnapshotError> {
    let core_tip = core.tip();
    if names_tip.height != core_tip.height || names_tip.block_hash != core_tip.block_hash {
        return Err(NamesRuntimeSnapshotError::TipMismatch);
    }
    Ok(())
}

fn has_duplicate_or_unsorted_keys<K: Ord, V>(values: &[(K, V)]) -> bool {
    values.windows(2).any(|pair| pair[0].0 >= pair[1].0)
}

fn calculate_state_root(
    deployment: &DeploymentParameters,
    deployment_id: NamesDeploymentId,
    state: &CoppiceState,
    tip: ApplicationTip,
    checkpoint: CoreIronwoodCheckpoint,
) -> Result<[u8; 32], NamesRuntimeInitializationError> {
    let oldest_retained_height = recent_spent::oldest_retained_height(
        deployment.activation_height,
        tip.height,
        deployment.bond_note_max_age_blocks,
        deployment.commit_ttl_blocks,
    )
    .map_err(|_| NamesRuntimeInitializationError::ArithmeticOverflow)?;
    let name_tree_root = state
        .name_tree_root()
        .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)?;
    let pending_root = state
        .pending_root()
        .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)?;
    let recent_spent_root = state
        .recent_spent_root(oldest_retained_height)
        .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)?;
    state_root::state_root(&StateRootInput {
        deployment_id: deployment_id.to_bytes(),
        height: tip.height,
        block_hash: tip.block_hash,
        ironwood_tree_size: checkpoint.tree_size,
        ironwood_root: checkpoint.root,
        name_tree_root,
        pending_root,
        recent_spent_root,
    })
    .map_err(|_| NamesRuntimeInitializationError::StateInvariantFailure)
}

fn map_state_fatal(_error: StateMutationError) -> NamesApplicationError {
    NamesApplicationError::StateInvariantFailure
}

fn map_reveal_rejection(
    error: RevealValidationError,
) -> Result<NamesProtocolRejection, NamesApplicationError> {
    Ok(match error {
        RevealValidationError::InvalidName => NamesProtocolRejection::InvalidName,
        RevealValidationError::InvalidOwnerKey => NamesProtocolRejection::InvalidOwnerKey,
        RevealValidationError::InvalidAddress
        | RevealValidationError::WrongAddressNetwork
        | RevealValidationError::NonCanonicalAddress
        | RevealValidationError::AddressTooLong => NamesProtocolRejection::InvalidAddress,
        RevealValidationError::CommitmentNotPending => NamesProtocolRejection::UnknownCommitment,
        RevealValidationError::CommitmentNotMature => NamesProtocolRejection::CommitmentNotMature,
        RevealValidationError::CommitmentExpired => NamesProtocolRejection::CommitmentExpired,
        RevealValidationError::NameNotClaimable => NamesProtocolRejection::NameUnavailable,
        RevealValidationError::CommitPredatesClaimability => {
            NamesProtocolRejection::CommitPredatesClaimEpoch
        }
        RevealValidationError::BondAlreadySpent => NamesProtocolRejection::BondRecentlySpent,
        RevealValidationError::BondAlreadyInUse => NamesProtocolRejection::BondAlreadyInUse,
        RevealValidationError::InvalidAnchorHeight => {
            NamesProtocolRejection::InvalidBondAnchorHeight
        }
        RevealValidationError::AnchorCheckpointMismatch
        | RevealValidationError::FreshnessCheckpointMismatch => {
            NamesProtocolRejection::UnknownBondAnchor
        }
        RevealValidationError::ProofTooLarge => NamesProtocolRejection::OversizedProof,
        RevealValidationError::InvalidPublicInput | RevealValidationError::InvalidProof => {
            NamesProtocolRejection::InvalidBondProof
        }
        RevealValidationError::UnsupportedOperation => NamesProtocolRejection::MalformedOperation,
        RevealValidationError::DeploymentEncoding(_)
        | RevealValidationError::VerifierIdentityMismatch => {
            return Err(NamesApplicationError::StateInvariantFailure);
        }
        RevealValidationError::ArithmeticOverflow => {
            return Err(NamesApplicationError::ArithmeticOverflow);
        }
    })
}

fn map_undo<K: Ord + Clone, V: Clone + PartialEq>(
    before: &BTreeMap<K, V>,
    after: &BTreeMap<K, V>,
) -> Vec<(K, Option<V>)> {
    before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|key| {
            (before.get(&key) != after.get(&key)).then(|| (key.clone(), before.get(&key).cloned()))
        })
        .collect()
}

fn apply_map_undo<K: Ord + Clone, V: Clone>(target: &mut BTreeMap<K, V>, undo: &[(K, Option<V>)]) {
    for (key, value) in undo {
        match value {
            Some(value) => {
                target.insert(key.clone(), value.clone());
            }
            None => {
                target.remove(key);
            }
        }
    }
}
