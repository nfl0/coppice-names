//! Coppice Core application-host adapter for Names v1.
//!
//! This module is deliberately a thin lifecycle layer. The [`V1StateMachine`]
//! remains the only Names transition authority; Core supplies canonical order,
//! authenticated Ironwood effects, routing, and reorg boundaries.

use std::sync::Arc;

use coppice::application::{
    ApplicationBlockContext, ApplicationDescriptor, ApplicationKey, ApplicationSnapshot,
    ApplicationSnapshotValidationError, CoppiceApplication, PersistedCoppiceApplication,
};

use super::{
    AppliedBlock, ApplyError, CanonicalBlock, ChainTip, CommitRef, LeaseParameterError,
    MachineSnapshotError, NameId, NameState, ResolutionStatus, V1Parameters, V1StateMachine,
    V1StateProofVerifier,
    operation::ActionViewError,
    resolver::CanonicalSource,
    resolver::{FreshResolver, ResolutionResult, ResolveError},
};

/// The routed application version for the Names v1 wire protocol.
pub const NAMES_APPLICATION_VERSION: u16 = 1;
/// The opaque Names application-checkpoint format version.
pub const NAMES_APPLICATION_SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// Errors while constructing an empty Names application at a pre-activation
/// Core tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesApplicationConfigError {
    InvalidParameters(LeaseParameterError),
    ZeroRewindRetention,
}

/// Errors while adapting a canonical Core block into Names replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesApplicationApplyError {
    /// Core effects could not be represented by the exact Names action view.
    CanonicalActionView(ActionViewError),
    /// An active/pre-activation position violated Names machine continuity.
    Machine(ApplyError),
    /// An active application context did not contain its required canonical
    /// block view. This can only arise from a manually malformed host context.
    MissingActiveContext,
}

impl From<ApplyError> for NamesApplicationApplyError {
    fn from(error: ApplyError) -> Self {
        Self::Machine(error)
    }
}

/// Errors while rewinding the application-owned bounded undo journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesApplicationRewindError {
    /// The requested height is outside the retained application journal.
    OutsideRetention,
    /// A retained prior machine state was unexpectedly absent.
    MissingHistory,
    /// A retained journal entry failed its internal tip continuity check.
    InvalidHistory,
}

/// Errors while loading a Names application checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesApplicationSnapshotError {
    Encoding,
    Machine(MachineSnapshotError),
    Metadata(ApplicationSnapshotValidationError),
    ParameterMismatch,
    /// A checkpoint that omits the in-memory undo journal advertised an older
    /// rewind point than the state it actually contains.
    InvalidRewindBoundary,
}

/// The result returned to a host after one canonical block is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamesApplicationBlockOutput {
    pub tip: ChainTip,
    pub active: bool,
    pub replay: Option<AppliedBlock>,
}

/// Names v1 hosted as one statically composed Coppice application.
///
/// `proofs` is held behind `Arc` so the application can satisfy Core's
/// clone-before-apply atomicity without requiring a proof-verifier-specific
/// `Clone` implementation. It is never included in application state or
/// snapshot fingerprints.
pub struct NamesApplication<P> {
    machine: V1StateMachine,
    proofs: Arc<P>,
    rewind_retention_blocks: u32,
    /// Each entry is the complete application state immediately before one
    /// successful block. The journal is an acceleration aid; checkpoints
    /// intentionally persist only the current machine and can rebuild from
    /// the authenticated activation boundary after a restart.
    history: Vec<(ChainTip, V1StateMachine)>,
}

impl<P> Clone for NamesApplication<P> {
    fn clone(&self) -> Self {
        Self {
            machine: self.machine.clone(),
            proofs: Arc::clone(&self.proofs),
            rewind_retention_blocks: self.rewind_retention_blocks,
            history: self.history.clone(),
        }
    }
}

impl<P> NamesApplication<P>
where
    P: V1StateProofVerifier,
{
    /// Creates an empty application at an arbitrary canonical tip before its
    /// Names activation height. The host should pass the Core runtime tip so
    /// the application can join an already-running pre-activation runtime.
    pub fn new(
        params: V1Parameters,
        initial_tip: ChainTip,
        proofs: Arc<P>,
        rewind_retention_blocks: u32,
    ) -> Result<Self, NamesApplicationConfigError> {
        if rewind_retention_blocks == 0 {
            return Err(NamesApplicationConfigError::ZeroRewindRetention);
        }
        let machine = V1StateMachine::from_pre_activation_tip(params, initial_tip)
            .map_err(NamesApplicationConfigError::InvalidParameters)?;
        Ok(Self {
            machine,
            proofs,
            rewind_retention_blocks,
            history: Vec::new(),
        })
    }

    /// Convenience constructor for the usual activation-checkpoint start.
    pub fn from_activation_parent(
        params: V1Parameters,
        parent_block_hash: [u8; 32],
        proofs: Arc<P>,
        rewind_retention_blocks: u32,
    ) -> Result<Self, NamesApplicationConfigError> {
        Self::new(
            params,
            ChainTip {
                height: params.activation_height.saturating_sub(1),
                block_hash: parent_block_hash,
            },
            proofs,
            rewind_retention_blocks,
        )
    }

    /// Returns the application-owned state machine.
    pub fn state_machine(&self) -> &V1StateMachine {
        &self.machine
    }

    /// Returns the verifier shared by cloned hosted instances.
    pub fn proofs(&self) -> &P {
        self.proofs.as_ref()
    }

    pub const fn params(&self) -> V1Parameters {
        self.machine.params()
    }

    pub fn head(&self, name_id: NameId) -> Option<&NameState> {
        self.machine.head(name_id)
    }

    pub fn pending(&self, commitment: [u8; 32]) -> Option<CommitRef> {
        self.machine.pending(commitment)
    }

    pub fn resolution_at(&self, name_id: NameId, height: u32) -> ResolutionStatus {
        self.machine.resolution_at(name_id, height)
    }

    /// Constructs the existing bounded exact-name resolver with this
    /// application's parameters and verifier. The supplied source remains
    /// the canonical authority; no application index or checkpoint is used.
    pub fn fresh_resolver(&self) -> Result<FreshResolver, ResolveError> {
        FreshResolver::new(self.params())
    }

    /// Resolves one exact name through the existing bounded canonical-source
    /// path. Full directory state remains the responsibility of replay.
    pub fn resolve_fresh<S: CanonicalSource>(
        &self,
        name: &str,
        source: &S,
    ) -> Result<ResolutionResult, ResolveError> {
        self.fresh_resolver()?
            .resolve(name, source, self.proofs.as_ref())
    }

    /// Restores a locally persisted checkpoint after checking the payload and
    /// envelope's internal consistency. This does not establish canonicality;
    /// a host that knows the Core activation height should use
    /// [`Self::from_snapshot_at_runtime`] before composing the runtime.
    pub fn from_snapshot(
        snapshot: ApplicationSnapshot,
        proofs: Arc<P>,
        rewind_retention_blocks: u32,
    ) -> Result<Self, NamesApplicationSnapshotError> {
        Self::restore_snapshot(snapshot, proofs, rewind_retention_blocks, None)
    }

    /// Restores a checkpoint and validates its common metadata against the
    /// actual Core runtime activation boundary. The runtime activation height
    /// is intentionally supplied by the host; Names does not infer or own it.
    pub fn from_snapshot_at_runtime(
        snapshot: ApplicationSnapshot,
        proofs: Arc<P>,
        rewind_retention_blocks: u32,
        runtime_activation_height: u32,
    ) -> Result<Self, NamesApplicationSnapshotError> {
        Self::restore_snapshot(
            snapshot,
            proofs,
            rewind_retention_blocks,
            Some(runtime_activation_height),
        )
    }

    fn restore_snapshot(
        snapshot: ApplicationSnapshot,
        proofs: Arc<P>,
        rewind_retention_blocks: u32,
        runtime_activation_height: Option<u32>,
    ) -> Result<Self, NamesApplicationSnapshotError> {
        if rewind_retention_blocks == 0 {
            return Err(NamesApplicationSnapshotError::InvalidRewindBoundary);
        }
        let machine = V1StateMachine::from_snapshot_bytes(&snapshot.payload)
            .map_err(NamesApplicationSnapshotError::Machine)?;
        let application = Self {
            machine,
            proofs,
            rewind_retention_blocks,
            history: Vec::new(),
        };
        if let Some(runtime_activation_height) = runtime_activation_height {
            application.validate_snapshot_for_runtime(&snapshot, runtime_activation_height)?;
        } else {
            Self::validate_snapshot_envelope(
                &snapshot,
                application.snapshot_format_version(),
                application.descriptor(),
                application.tip(),
                Self::snapshot_state_root(&application.machine),
            )?;
        }
        if snapshot.oldest_rewind_height != application.tip().height {
            return Err(NamesApplicationSnapshotError::InvalidRewindBoundary);
        }
        Ok(application)
    }

    fn snapshot_state_root(machine: &V1StateMachine) -> [u8; 32] {
        let bytes = machine
            .snapshot_bytes()
            .expect("validated Names state is serializable");
        // This is a persistence fingerprint only. It is not a Names protocol
        // root, a global application commitment, or a proof input.
        super::state::hash_bytes("CoppiceN1Snap", &bytes)
    }

    /// Validates the common snapshot envelope against the host's actual Core
    /// runtime. This is separate from application payload decoding so a local
    /// checkpoint never becomes evidence of canonical applicability.
    pub fn validate_snapshot_for_runtime(
        &self,
        snapshot: &ApplicationSnapshot,
        runtime_activation_height: u32,
    ) -> Result<(), NamesApplicationSnapshotError> {
        snapshot
            .validate_for(
                self.snapshot_format_version(),
                self.descriptor(),
                runtime_activation_height,
                self.tip(),
                Self::snapshot_state_root(&self.machine),
            )
            .map_err(NamesApplicationSnapshotError::Metadata)
    }

    fn validate_snapshot_envelope(
        snapshot: &ApplicationSnapshot,
        expected_format_version: u32,
        expected_descriptor: ApplicationDescriptor,
        expected_tip: coppice::application::ApplicationTip,
        expected_state_root: [u8; 32],
    ) -> Result<(), NamesApplicationSnapshotError> {
        if snapshot.format_version != expected_format_version {
            return Err(NamesApplicationSnapshotError::Metadata(
                ApplicationSnapshotValidationError::UnsupportedFormat {
                    expected: expected_format_version,
                    actual: snapshot.format_version,
                },
            ));
        }
        if snapshot.descriptor != expected_descriptor {
            return Err(NamesApplicationSnapshotError::Metadata(
                ApplicationSnapshotValidationError::DescriptorMismatch,
            ));
        }
        if snapshot.tip != expected_tip {
            return Err(NamesApplicationSnapshotError::Metadata(
                ApplicationSnapshotValidationError::TipMismatch,
            ));
        }
        if snapshot.state_root != expected_state_root {
            return Err(NamesApplicationSnapshotError::Metadata(
                ApplicationSnapshotValidationError::StateRootMismatch,
            ));
        }
        Ok(())
    }

    fn push_history(&mut self, prior: V1StateMachine) {
        self.history.push((prior.tip(), prior));
        let retention = usize::try_from(self.rewind_retention_blocks).unwrap_or(usize::MAX);
        if self.history.len() > retention {
            let excess = self.history.len() - retention;
            self.history.drain(..excess);
        }
    }

    fn tip_as_chain_tip(tip: coppice::application::ApplicationTip) -> ChainTip {
        ChainTip {
            height: tip.height,
            block_hash: tip.block_hash,
        }
    }
}

impl<P> CoppiceApplication for NamesApplication<P>
where
    P: V1StateProofVerifier,
{
    type BlockOutput = NamesApplicationBlockOutput;
    type ApplyError = NamesApplicationApplyError;
    type RewindError = NamesApplicationRewindError;

    fn descriptor(&self) -> ApplicationDescriptor {
        ApplicationDescriptor {
            key: ApplicationKey::new(super::names_application_id(), NAMES_APPLICATION_VERSION),
            activation_height: self.params().activation_height,
        }
    }

    fn tip(&self) -> coppice::application::ApplicationTip {
        self.machine.tip().into()
    }

    fn state_root(&self) -> [u8; 32] {
        Self::snapshot_state_root(&self.machine)
    }

    fn apply_block(
        &mut self,
        block: &ApplicationBlockContext,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        let mut next = self.clone();
        let prior = next.machine.clone();
        let replay = if block.is_active() {
            let canonical = CanonicalBlock::from_application_context(block)
                .map_err(NamesApplicationApplyError::CanonicalActionView)?
                .ok_or(NamesApplicationApplyError::MissingActiveContext)?;
            Some(
                next.machine
                    .apply_block(&canonical, next.proofs.as_ref())
                    .map_err(NamesApplicationApplyError::Machine)?,
            )
        } else {
            next.machine
                .advance_pre_activation(Self::tip_as_chain_tip(block.tip()))
                .map_err(NamesApplicationApplyError::Machine)?;
            None
        };
        next.push_history(prior);
        let output = NamesApplicationBlockOutput {
            tip: next.machine.tip(),
            active: block.is_active(),
            replay,
        };
        *self = next;
        Ok(output)
    }

    fn rewind_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        if height < self.oldest_rewind_height() || height > self.machine.tip().height {
            return Err(NamesApplicationRewindError::OutsideRetention);
        }
        let mut next = self.clone();
        while next.machine.tip().height > height {
            let current_tip = next.machine.tip();
            let (prior_tip, prior_machine) = next
                .history
                .pop()
                .ok_or(NamesApplicationRewindError::MissingHistory)?;
            if prior_tip != prior_machine.tip()
                || prior_tip.height.checked_add(1) != Some(current_tip.height)
            {
                return Err(NamesApplicationRewindError::InvalidHistory);
            }
            next.machine = prior_machine;
        }
        if next.machine.tip().height != height {
            return Err(NamesApplicationRewindError::InvalidHistory);
        }
        *self = next;
        Ok(())
    }

    fn rewind_retention_blocks(&self) -> u32 {
        self.rewind_retention_blocks
    }

    fn oldest_rewind_height(&self) -> u32 {
        self.history
            .first()
            .map_or(self.machine.tip().height, |(tip, _)| tip.height)
    }

    fn retained_tip_at(&self, height: u32) -> Option<coppice::application::ApplicationTip> {
        if height == self.machine.tip().height {
            return Some(self.tip());
        }
        self.history
            .iter()
            .find(|(tip, _)| tip.height == height)
            .map(|(tip, _)| (*tip).into())
    }
}

impl<P> PersistedCoppiceApplication for NamesApplication<P>
where
    P: V1StateProofVerifier,
{
    type SnapshotError = NamesApplicationSnapshotError;

    fn snapshot_format_version(&self) -> u32 {
        NAMES_APPLICATION_SNAPSHOT_FORMAT_VERSION
    }

    fn save_application_payload(&self) -> Result<Vec<u8>, Self::SnapshotError> {
        self.machine
            .snapshot_bytes()
            .map_err(NamesApplicationSnapshotError::Machine)
    }

    fn save_application_snapshot(&self) -> Result<ApplicationSnapshot, Self::SnapshotError> {
        // The payload is a restart checkpoint and intentionally does not
        // serialize the in-memory undo journal. Do not advertise a rewind
        // point that a restored application cannot actually serve.
        Ok(ApplicationSnapshot {
            format_version: self.snapshot_format_version(),
            descriptor: self.descriptor(),
            tip: self.tip(),
            state_root: self.state_root(),
            oldest_rewind_height: self.tip().height,
            payload: self.save_application_payload()?,
        })
    }

    fn load_application_payload(
        &mut self,
        snapshot: ApplicationSnapshot,
    ) -> Result<(), Self::SnapshotError> {
        let candidate = V1StateMachine::from_snapshot_bytes(&snapshot.payload)
            .map_err(NamesApplicationSnapshotError::Machine)?;
        if candidate.params() != self.params() {
            return Err(NamesApplicationSnapshotError::ParameterMismatch);
        }
        let candidate_tip = candidate.tip();
        let candidate_root = Self::snapshot_state_root(&candidate);
        Self::validate_snapshot_envelope(
            &snapshot,
            self.snapshot_format_version(),
            self.descriptor(),
            candidate_tip.into(),
            candidate_root,
        )?;
        if snapshot.oldest_rewind_height != candidate_tip.height {
            return Err(NamesApplicationSnapshotError::InvalidRewindBoundary);
        }
        self.machine = candidate;
        self.history.clear();
        Ok(())
    }
}

impl From<ChainTip> for coppice::application::ApplicationTip {
    fn from(tip: ChainTip) -> Self {
        Self {
            height: tip.height,
            block_hash: tip.block_hash,
        }
    }
}

impl From<coppice::application::ApplicationTip> for ChainTip {
    fn from(tip: coppice::application::ApplicationTip) -> Self {
        Self {
            height: tip.height,
            block_hash: tip.block_hash,
        }
    }
}

#[cfg(test)]
#[path = "tests/application.rs"]
mod tests;
