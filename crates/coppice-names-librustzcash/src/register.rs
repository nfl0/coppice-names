//! Wallet-local Coppice v1 registration workflow preparation.
//!
//! This module stops at canonical carrier frames. Transaction construction,
//! broadcast, chain discovery, key storage, and persistence belong to the host
//! wallet.

use std::{convert::Infallible, fmt::Debug};

use coppice::{
    bond::V1BondProver,
    config::DeploymentValidationError,
    envelope::{self, Operation},
    names_application::{NamesApplicationEnvelopeError, encode_names_v1_envelope},
    names_runtime::NamesRuntime,
    owner::{name_id, owner_key_bytes, parse_v1_owner_key},
    owner_kdf::{OwnerKdfError, derive_v1_owner_verification_key},
    pending::PendingTimingError,
    record::{NameRecord, NameStatus},
    registration::registration_commitment,
    reveal::{RevealValidationError, canonical_v1_address},
    state::CoppiceState,
};
use coppice_core::{identity::CoreRuntimeId, transport};
use rand_core::{CryptoRng, RngCore};

use crate::{
    BondNoteSelectionPolicy, CoppiceLockBackend, ExactCanonicalTipError, FreshnessContextError,
    HostCanonicalTipSource, InventoryError, IronwoodOutputId, IronwoodViewingCapability,
    IronwoodWitnessSource, PendingRegistration, PendingRegistrationCollection,
    PendingRegistrationCollectionError, ReconciliationError, ResolveWitnessError, SelectedBondNote,
    WalletBondPrivateMaterial, WalletBondProverError, active_canonical_bond_tags,
    choose_current_anchor, freshness_for_canonical_commit, freshness_for_next_block_commit,
    inventory::classify_notes, prove_selected_bond, reconcile_locks, require_exact_canonical_tip,
    resolve_canonical_ironwood_witness, select_fresh_bond_note_with_policy,
};

/// Exact canonical operation bytes and index-ordered v1 memo frames.
///
/// This intentionally has no `Debug`: REVEAL bytes contain the registration
/// secret before publication.
pub struct PreparedCarrier {
    operation_payload: Vec<u8>,
    application_envelope: Vec<u8>,
    frames: Vec<[u8; 512]>,
}

impl PreparedCarrier {
    /// Exact frozen Coppice Names v1 operation bytes.
    pub fn payload(&self) -> &[u8] {
        &self.operation_payload
    }

    /// Exact CA01 application envelope carried by CPV1.
    pub fn application_envelope(&self) -> &[u8] {
        &self.application_envelope
    }

    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
    }

    pub(crate) fn from_operation(
        runtime_id: CoreRuntimeId,
        operation: &Operation,
    ) -> Result<Self, CarrierPreparationError> {
        let operation_payload = envelope::encode_operation(operation)
            .map_err(CarrierPreparationError::OperationEncoding)?;
        let application_envelope = encode_names_v1_envelope(operation)
            .map_err(CarrierPreparationError::ApplicationEnvelope)?;
        let frames = transport::encode_frames(runtime_id.to_bytes(), &application_envelope)
            .map_err(CarrierPreparationError::Framing)?;
        Ok(Self {
            operation_payload,
            application_envelope,
            frames,
        })
    }
}

fn prepare_carrier(
    runtime: &NamesRuntime,
    operation: &Operation,
) -> Result<PreparedCarrier, CarrierPreparationError> {
    PreparedCarrier::from_operation(runtime.core().runtime_id(), operation)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CarrierPreparationError {
    OperationEncoding(envelope::Error),
    ApplicationEnvelope(NamesApplicationEnvelopeError),
    Framing(transport::Error),
}

/// A COMMIT handoff that cannot be obtained until its bond is locked and its
/// local pending intent is present.
pub struct PreparedCommit {
    pub commitment: [u8; 32],
    pub selected_bond: SelectedBondNote,
    pub owner_pk: [u8; 32],
    carrier: PreparedCarrier,
}

impl PreparedCommit {
    pub fn carrier(&self) -> &PreparedCarrier {
        &self.carrier
    }
}

/// Public REVEAL preparation metadata and the secret-bearing carrier.
pub struct PreparedReveal {
    pub commitment: [u8; 32],
    pub anchor_height: u32,
    pub bond_tag: [u8; 32],
    pub position_floor: u32,
    pub proof_len: usize,
    carrier: PreparedCarrier,
}

impl PreparedReveal {
    pub fn carrier(&self) -> &PreparedCarrier {
        &self.carrier
    }
}

/// Registration owner choice. Default-software key material is transient and
/// is never retained in pending metadata.
pub enum RegistrationOwner<'a> {
    External([u8; 32]),
    DefaultSoftware(&'a [u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationStage {
    Prepared,
    CommitBroadcast,
    /// The semantic commitment exists in the last observed canonical runtime
    /// state, independently of which transaction carried it.
    CommitCanonical,
}

pub fn registration_stage(pending: &PendingRegistration) -> RegistrationStage {
    match (pending.commit_txid(), pending.commit_height()) {
        (_, Some(_)) => RegistrationStage::CommitCanonical,
        (Some(_), None) => RegistrationStage::CommitBroadcast,
        (None, None) => RegistrationStage::Prepared,
    }
}

#[derive(Debug)]
pub enum BeginRegistrationError<HostError, BackendError: Debug> {
    Tip(ExactCanonicalTipError<HostError>),
    InvalidDeployment(DeploymentValidationError),
    InvalidName,
    InvalidAddress(RevealValidationError),
    CommitHeightOverflow,
    Freshness(FreshnessContextError),
    Inventory(BackendError),
    Selection(InventoryError),
    NoEligibleBond,
    InvalidExternalOwner,
    OwnerDerivation(OwnerKdfError),
    Commitment(coppice::config::DeploymentEncodingError),
    PendingValidation(crate::PendingRegistrationValidationError),
    Carrier(CarrierPreparationError),
    Lock(BackendError),
    /// The lock is deliberately left in place. Reconciliation can safely
    /// remove it because no local-pending or canonical-active tag desires it.
    PendingInsertionAfterLock(PendingRegistrationCollectionError),
}

#[allow(clippy::too_many_arguments)]
pub fn begin_registration<Host, Backend, R>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending_collection: &mut PendingRegistrationCollection,
    account_id: crate::WalletAccountId,
    capability: IronwoodViewingCapability,
    lock_backend: &mut Backend,
    name: &str,
    canonical_address: &[u8],
    owner_choice: RegistrationOwner<'_>,
    rng: R,
) -> Result<PreparedCommit, BeginRegistrationError<Host::Error, Backend::Error>>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
    R: RngCore + CryptoRng,
{
    begin_registration_with_policy(
        host_tip_source,
        runtime,
        pending_collection,
        account_id,
        capability,
        BondNoteSelectionPolicy::ExactMinimum,
        lock_backend,
        name,
        canonical_address,
        owner_choice,
        rng,
    )
}

/// Begins registration with an explicit bond-note selection policy.
///
/// The default [`begin_registration`] path accepts only an exact-minimum
/// eligible note. Callers may use [`BondNoteSelectionPolicy::AllowLarger`]
/// only when the user has explicitly chosen larger-than-minimum bonding.
#[allow(clippy::too_many_arguments)]
pub fn begin_registration_with_policy<Host, Backend, R>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending_collection: &mut PendingRegistrationCollection,
    account_id: crate::WalletAccountId,
    capability: IronwoodViewingCapability,
    bond_policy: BondNoteSelectionPolicy,
    lock_backend: &mut Backend,
    name: &str,
    canonical_address: &[u8],
    owner_choice: RegistrationOwner<'_>,
    mut rng: R,
) -> Result<PreparedCommit, BeginRegistrationError<Host::Error, Backend::Error>>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
    R: RngCore + CryptoRng,
{
    require_exact_canonical_tip(host_tip_source, runtime).map_err(BeginRegistrationError::Tip)?;
    let deployment = runtime.deployment();
    deployment
        .validate()
        .map_err(BeginRegistrationError::InvalidDeployment)?;
    let name = envelope::normalize_name(name).map_err(|_| BeginRegistrationError::InvalidName)?;
    let address = canonical_v1_address(canonical_address, deployment)
        .map_err(BeginRegistrationError::InvalidAddress)?;
    if address != canonical_address {
        return Err(BeginRegistrationError::InvalidAddress(
            RevealValidationError::NonCanonicalAddress,
        ));
    }
    let commit_height = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or(BeginRegistrationError::CommitHeightOverflow)?;
    let freshness = freshness_for_next_block_commit(runtime, commit_height)
        .map_err(BeginRegistrationError::Freshness)?;
    let notes = lock_backend
        .owned_unspent_ironwood_notes()
        .map_err(BeginRegistrationError::Inventory)?;
    let selected_bond = select_fresh_bond_note_with_policy(
        &notes,
        deployment.minimum_bond_value,
        capability,
        &freshness,
        bond_policy,
    )
    .map_err(BeginRegistrationError::Selection)?
    .ok_or(BeginRegistrationError::NoEligibleBond)?;
    let owner_pk = match owner_choice {
        RegistrationOwner::External(bytes) => {
            parse_v1_owner_key(bytes).map_err(|_| BeginRegistrationError::InvalidExternalOwner)?;
            bytes
        }
        RegistrationOwner::DefaultSoftware(spending_key) => owner_key_bytes(
            &derive_v1_owner_verification_key(
                *spending_key,
                runtime.names_deployment_id().to_bytes(),
                name_id(&name),
                selected_bond.bond_tag,
            )
            .map_err(BeginRegistrationError::OwnerDerivation)?,
        ),
    };
    let mut secret = [0; 32];
    rng.fill_bytes(&mut secret);
    let commitment = registration_commitment(
        deployment,
        &name,
        owner_pk,
        selected_bond.bond_tag,
        &address,
        secret,
    )
    .map_err(BeginRegistrationError::Commitment)?;
    let pending = PendingRegistration::new(
        deployment,
        account_id,
        name,
        address,
        owner_pk,
        selected_bond.bond_tag,
        secret,
        commitment,
    )
    .map_err(BeginRegistrationError::PendingValidation)?;
    let carrier = prepare_carrier(runtime, &Operation::Commit { commitment })
        .map_err(BeginRegistrationError::Carrier)?;

    lock_backend
        .ensure_coppice_lock(
            &selected_bond.output_id,
            selected_bond.bond_tag,
            lock_backend.max_lock_expiry_height(),
        )
        .map_err(BeginRegistrationError::Lock)?;
    pending_collection
        .insert(pending)
        .map_err(BeginRegistrationError::PendingInsertionAfterLock)?;
    Ok(PreparedCommit {
        commitment,
        selected_bond,
        owner_pk,
        carrier,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitTransitionError {
    UnknownCommitment,
    Pending(PendingRegistrationCollectionError),
}

pub fn record_commit_broadcast(
    pending: &mut PendingRegistrationCollection,
    commitment: &[u8; 32],
    txid: [u8; 32],
) -> Result<(), CommitTransitionError> {
    pending
        .mark_commit_broadcast(commitment, txid)
        .map_err(|error| match error {
            PendingRegistrationCollectionError::UnknownCommitment => {
                CommitTransitionError::UnknownCommitment
            }
            other => CommitTransitionError::Pending(other),
        })
}

/// Observes the semantic commitment in the current canonical runtime state.
/// The runtime's `ChainPosition`, not this wallet's broadcast txid, supplies
/// the cached height. Repeated observations follow reorg height changes.
pub fn observe_canonical_commit<Host: HostCanonicalTipSource>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending: &mut PendingRegistrationCollection,
    commitment: &[u8; 32],
) -> Result<u32, ObserveCanonicalCommitError<Host::Error>> {
    require_exact_canonical_tip(host_tip_source, runtime)
        .map_err(ObserveCanonicalCommitError::Tip)?;
    if pending.get(commitment).is_none() {
        return Err(ObserveCanonicalCommitError::UnknownCommitment);
    }
    let height = canonical_commit_height(runtime.state(), commitment)
        .map_err(|_| ObserveCanonicalCommitError::CanonicalCommitMissing)?;
    pending
        .observe_canonical_commit_height(commitment, height)
        .map_err(ObserveCanonicalCommitError::Pending)?;
    Ok(height)
}

/// Reconciles every local canonical-COMMIT cache entry bidirectionally with
/// the current authenticated runtime state. A reorg that removes a commitment
/// clears the cached height instead of leaving a misleading canonical stage.
pub fn reconcile_canonical_commit_cache(
    runtime: &NamesRuntime,
    pending: &mut PendingRegistrationCollection,
) -> Result<(), PendingRegistrationCollectionError> {
    let commitments = pending.commitments().collect::<Vec<_>>();
    for commitment in commitments {
        match runtime.state().pending.get(&commitment) {
            Some(position) => {
                pending.observe_canonical_commit_height(&commitment, position.block_height)?
            }
            None => pending.clear_canonical_commit_height(&commitment)?,
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum ObserveCanonicalCommitError<HostError> {
    Tip(ExactCanonicalTipError<HostError>),
    UnknownCommitment,
    CanonicalCommitMissing,
    Pending(PendingRegistrationCollectionError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalCommitMissing;

/// Resolves the protocol COMMIT height from canonical runtime state only.
/// Wallet transport metadata is deliberately absent from this API.
pub fn canonical_commit_height(
    state: &CoppiceState,
    commitment: &[u8; 32],
) -> Result<u32, CanonicalCommitMissing> {
    state
        .pending
        .get(commitment)
        .map(|position| position.block_height)
        .ok_or(CanonicalCommitMissing)
}

pub trait RegistrationBondMaterialSource {
    type Error: Debug;

    fn private_material_for(
        &mut self,
        output_id: &IronwoodOutputId,
    ) -> Result<WalletBondPrivateMaterial, Self::Error>;
}

#[derive(Debug)]
pub enum PrepareRevealError<HostError, BackendError: Debug, WitnessError, MaterialError: Debug> {
    Tip(ExactCanonicalTipError<HostError>),
    UnknownPending,
    Timing(PendingTimingError),
    CommitExpired,
    CanonicalCommitMissing,
    Freshness(FreshnessContextError),
    BondNoLongerFresh { position: u32, position_floor: u32 },
    Reconciliation(ReconciliationError<BackendError>),
    Inventory(BackendError),
    Classification(InventoryError),
    MissingPendingBond,
    AmbiguousBondTag,
    MissingBondPosition,
    Anchor(ResolveWitnessError<Infallible>),
    Witness(ResolveWitnessError<WitnessError>),
    PrivateMaterial(MaterialError),
    BondProof(WalletBondProverError),
    RevealInvariantMismatch,
    Commitment(coppice::config::DeploymentEncodingError),
    Carrier(CarrierPreparationError),
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn prepare_reveal<Host, Backend, Witness, Material, R>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending_collection: &PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    lock_backend: &mut Backend,
    witness_source: &mut Witness,
    private_material_source: &mut Material,
    prover: &V1BondProver,
    commitment: &[u8; 32],
    rng: R,
) -> Result<
    PreparedReveal,
    PrepareRevealError<Host::Error, Backend::Error, Witness::Error, Material::Error>,
>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
    Witness: IronwoodWitnessSource,
    Material: RegistrationBondMaterialSource,
    R: RngCore + CryptoRng,
{
    require_exact_canonical_tip(host_tip_source, runtime).map_err(PrepareRevealError::Tip)?;
    let pending = pending_collection
        .get(commitment)
        .cloned()
        .ok_or(PrepareRevealError::UnknownPending)?;
    let commit_height = canonical_commit_height(runtime.state(), commitment)
        .map_err(|_| PrepareRevealError::CanonicalCommitMissing)?;
    let tip_height = runtime.tip().height;
    if crate::pending_commit_expired(
        commit_height,
        runtime.deployment().commit_ttl_blocks,
        tip_height,
    )
    .map_err(PrepareRevealError::Timing)?
    {
        return Err(PrepareRevealError::CommitExpired);
    }
    let freshness = freshness_for_canonical_commit(runtime, commit_height)
        .map_err(PrepareRevealError::Freshness)?;

    let active_tags = active_canonical_bond_tags(runtime);
    reconcile_locks(
        &active_tags,
        pending_collection,
        pending.account_id(),
        capability,
        lock_backend,
    )
    .map_err(|error| match error {
        ReconciliationError::MissingPendingBond { .. } => PrepareRevealError::MissingPendingBond,
        other => PrepareRevealError::Reconciliation(other),
    })?;
    let notes = lock_backend
        .owned_unspent_ironwood_notes()
        .map_err(PrepareRevealError::Inventory)?;
    let mut matches = classify_notes(&notes, capability)
        .map_err(PrepareRevealError::Classification)?
        .into_iter()
        .filter(|classified| classified.bond_tag == pending.bond_tag());
    let matched = matches
        .next()
        .ok_or(PrepareRevealError::MissingPendingBond)?;
    if matches.next().is_some() {
        return Err(PrepareRevealError::AmbiguousBondTag);
    }
    let position = matched
        .note
        .position
        .ok_or(PrepareRevealError::MissingBondPosition)?;
    if position < freshness.position_floor {
        return Err(PrepareRevealError::BondNoLongerFresh {
            position,
            position_floor: freshness.position_floor,
        });
    }
    let selected = SelectedBondNote {
        output_id: matched.note.output_id,
        value_zat: matched.note.value_zat,
        bond_tag: matched.bond_tag,
        position,
    };
    let anchor =
        choose_current_anchor(runtime, commit_height).map_err(PrepareRevealError::Anchor)?;
    let witness = resolve_canonical_ironwood_witness(
        runtime,
        witness_source,
        selected.position,
        anchor.anchor_height,
    )
    .map_err(PrepareRevealError::Witness)?;
    let private_material = private_material_source
        .private_material_for(&selected.output_id)
        .map_err(PrepareRevealError::PrivateMaterial)?;
    let proof = prove_selected_bond(
        prover,
        runtime.deployment(),
        pending.name(),
        pending.address(),
        pending.owner_pk(),
        selected,
        private_material,
        &freshness,
        &anchor,
        witness,
        rng,
    )
    .map_err(PrepareRevealError::BondProof)?;
    let operation = Operation::Reveal {
        name: pending.name().to_owned(),
        owner_pk: pending.owner_pk(),
        bond_tag: pending.bond_tag(),
        bond_anchor_height: anchor.anchor_height,
        bond_anchor: proof.anchor,
        bond_proof: proof.proof,
        address: pending.address().to_vec(),
        secret: pending.secret(),
    };
    let recomputed = registration_commitment(
        runtime.deployment(),
        pending.name(),
        pending.owner_pk(),
        pending.bond_tag(),
        pending.address(),
        pending.secret(),
    )
    .map_err(PrepareRevealError::Commitment)?;
    if recomputed != pending.commitment() {
        return Err(PrepareRevealError::RevealInvariantMismatch);
    }
    let proof_len = match &operation {
        Operation::Reveal { bond_proof, .. } => bond_proof.len(),
        _ => unreachable!(),
    };
    let carrier = prepare_carrier(runtime, &operation).map_err(PrepareRevealError::Carrier)?;
    Ok(PreparedReveal {
        commitment: pending.commitment(),
        anchor_height: anchor.anchor_height,
        bond_tag: pending.bond_tag(),
        position_floor: freshness.position_floor,
        proof_len,
        carrier,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionMismatch {
    NameMissing,
    NotActive,
    Owner,
    BondTag,
    Address,
    Sequence,
}

pub fn registration_matches_active_record(
    pending: &PendingRegistration,
    record: Option<&NameRecord>,
) -> Result<(), CompletionMismatch> {
    let record = record.ok_or(CompletionMismatch::NameMissing)?;
    if record.status != NameStatus::Active {
        return Err(CompletionMismatch::NotActive);
    }
    if record.owner_pk != pending.owner_pk() {
        return Err(CompletionMismatch::Owner);
    }
    if record.bond_tag != pending.bond_tag() {
        return Err(CompletionMismatch::BondTag);
    }
    if record.address != pending.address() {
        return Err(CompletionMismatch::Address);
    }
    if record.sequence != 0 {
        return Err(CompletionMismatch::Sequence);
    }
    Ok(())
}

#[derive(Debug)]
pub enum LifecycleError<HostError, BackendError: Debug> {
    Tip(ExactCanonicalTipError<HostError>),
    UnknownPending,
    CompletionMismatch(CompletionMismatch),
    CanonicalCommitMissing,
    Timing(PendingTimingError),
    NotExpired,
    Reconciliation(ReconciliationError<BackendError>),
}

fn staged_remove_and_reconcile<Backend: CoppiceLockBackend>(
    runtime: &NamesRuntime,
    pending: &mut PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    lock_backend: &mut Backend,
    commitment: &[u8; 32],
) -> Result<(), LifecycleError<Infallible, Backend::Error>> {
    let account_id = pending
        .get(commitment)
        .ok_or(LifecycleError::UnknownPending)?
        .account_id();
    let mut staged = pending.clone();
    staged
        .remove(commitment)
        .ok_or(LifecycleError::UnknownPending)?;
    reconcile_locks(
        &active_canonical_bond_tags(runtime),
        &staged,
        account_id,
        capability,
        lock_backend,
    )
    .map_err(LifecycleError::Reconciliation)?;
    *pending = staged;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn complete_registration<Host, Backend>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending: &mut PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    lock_backend: &mut Backend,
    commitment: &[u8; 32],
) -> Result<(), LifecycleError<Host::Error, Backend::Error>>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
{
    require_exact_canonical_tip(host_tip_source, runtime).map_err(LifecycleError::Tip)?;
    let local = pending
        .get(commitment)
        .ok_or(LifecycleError::UnknownPending)?;
    registration_matches_active_record(local, runtime.state().names.get(local.name()))
        .map_err(LifecycleError::CompletionMismatch)?;
    staged_remove_and_reconcile(runtime, pending, capability, lock_backend, commitment).map_err(
        |error| match error {
            LifecycleError::UnknownPending => LifecycleError::UnknownPending,
            LifecycleError::Reconciliation(error) => LifecycleError::Reconciliation(error),
            _ => unreachable!(),
        },
    )
}

pub fn abandon_registration<Host, Backend>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending: &mut PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    lock_backend: &mut Backend,
    commitment: &[u8; 32],
) -> Result<(), LifecycleError<Host::Error, Backend::Error>>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
{
    require_exact_canonical_tip(host_tip_source, runtime).map_err(LifecycleError::Tip)?;
    staged_remove_and_reconcile(runtime, pending, capability, lock_backend, commitment).map_err(
        |error| match error {
            LifecycleError::UnknownPending => LifecycleError::UnknownPending,
            LifecycleError::Reconciliation(error) => LifecycleError::Reconciliation(error),
            _ => unreachable!(),
        },
    )
}

pub fn abandon_expired_registration<Host, Backend>(
    host_tip_source: &Host,
    runtime: &NamesRuntime,
    pending: &mut PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    lock_backend: &mut Backend,
    commitment: &[u8; 32],
) -> Result<(), LifecycleError<Host::Error, Backend::Error>>
where
    Host: HostCanonicalTipSource,
    Backend: CoppiceLockBackend,
{
    require_exact_canonical_tip(host_tip_source, runtime).map_err(LifecycleError::Tip)?;
    let local = pending
        .get(commitment)
        .ok_or(LifecycleError::UnknownPending)?;
    let commit_height = canonical_commit_height(runtime.state(), commitment)
        .ok()
        .or(local.commit_height())
        .ok_or(LifecycleError::CanonicalCommitMissing)?;
    if !crate::pending_commit_expired(
        commit_height,
        runtime.deployment().commit_ttl_blocks,
        runtime.tip().height,
    )
    .map_err(LifecycleError::Timing)?
    {
        return Err(LifecycleError::NotExpired);
    }
    staged_remove_and_reconcile(runtime, pending, capability, lock_backend, commitment).map_err(
        |error| match error {
            LifecycleError::UnknownPending => LifecycleError::UnknownPending,
            LifecycleError::Reconciliation(error) => LifecycleError::Reconciliation(error),
            _ => unreachable!(),
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap};

    use coppice::{
        bond::V1BondProver,
        config::{DeploymentParameters, REGTEST, Rendezvous},
        constants::REGTEST_ACTIVATION_HEIGHT,
        names_runtime::{
            CoreCanonicalBlockInput, CoreReplayActivationCheckpoint, CoreReplayTip,
            IronwoodFrontier,
        },
        owner::{OwnerSigningKey, owner_key_bytes},
        pending::{ChainPosition, PendingCommitments},
        recent_spent::RecentSpent,
        record::NameRecord,
        state::CoppiceState,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use zcash_client_backend::wallet::LockOwner;
    use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType};

    use super::*;
    use crate::{IronwoodWitness, OwnedIronwoodNote, lock_owner_for_bond};

    const ADDRESS: &[u8] = b"uregtest15zjdhgeu9vfwkrgxvxyuynkprgryyww0cl668tpj0ykhl7nvvh7v7ln89f0v8c36vwyffxglg24zh5d4622ela80w065cc28mv7gf423";

    fn deployment() -> DeploymentParameters {
        DeploymentParameters {
            network_id: REGTEST.network_id.to_vec(),
            address_network: NetworkType::Regtest,
            activation_height: REGTEST_ACTIVATION_HEIGHT,
            minimum_bond_value: REGTEST.minimum_bond_value,
            commit_ttl_blocks: 20,
            reuse_delay_blocks: 10,
            bond_note_max_age_blocks: 100,
            rendezvous: Rendezvous {
                orchard_ivk: REGTEST.rendezvous.orchard_ivk,
                orchard_receiver: REGTEST.rendezvous.orchard_receiver,
            },
        }
    }

    fn runtime() -> NamesRuntime {
        let activation_floor = deployment().activation_height - 1;
        NamesRuntime::new(
            deployment(),
            CoreReplayActivationCheckpoint {
                height: activation_floor,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap()
    }

    fn advance_empty(runtime: &mut NamesRuntime, height: u32) {
        runtime
            .apply_block(&CoreCanonicalBlockInput {
                height,
                block_hash: [height as u8; 32],
                prev_block_hash: runtime.tip().block_hash,
                branch_id: BranchId::Nu6_3,
                transactions: vec![],
            })
            .unwrap();
    }

    fn next_height(runtime: &NamesRuntime) -> u32 {
        runtime.tip().height.checked_add(1).unwrap()
    }

    #[derive(Clone, Copy)]
    struct Host(CoreReplayTip);

    impl HostCanonicalTipSource for Host {
        type Error = ();

        fn canonical_tip(&self) -> Result<crate::WalletCanonicalTip, Self::Error> {
            Ok(self.0.into())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum BackendError {
        Foreign,
        Forced,
    }

    struct Backend {
        notes: Vec<OwnedIronwoodNote>,
        locks: BTreeMap<IronwoodOutputId, LockOwner>,
        fail: bool,
    }

    impl CoppiceLockBackend for Backend {
        type Error = BackendError;

        fn owned_unspent_ironwood_notes(&self) -> Result<Vec<OwnedIronwoodNote>, Self::Error> {
            Ok(self.notes.clone())
        }

        fn ensure_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
            _: BlockHeight,
        ) -> Result<(), Self::Error> {
            if self.fail {
                return Err(BackendError::Forced);
            }
            let owner = lock_owner_for_bond(bond_tag);
            if self
                .locks
                .get(output_id)
                .is_some_and(|stored| *stored != owner)
            {
                return Err(BackendError::Foreign);
            }
            self.locks.insert(*output_id, owner);
            if let Some(note) = self
                .notes
                .iter_mut()
                .find(|note| note.output_id == *output_id)
            {
                note.locked = true;
            }
            Ok(())
        }

        fn remove_coppice_lock(
            &mut self,
            output_id: &IronwoodOutputId,
            bond_tag: [u8; 32],
        ) -> Result<bool, Self::Error> {
            if self.fail {
                return Err(BackendError::Forced);
            }
            if self.locks.get(output_id) == Some(&lock_owner_for_bond(bond_tag)) {
                self.locks.remove(output_id);
                if let Some(note) = self
                    .notes
                    .iter_mut()
                    .find(|note| note.output_id == *output_id)
                {
                    note.locked = false;
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn max_lock_expiry_height(&self) -> BlockHeight {
            BlockHeight::from_u32(u32::MAX)
        }
    }

    fn note(value: u64, id: u8) -> OwnedIronwoodNote {
        OwnedIronwoodNote {
            output_id: IronwoodOutputId::new([id; 32], u32::from(id)),
            value_zat: value,
            nullifier: [id; 32],
            position: Some(0),
            locked: false,
            spendable: true,
        }
    }

    fn backend(notes: Vec<OwnedIronwoodNote>) -> Backend {
        Backend {
            notes,
            locks: BTreeMap::new(),
            fail: false,
        }
    }

    fn owner() -> [u8; 32] {
        owner_key_bytes(&(&OwnerSigningKey::try_from([1; 32]).unwrap()).into())
    }

    fn account_id() -> crate::WalletAccountId {
        crate::WalletAccountId::from_bytes([0x11; 32])
    }

    #[test]
    fn begin_locks_then_persists_and_builds_exact_commit_carrier() {
        let runtime = runtime();
        let host = Host(runtime.tip());
        let mut pending = PendingRegistrationCollection::new();
        let minimum = runtime.deployment().minimum_bond_value;
        let mut backend = backend(vec![note(minimum + 10, 2), note(minimum, 1)]);
        let prepared = begin_registration(
            &host,
            &runtime,
            &mut pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            "alice.zec",
            ADDRESS,
            RegistrationOwner::External(owner()),
            ChaCha20Rng::from_seed([3; 32]),
        )
        .unwrap();

        assert_eq!(prepared.selected_bond.value_zat, minimum);
        assert!(
            backend
                .locks
                .contains_key(&prepared.selected_bond.output_id)
        );
        let local = pending.get(&prepared.commitment).unwrap();
        assert_eq!(local.name(), "alice");
        assert_eq!(registration_stage(local), RegistrationStage::Prepared);
        assert_eq!(
            registration_commitment(
                runtime.deployment(),
                local.name(),
                local.owner_pk(),
                local.bond_tag(),
                local.address(),
                local.secret(),
            )
            .unwrap(),
            prepared.commitment
        );
        assert_eq!(
            envelope::decode_operation(prepared.carrier().payload()).unwrap(),
            Operation::Commit {
                commitment: prepared.commitment
            }
        );
        assert_eq!(
            transport::reconstruct_frames(
                prepared.carrier().frames(),
                runtime.core().runtime_id().to_bytes(),
            )
            .unwrap(),
            prepared.carrier().application_envelope()
        );
    }

    #[test]
    fn larger_bond_requires_explicit_registration_policy() {
        let runtime = runtime();
        let host = Host(runtime.tip());
        let mut pending = PendingRegistrationCollection::new();
        let minimum = runtime.deployment().minimum_bond_value;
        let mut backend = backend(vec![note(minimum + 10, 2)]);

        assert!(matches!(
            begin_registration(
                &host,
                &runtime,
                &mut pending,
                account_id(),
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                "large-default",
                ADDRESS,
                RegistrationOwner::External(owner()),
                ChaCha20Rng::from_seed([4; 32]),
            ),
            Err(BeginRegistrationError::NoEligibleBond)
        ));
        assert!(pending.is_empty());
        assert!(backend.locks.is_empty());

        let prepared = begin_registration_with_policy(
            &host,
            &runtime,
            &mut pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            BondNoteSelectionPolicy::AllowLarger,
            &mut backend,
            "large-explicit",
            ADDRESS,
            RegistrationOwner::External(owner()),
            ChaCha20Rng::from_seed([5; 32]),
        )
        .unwrap();
        assert_eq!(prepared.selected_bond.value_zat, minimum + 10);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn prepared_reveal_carrier_survives_builder_action_shuffle() {
        let runtime = runtime();
        let operation = Operation::Reveal {
            name: "builder-shuffle".to_owned(),
            owner_pk: owner(),
            bond_tag: [2; 32],
            bond_anchor_height: runtime.tip().height,
            bond_anchor: [3; 32],
            bond_proof: vec![4; 4_960],
            address: vec![5; coppice::constants::MAX_ADDRESS_LEN],
            secret: [6; 32],
        };
        let prepared = prepare_carrier(&runtime, &operation).unwrap();
        assert_eq!(prepared.frames().len(), 12);

        // Orchard/Ironwood builders randomize Action positions. Output
        // insertion order therefore cannot be the carrier ordering rule.
        let mut action_order = prepared.frames().to_vec();
        action_order.rotate_left(7);
        action_order.swap(1, 9);
        assert_eq!(
            transport::reconstruct_frames(&action_order, runtime.core().runtime_id().to_bytes(),)
                .unwrap(),
            prepared.application_envelope()
        );
    }

    #[test]
    fn default_owner_is_bound_to_selected_tag_and_transient_account_key() {
        let runtime = runtime();
        let host = Host(runtime.tip());
        let mut pending = PendingRegistrationCollection::new();
        let mut backend = backend(vec![note(runtime.deployment().minimum_bond_value, 1)]);
        let account_key = [42; 32];
        let prepared = begin_registration(
            &host,
            &runtime,
            &mut pending,
            account_id(),
            IronwoodViewingCapability::Spending,
            &mut backend,
            "alice",
            ADDRESS,
            RegistrationOwner::DefaultSoftware(&account_key),
            ChaCha20Rng::from_seed([11; 32]),
        )
        .unwrap();
        let expected = owner_key_bytes(
            &derive_v1_owner_verification_key(
                account_key,
                runtime.names_deployment_id().to_bytes(),
                name_id("alice"),
                prepared.selected_bond.bond_tag,
            )
            .unwrap(),
        );
        assert_eq!(prepared.owner_pk, expected);
    }

    #[test]
    fn insertion_failure_after_lock_does_not_speculatively_unlock() {
        let runtime = runtime();
        let host = Host(runtime.tip());
        let selected_note = note(runtime.deployment().minimum_bond_value, 1);
        let selected_tag = coppice::bond_tag::derive_v1_bond_tag(&selected_note.nullifier).unwrap();
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        let mut secret = [0; 32];
        rng.fill_bytes(&mut secret);
        let commitment = registration_commitment(
            runtime.deployment(),
            "alice",
            owner(),
            selected_tag,
            ADDRESS,
            secret,
        )
        .unwrap();
        let mut pending = PendingRegistrationCollection::new();
        pending
            .insert(
                PendingRegistration::new(
                    runtime.deployment(),
                    account_id(),
                    "alice".to_owned(),
                    ADDRESS.to_vec(),
                    owner(),
                    selected_tag,
                    secret,
                    commitment,
                )
                .unwrap(),
            )
            .unwrap();
        let mut backend = backend(vec![selected_note]);
        assert!(matches!(
            begin_registration(
                &host,
                &runtime,
                &mut pending,
                account_id(),
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                "alice",
                ADDRESS,
                RegistrationOwner::External(owner()),
                ChaCha20Rng::from_seed([12; 32]),
            ),
            Err(BeginRegistrationError::PendingInsertionAfterLock(
                PendingRegistrationCollectionError::DuplicateCommitment
            ))
        ));
        assert!(backend.locks.contains_key(&selected_note.output_id));
        pending.remove(&commitment);
        reconcile_locks(
            &active_canonical_bond_tags(&runtime),
            &pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .unwrap();
        assert!(!backend.locks.contains_key(&selected_note.output_id));
    }

    #[test]
    fn exact_tip_and_input_failures_precede_lock_mutation() {
        let runtime = runtime();
        let mut pending = PendingRegistrationCollection::new();
        let mut backend = backend(vec![note(runtime.deployment().minimum_bond_value, 1)]);
        let bad_host = Host(CoreReplayTip {
            height: runtime.tip().height,
            block_hash: [8; 32],
        });
        assert!(matches!(
            begin_registration(
                &bad_host,
                &runtime,
                &mut pending,
                account_id(),
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                "alice",
                ADDRESS,
                RegistrationOwner::External(owner()),
                ChaCha20Rng::from_seed([3; 32]),
            ),
            Err(BeginRegistrationError::Tip(
                ExactCanonicalTipError::BlockHashMismatch { .. }
            ))
        ));
        assert!(backend.locks.is_empty());
        assert!(pending.is_empty());

        let host = Host(runtime.tip());
        assert!(matches!(
            begin_registration(
                &host,
                &runtime,
                &mut pending,
                account_id(),
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                "-bad",
                ADDRESS,
                RegistrationOwner::External(owner()),
                ChaCha20Rng::from_seed([3; 32]),
            ),
            Err(BeginRegistrationError::InvalidName)
        ));
        assert!(backend.locks.is_empty());
    }

    #[test]
    fn stage_separates_broadcast_from_reorg_updatable_canonical_observation() {
        let runtime = runtime();
        let host = Host(runtime.tip());
        let mut collection = PendingRegistrationCollection::new();
        let mut backend = backend(vec![note(runtime.deployment().minimum_bond_value, 1)]);
        let commitment = begin_registration(
            &host,
            &runtime,
            &mut collection,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            "alice",
            ADDRESS,
            RegistrationOwner::External(owner()),
            ChaCha20Rng::from_seed([5; 32]),
        )
        .unwrap()
        .commitment;
        let txid = [7; 32];
        record_commit_broadcast(&mut collection, &commitment, txid).unwrap();
        record_commit_broadcast(&mut collection, &commitment, txid).unwrap();
        assert_eq!(
            registration_stage(collection.get(&commitment).unwrap()),
            RegistrationStage::CommitBroadcast
        );
        collection
            .observe_canonical_commit_height(&commitment, 108)
            .unwrap();
        assert_eq!(
            registration_stage(collection.get(&commitment).unwrap()),
            RegistrationStage::CommitCanonical
        );
        reconcile_canonical_commit_cache(&runtime, &mut collection).unwrap();
        assert_eq!(
            registration_stage(collection.get(&commitment).unwrap()),
            RegistrationStage::CommitBroadcast
        );
        collection
            .observe_canonical_commit_height(&commitment, 111)
            .unwrap();
        collection
            .observe_canonical_commit_height(&commitment, 111)
            .unwrap();
        assert_eq!(
            collection.get(&commitment).unwrap().commit_height(),
            Some(111)
        );
        assert_eq!(
            collection.get(&commitment).unwrap().commit_txid(),
            Some(txid)
        );
    }

    fn state_with_commit(commitment: [u8; 32], height: u32) -> CoppiceState {
        let mut protocol_pending = PendingCommitments::new();
        protocol_pending.insert(
            commitment,
            ChainPosition {
                block_height: height,
                tx_index: 7,
            },
        );
        CoppiceState::from_authoritative_parts(
            BTreeMap::new(),
            protocol_pending,
            RecentSpent::new(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_height_ignores_transport_cache_and_follows_reorg_state() {
        let commitment = [0x44; 32];
        let earlier_copy = state_with_commit(commitment, 108);
        assert_eq!(canonical_commit_height(&earlier_copy, &commitment), Ok(108));

        let reorg_replacement = state_with_commit(commitment, 111);
        assert_eq!(
            canonical_commit_height(&reorg_replacement, &commitment),
            Ok(111)
        );
        assert_eq!(
            canonical_commit_height(&CoppiceState::default(), &commitment),
            Err(CanonicalCommitMissing)
        );

        // A stale wallet cache of 110 is intentionally not an input to the
        // protocol lookup: copied COMMIT height 108 remains authoritative.
        let stale_local_height = 110;
        assert_ne!(
            canonical_commit_height(&earlier_copy, &commitment).unwrap(),
            stale_local_height
        );
        let canonical_height = canonical_commit_height(&earlier_copy, &commitment).unwrap();
        assert!(crate::pending_commit_expired(canonical_height, 20, 128).unwrap());
        assert!(!crate::pending_commit_expired(stale_local_height, 20, 128).unwrap());
    }

    struct NeverWitness(Cell<usize>);

    impl IronwoodWitnessSource for NeverWitness {
        type Error = ();

        fn witness_at(&mut self, _: u32, _: u32) -> Result<IronwoodWitness, Self::Error> {
            self.0.set(self.0.get() + 1);
            panic!("witness must not be requested")
        }
    }

    struct NeverMaterial(Cell<usize>);

    impl RegistrationBondMaterialSource for NeverMaterial {
        type Error = ();

        fn private_material_for(
            &mut self,
            _: &IronwoodOutputId,
        ) -> Result<WalletBondPrivateMaterial, Self::Error> {
            self.0.set(self.0.get() + 1);
            panic!("private material must not be requested")
        }
    }

    #[test]
    fn stale_local_commit_is_rejected_from_current_runtime_before_private_work() {
        let mut runtime = runtime();
        let initial_host = Host(runtime.tip());
        let mut collection = PendingRegistrationCollection::new();
        let mut backend = backend(vec![note(runtime.deployment().minimum_bond_value, 1)]);
        let commitment = begin_registration(
            &initial_host,
            &runtime,
            &mut collection,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            "alice",
            ADDRESS,
            RegistrationOwner::External(owner()),
            ChaCha20Rng::from_seed([6; 32]),
        )
        .unwrap()
        .commitment;
        let mined_height = next_height(&runtime);
        collection
            .observe_canonical_commit_height(&commitment, mined_height)
            .unwrap();
        advance_empty(&mut runtime, mined_height);
        let host = Host(runtime.tip());
        let mut witness = NeverWitness(Cell::new(0));
        let mut material = NeverMaterial(Cell::new(0));
        assert!(matches!(
            prepare_reveal(
                &host,
                &runtime,
                &collection,
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                &mut witness,
                &mut material,
                &V1BondProver::new().unwrap(),
                &commitment,
                ChaCha20Rng::from_seed([9; 32]),
            ),
            Err(PrepareRevealError::CanonicalCommitMissing)
        ));
        assert_eq!(witness.0.get(), 0);
        assert_eq!(material.0.get(), 0);
        assert!(collection.get(&commitment).is_some());
    }

    #[test]
    fn active_record_matching_checks_every_registration_fact() {
        let runtime = runtime();
        let bond_tag = [4; 32];
        let secret = [5; 32];
        let commitment = registration_commitment(
            runtime.deployment(),
            "alice",
            owner(),
            bond_tag,
            ADDRESS,
            secret,
        )
        .unwrap();
        let pending = PendingRegistration::new(
            runtime.deployment(),
            account_id(),
            "alice".to_owned(),
            ADDRESS.to_vec(),
            owner(),
            bond_tag,
            secret,
            commitment,
        )
        .unwrap();
        let record = NameRecord {
            owner_pk: owner(),
            bond_tag,
            sequence: 0,
            address: ADDRESS.to_vec(),
            status: NameStatus::Active,
        };
        assert_eq!(
            registration_matches_active_record(&pending, Some(&record)),
            Ok(())
        );
        let mut wrong = record.clone();
        wrong.sequence = 1;
        assert_eq!(
            registration_matches_active_record(&pending, Some(&wrong)),
            Err(CompletionMismatch::Sequence)
        );
        wrong = record.clone();
        wrong.status = NameStatus::Released { terminal_height: 1 };
        assert_eq!(
            registration_matches_active_record(&pending, Some(&wrong)),
            Err(CompletionMismatch::NotActive)
        );
    }

    #[test]
    fn explicit_abandon_is_staged_and_reconciliation_failure_retains_pending() {
        let runtime = runtime();
        let host = Host(runtime.tip());
        let mut pending = PendingRegistrationCollection::new();
        let mut backend = backend(vec![note(runtime.deployment().minimum_bond_value, 1)]);
        let commitment = begin_registration(
            &host,
            &runtime,
            &mut pending,
            account_id(),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            "alice",
            ADDRESS,
            RegistrationOwner::External(owner()),
            ChaCha20Rng::from_seed([13; 32]),
        )
        .unwrap()
        .commitment;
        backend.fail = true;
        assert!(matches!(
            abandon_registration(
                &host,
                &runtime,
                &mut pending,
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                &commitment,
            ),
            Err(LifecycleError::Reconciliation(_))
        ));
        assert!(pending.get(&commitment).is_some());
        backend.fail = false;
        abandon_registration(
            &host,
            &runtime,
            &mut pending,
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            &commitment,
        )
        .unwrap();
        assert!(pending.get(&commitment).is_none());
        assert!(backend.locks.is_empty());
    }
}
