//! Wallet-local Coppice primitives for librustzcash integrations.
//!
//! This crate deliberately contains no wallet database, synchronization, RPC,
//! broadcast, or UI integration. It adapts locally derived wallet facts and
//! the host's public wallet traits, including normal transaction construction.

mod bond_note;
mod bond_prover;
mod carrier_tx;
mod guard;
mod inventory;
mod locking;
mod operations;
mod pending;
mod reconcile;
mod register;
mod selection;
mod source;
mod witness;

pub use guard::{
    CoppiceProtectionMode, ExactCanonicalTipError, HostCanonicalTipSource, SpendGuardError,
    WalletCanonicalTip, require_exact_canonical_tip, with_coppice_spend_guard,
};
pub use inventory::{
    InventoryError, IronwoodOutputId, IronwoodViewingCapability, OwnedBond, OwnedIronwoodNote,
    OwnedIronwoodNoteSource, active_canonical_bond_tags, active_canonical_bond_tags_from_state,
    classify_owned_bonds,
};
pub use locking::{
    CoppiceLockBackend, DesiredLockSetError, OutputLockBackendError, OutputLockStoreBridge,
    ReconciliationError, ReconciliationReport, WalletCoppiceLockBackend, WalletCoppiceLockError,
    desired_lock_tags, lock_owner_for_bond, reconcile_locks,
};
pub use operations::{
    BreakBondError, BreakBondPlan, OwnerAuthority, OwnerOperationError, PaymentResolutionError,
    PreparedOwnerOperation, VerifiedDestination, prepare_break_bond, prepare_release,
    prepare_update, resolve_for_payment,
};
pub use pending::{
    PendingRegistration, PendingRegistrationCollection, PendingRegistrationCollectionError,
    PendingRegistrationPersistenceError, PendingRegistrationTransitionError,
    PendingRegistrationValidationError, WalletAccountId, pending_attempt_expired,
    pending_commit_expired,
};
pub use reconcile::{
    CanonicalBlockSource, CanonicalTip, FrozenCanonicalBlockSource, ReconcileError, ReconcileKind,
    ReconcileOutcome, ReconcileResult, reconcile_canonical_chain,
    reconcile_canonical_chain_with_progress,
};
pub use register::{
    BeginRegistrationError, CanonicalCommitMissing, CarrierPreparationError, CommitTransitionError,
    CompletionMismatch, LifecycleError, ObserveCanonicalCommitError, PrepareRevealError,
    PreparedCarrier, PreparedCommit, PreparedReveal, RegistrationBondMaterialSource,
    RegistrationOwner, RegistrationStage, abandon_expired_registration, abandon_registration,
    begin_registration, begin_registration_with_policy, canonical_commit_height,
    complete_registration, observe_canonical_commit, prepare_reveal,
    reconcile_canonical_commit_cache, record_commit_broadcast, registration_matches_active_record,
    registration_stage,
};
pub use selection::{
    BondNotePreparation, BondNoteSelectionPolicy, FreshnessEligibility, SelectedBondNote,
    prepare_bond_note, select_bond_note, select_bond_note_with_policy,
};
pub use source::{
    InputSourceIronwoodNoteSource, IronwoodNoteConversionError, IronwoodNoteSourceError,
};
pub use witness::{
    AnchorContext, BondFreshnessContext, FreshnessContextError, IronwoodWitness,
    IronwoodWitnessSource, ResolveWitnessError, WalletCommitmentTreesIronwoodWitnessSource,
    WalletIronwoodWitnessError, anchor_for_registration, choose_current_anchor,
    freshness_for_canonical_commit, freshness_for_next_block_commit,
    resolve_canonical_ironwood_witness, select_fresh_bond_note, select_fresh_bond_note_with_policy,
};

pub use bond_note::{
    BondNotePreparationConstructionError, BondNotePreparationProposalError,
    BondNotePreparationRequestError, BondNotePreparationValidationError, BondNoteSplitError,
    BondNoteSplitPlan, ConstructedBondNotePreparation, PreparedBondNoteProposal,
    bond_note_preparation_request, bond_note_preparation_spend_policy,
    create_bond_note_preparation_transaction, plan_bond_note_split, propose_bond_note_preparation,
};
pub use bond_prover::{WalletBondPrivateMaterial, WalletBondProverError, prove_selected_bond};
pub use carrier_tx::{
    CarrierConstructionError, CarrierProposalError, CarrierProposalValidationError,
    CarrierTransactionRequestError, ConstructedCarrierTransaction, PostBuildInvariantError,
    PreparedCarrierProposal, carrier_transaction_request, create_carrier_transaction,
    propose_carrier_transaction,
};
pub use coppice_librustzcash::{
    CanonicalRuntime, CompactBlockAdapterError, CompactBlockApplyError, FullTransactionSource,
    MAX_CANDIDATE_FULL_TX_BYTES, apply_compact_block, prepare_canonical_block,
    prepare_canonical_block_with_transaction_selector,
};
/// The exact pinned librustzcash lock-owner type used by this adapter.
pub use zcash_client_backend::wallet::LockOwner;
