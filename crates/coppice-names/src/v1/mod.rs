//! Coppice Names protocol implementation.
//!
//! The module owns the complete local Names state transition and its
//! canonical resolver. Coppice Core remains responsible for generic
//! transport and canonical acquisition; Zcash consensus remains the sole
//! transaction and fork-choice authority.

pub use crate::{NAMES_CANONICAL_APPLICATION_IDENTITY, names_application_id};

pub mod application;
pub mod lease;
pub mod machine;
pub mod operation;
pub mod payment;
pub mod registration;
pub mod resolver;
pub mod schedule;
pub mod state;
pub mod transition;
pub mod wire;

pub use application::{
    NAMES_APPLICATION_SNAPSHOT_FORMAT_VERSION, NAMES_APPLICATION_VERSION, NamesApplication,
    NamesApplicationApplyError, NamesApplicationBlockOutput, NamesApplicationConfigError,
    NamesApplicationRewindError, NamesApplicationSnapshotError,
};
pub use lease::{LeaseParameterError, Lifecycle, V1Parameters};
pub use machine::{
    AppliedBlock, AppliedOperation, AppliedOperationKind, AppliedOperationResult, ApplyError,
    MachineSnapshotError, ResolutionStatus, V1StateMachine,
};
pub use operation::{
    ActionViewError, CanonicalBlock, CanonicalTransaction, ChainTip, IronwoodActionRef,
    OperationKind, V1Operation,
};
pub use payment::{
    PAYMENT_RECORD_HEADER_LEN, PAYMENT_RECORD_MAGIC, PAYMENT_RECORD_VERSION, PaymentNetwork,
    PaymentRecord, PaymentRecordError,
};
pub use registration::{CommitRef, RegistrationError, RegistrationIntent};
pub use resolver::{
    CanonicalSource, FreshResolver, ResolutionResult, ResolutionStats, ResolveError,
};
pub use state::{
    NameId, NameState, OwnerKey, ProducerPosition, StateData, StateError, StateRef, StateStatus,
};
pub use transition::{
    GenesisStatement, OrchardV1ProofProver, OrchardV1ProofVerifier, ProofCreationError,
    StatementError, TransitionStatement, V1StateProofVerifier,
};
pub use wire::{
    CNV1_WIRE_VERSION, WireError, decode_operation, decode_operations, encode_operation,
    encode_operations, operation_footprint,
};
