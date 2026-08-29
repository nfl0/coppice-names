//! Coppice Names protocol implementation.
//!
//! The module owns the complete local Names state transition and its
//! canonical resolver. Coppice Core remains responsible for generic
//! transport and canonical acquisition; Zcash consensus remains the sole
//! transaction and fork-choice authority.

use coppice::application::{ApplicationId, derive_application_id};

/// Exact application-family identity used by Names operations on the generic
/// Coppice transport. The operation version is encoded by CNV1 itself.
pub const NAMES_CANONICAL_APPLICATION_IDENTITY: &[u8] = b"coppice.names";

/// Returns the canonical Names application family identifier.
pub fn names_application_id() -> ApplicationId {
    derive_application_id(NAMES_CANONICAL_APPLICATION_IDENTITY)
        .expect("the Names application identity is nonempty")
}

pub mod lease;
pub mod machine;
pub mod operation;
pub mod registration;
pub mod resolver;
pub mod schedule;
pub mod state;
pub mod transition;
pub mod wire;

pub use lease::{LeaseParameterError, Lifecycle, V1Parameters};
pub use machine::{
    AppliedBlock, AppliedOperation, AppliedOperationKind, AppliedOperationResult, ApplyError,
    ResolutionStatus, V1StateMachine,
};
pub use operation::{
    ActionViewError, CanonicalBlock, CanonicalTransaction, ChainTip, IronwoodActionRef,
    OperationKind, V1Operation,
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
