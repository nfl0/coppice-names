//! Experimental Coppice Names v2 vertical slice.
//!
//! This namespace is additive. The v1 envelope, registration, BondProof,
//! runtime identities, and serialized state remain owned by their existing
//! modules and are not decoded here.

pub mod lease;
pub mod machine;
pub mod operation;
pub mod registration;
pub mod resolver;
pub mod schedule;
pub mod state;
pub mod transition;

pub use lease::{LeaseParameterError, Lifecycle, V2Parameters};
pub use machine::{
    AppliedBlock, AppliedOperationKind, ApplyError, ResolutionStatus, V2StateMachine,
};
pub use operation::{
    ActionViewError, CanonicalBlock, CanonicalTransaction, ChainTip, IronwoodActionRef,
    OperationKind, V2Operation,
};
pub use registration::{
    BondEvidence, BondProofVerifier, CommitRef, FrozenV1BondProofVerifier, RegistrationError,
    RegistrationIntent,
};
pub use resolver::{
    CanonicalSource, FreshResolver, ResolutionResult, ResolutionStats, ResolveError,
};
pub use state::{
    NameId, NameState, OwnerKey, ProducerPosition, StateData, StateError, StateRef, StateStatus,
};
pub use transition::{
    GenesisStatement, OrchardV2ProofVerifier, StatementError, TransitionStatement,
    V2StateProofVerifier,
};
