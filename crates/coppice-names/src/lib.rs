//! Canonical Coppice Names state, replay, and proof-boundary primitives.

use coppice::application::{ApplicationId, derive_application_id};

/// Exact application-family identity used by Names operations.
pub const NAMES_CANONICAL_APPLICATION_IDENTITY: &[u8] = b"coppice.names";

/// Returns the canonical Names application family identifier.
pub fn names_application_id() -> ApplicationId {
    derive_application_id(NAMES_CANONICAL_APPLICATION_IDENTITY)
        .expect("the Names application identity is nonempty")
}

/// Exact manual operation codec for the replacement Names design.
pub mod codec;
/// Canonical verifier and deployment identities.
pub mod deployment;
/// Production Orchard proof adapters.
pub mod proof;
/// Canonical protocol values for the replacement Names design.
pub mod protocol;
/// Canonical accepted-state reducer.
pub mod reducer;
/// Deterministic height schedule and checked lifecycle arithmetic.
pub mod schedule;
/// Canonical one-public-field proof statements.
pub mod statement;

/// Transitional released implementation. This module is removed after its
/// wallet and host dependents move to the replacement protocol.
pub mod v1;
