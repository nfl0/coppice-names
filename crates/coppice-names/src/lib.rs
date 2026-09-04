//! Canonical Coppice Names state, replay, and proof-boundary primitives.

use coppice::application::{ApplicationId, derive_application_id};

/// Stable Names family label used as a deployment-identity input.
pub const NAMES_CANONICAL_APPLICATION_IDENTITY: &[u8] = b"coppice.names";

/// Returns the stable Names family identifier.
pub fn names_family_id() -> ApplicationId {
    derive_application_id(NAMES_CANONICAL_APPLICATION_IDENTITY)
        .expect("the Names application identity is nonempty")
}

/// Returns the exact Core routing identity for one immutable Names deployment.
pub fn names_application_id(deployment_id: [u8; 32]) -> ApplicationId {
    let mut identity = Vec::with_capacity(NAMES_CANONICAL_APPLICATION_IDENTITY.len() + 1 + 32);
    identity.extend_from_slice(NAMES_CANONICAL_APPLICATION_IDENTITY);
    identity.push(0);
    identity.extend_from_slice(&deployment_id);
    derive_application_id(&identity).expect("the deployment-routed Names identity is nonempty")
}

/// Exact manual operation codec for the current Names design.
pub mod codec;
/// Canonical verifier and deployment identities.
pub mod deployment;
/// Production Orchard proof adapters.
pub mod proof;
/// Canonical protocol values for the current Names design.
pub mod protocol;
/// Canonical outbound CAPP/CPCF publication construction.
pub mod publication;
/// Canonical accepted-state reducer.
pub mod reducer;
/// Exact arbitrary-name replay over authenticated canonical effects.
pub mod resolver;
/// Canonical machine-readable semantic-ruleset identity.
pub mod ruleset;
/// Deterministic height schedule and checked lifecycle arithmetic.
pub mod schedule;
/// Canonical one-public-field proof statements.
pub mod statement;
/// Authenticated Core-to-Names transport boundary.
pub mod transport;
