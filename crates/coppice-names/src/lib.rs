//! Canonical Coppice Names state, replay, and proof-boundary primitives.

/// Exact manual operation codec for the replacement Names design.
pub mod codec;
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
