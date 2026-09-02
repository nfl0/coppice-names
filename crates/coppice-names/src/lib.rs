//! Canonical Coppice Names state, replay, and proof-boundary primitives.

/// Exact manual operation codec for the replacement Names design.
pub mod codec;
/// Canonical protocol values for the replacement Names design.
pub mod protocol;
/// Canonical one-public-field proof statements.
pub mod statement;

/// Transitional released implementation. This module is removed after its
/// wallet and host dependents move to the replacement protocol.
pub mod v1;
