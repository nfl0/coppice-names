//! Canonical Coppice protocol state, replay, and wallet-integration primitives.
pub mod authorization;
pub mod bond;
pub mod bond_tag;
pub mod carrier;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod envelope;
pub mod ironwood;
pub mod name_tree;
pub mod names_application;
pub mod names_runtime;
pub mod owner;
pub mod owner_kdf;
pub mod pending;
pub mod recent_spent;
pub mod record;
pub mod registration;
pub mod reveal;
pub mod state;
pub mod state_root;
/// Experimental Names v2 state-note protocol. This namespace is intentionally
/// separate from the frozen v1 envelope, replay, and identity modules.
pub mod v2;
