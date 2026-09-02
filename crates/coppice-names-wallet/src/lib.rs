//! Reusable Zcash wallet construction for Coppice Names.
//!
//! `coppice-names` remains the deterministic protocol/runtime crate. This
//! crate owns wallet-side preparation of canonical Names operations and their
//! designated-pair Ironwood PCZTs. Wallet database access, key custody,
//! transaction approval, note splitting, persistence, and broadcast remain
//! responsibilities of the integrating wallet.

#![forbid(unsafe_code)]

pub mod bond;
pub mod builder;
pub mod operation;
pub mod recovery;
pub mod replacement;

pub use bond::{BondInventoryDecision, REQUIRED_BOND_ZATOSHIS, classify_bond_inventory};
