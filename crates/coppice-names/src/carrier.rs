//! Public Ironwood rendezvous construction and compact candidate detection.
//!
//! CPV1 framing, runtime binding, and application-envelope routing are owned
//! by `coppice-core`.

use crate::config::Rendezvous;
use orchard::keys::IncomingViewingKey;

#[derive(Debug)]
pub enum Error {
    Build,
}

/// Returns the configured public incoming capability. It contains no spending
/// authority.
pub fn bulletin_ivk(rendezvous: Rendezvous) -> Result<IncomingViewingKey, Error> {
    Option::from(IncomingViewingKey::from_bytes(&rendezvous.orchard_ivk)).ok_or(Error::Build)
}

pub fn bulletin_address(rendezvous: Rendezvous) -> Result<orchard::Address, Error> {
    Option::from(orchard::Address::from_raw_address_bytes(
        &rendezvous.orchard_receiver,
    ))
    .ok_or(Error::Build)
}

/// Detects a rendezvous output from compact Ironwood data without fetching
/// unrelated full transactions.
pub fn compact_action_is_bulletin(
    action: &orchard::note_encryption::CompactAction,
    rendezvous: Rendezvous,
) -> Result<bool, Error> {
    let context = coppice_core::carrier::CoreRendezvous::try_new(
        &rendezvous.orchard_ivk,
        &rendezvous.orchard_receiver,
    )
    .map_err(|_| Error::Build)?;
    Ok(coppice_core::carrier::compact_action_is_rendezvous(
        action, &context,
    ))
}
