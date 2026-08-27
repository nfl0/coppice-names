//! Canonical values for the experimental Names v2 state-note lineage.
//!
//! The v2 state is deliberately a value object. It has no application root
//! and no implicit transaction identity; the producer position is carried by
//! [`StateRef`] and is authenticated by the resolver when it follows a
//! lineage.

use crate::crypto;
use orchard::circuit::state_note_binding::{
    STATUS_ACTIVE, STATUS_RELEASED, StateMetadata as OrchardStateMetadata, native_state_digest,
};
use pasta_curves::group::ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

/// Maximum experimental v2 destination/record size.
pub const MAX_RECORD_BYTES: usize = 1024;

/// The canonical 32-byte name identifier used by v2.
pub type NameId = [u8; 32];
/// The canonical Ironwood `ak`/RedPallas SpendAuth validating-key encoding
/// used by v2.
pub type OwnerKey = [u8; 32];

/// Errors from canonical v2 state construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// The owner key is not a non-identity canonical Ironwood `ak` key.
    InvalidOwner,
    /// A state commitment or digest is not a canonical Pallas field encoding.
    InvalidField,
    /// The destination/record exceeds the experimental bound.
    RecordTooLarge,
    /// Active states cannot carry a terminal height.
    ActiveTerminalHeight,
    /// Released states must carry a nonzero terminal height.
    ReleasedTerminalHeight,
    /// The state reference does not name the supplied commitment.
    ReferenceCommitmentMismatch,
}

/// The only state statuses in the v2 milestone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateStatus {
    /// The name can resolve and can be renewed or updated while its lease is live.
    Active,
    /// The lineage is terminal and cannot resolve as active.
    Released,
}

impl StateStatus {
    /// Returns the circuit-level canonical status code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Active => STATUS_ACTIVE,
            Self::Released => STATUS_RELEASED,
        }
    }
}

/// The canonical, non-note portion of a v2 name state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateData {
    /// The name this state belongs to.
    pub name_id: NameId,
    /// The unchanged owner authority for this milestone.
    pub owner_pk: OwnerKey,
    /// Monotonic state sequence, encoded as a canonical u64.
    pub sequence: u64,
    /// Canonical destination/record bytes.
    pub record: Vec<u8>,
    /// Exclusive height at which an active lease stops resolving as active.
    pub lease_expiry: u32,
    /// Active or explicitly released.
    pub status: StateStatus,
    /// Zero while active, otherwise the canonical release height.
    pub terminal_height: u32,
}

impl StateData {
    /// Checks all representation-level invariants for a state value.
    pub fn validate(&self) -> Result<(), StateError> {
        owner_key_field(self.owner_pk)?;
        if self.record.len() > MAX_RECORD_BYTES {
            return Err(StateError::RecordTooLarge);
        }
        match self.status {
            StateStatus::Active if self.terminal_height != 0 => {
                Err(StateError::ActiveTerminalHeight)
            }
            StateStatus::Released if self.terminal_height == 0 => {
                Err(StateError::ReleasedTerminalHeight)
            }
            _ => Ok(()),
        }
    }

    /// Returns the canonical circuit metadata for this state.
    pub fn metadata(&self) -> OrchardStateMetadata {
        OrchardStateMetadata::new(
            self.sequence,
            record_digest_field(&self.record),
            self.lease_expiry,
            self.status.code(),
            self.terminal_height,
        )
    }

    /// Returns an unambiguous byte encoding of the state values.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StateError> {
        self.validate()?;
        let record_len =
            u32::try_from(self.record.len()).map_err(|_| StateError::RecordTooLarge)?;
        let mut out = Vec::with_capacity(32 + 32 + 8 + 4 + self.record.len() + 1 + 4);
        out.extend_from_slice(&self.name_id);
        out.extend_from_slice(&self.owner_pk);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&record_len.to_be_bytes());
        out.extend_from_slice(&self.record);
        out.extend_from_slice(&self.lease_expiry.to_be_bytes());
        out.push(self.status.code());
        out.extend_from_slice(&self.terminal_height.to_be_bytes());
        Ok(out)
    }
}

/// A canonical transaction position used by commits and state-note producers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProducerPosition {
    /// Canonical block height.
    pub height: u32,
    /// Canonical transaction index within the block.
    pub tx_index: u32,
    /// Canonical transaction identifier.
    pub txid: [u8; 32],
}

impl ProducerPosition {
    /// Constructs a canonical position.
    pub const fn new(height: u32, tx_index: u32, txid: [u8; 32]) -> Self {
        Self {
            height,
            tx_index,
            txid,
        }
    }
}

/// The authenticated producer position of one state-note output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StateRef {
    /// Block containing the producer transaction.
    pub producer_height: u32,
    /// Transaction index containing the producer action.
    pub producer_tx_index: u32,
    /// Transaction identifier containing the producer action.
    pub producer_txid: [u8; 32],
    /// Ironwood action index whose commitment is this state note.
    pub producer_action_index: u32,
    /// The state-note commitment created by that action.
    pub commitment: [u8; 32],
}

impl StateRef {
    /// Constructs a state reference from a transaction position and action.
    pub const fn new(position: ProducerPosition, action_index: u32, commitment: [u8; 32]) -> Self {
        Self {
            producer_height: position.height,
            producer_tx_index: position.tx_index,
            producer_txid: position.txid,
            producer_action_index: action_index,
            commitment,
        }
    }

    /// Returns the transaction portion of this reference.
    pub const fn position(&self) -> ProducerPosition {
        ProducerPosition::new(
            self.producer_height,
            self.producer_tx_index,
            self.producer_txid,
        )
    }

    /// Returns the explicit v2 field binding used in a transition proof.
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(4 + 4 + 32 + 4 + 32);
        bytes.extend_from_slice(&self.producer_height.to_be_bytes());
        bytes.extend_from_slice(&self.producer_tx_index.to_be_bytes());
        bytes.extend_from_slice(&self.producer_txid);
        bytes.extend_from_slice(&self.producer_action_index.to_be_bytes());
        bytes.extend_from_slice(&self.commitment);
        hash_to_field("CoppiceN2Ref", &bytes).to_repr()
    }
}

/// A state value together with its current authenticated note identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameState {
    /// Canonical state values.
    pub data: StateData,
    /// Commitment of the current state note.
    pub commitment: [u8; 32],
    /// Position that created the current note.
    pub state_ref: StateRef,
    /// Digest committed by the state-note proof.
    pub state_digest: [u8; 32],
}

impl NameState {
    /// Creates and validates a state head.
    pub fn new(
        data: StateData,
        commitment: [u8; 32],
        state_ref: StateRef,
    ) -> Result<Self, StateError> {
        data.validate()?;
        if state_ref.commitment != commitment {
            return Err(StateError::ReferenceCommitmentMismatch);
        }
        canonical_field(commitment)?;
        let state_digest = state_digest(&data, commitment);
        Ok(Self {
            data,
            commitment,
            state_ref,
            state_digest,
        })
    }

    /// Returns true only while this state is active and its lease is live.
    pub fn is_active_at(&self, height: u32) -> bool {
        self.data.status == StateStatus::Active && height < self.data.lease_expiry
    }
}

/// Computes the v2 deterministic name identifier after canonical name validation.
pub fn name_id(name: &str) -> Result<NameId, crate::envelope::Error> {
    let canonical = crate::envelope::normalize_name(name)?;
    Ok(hash_bytes("CoppiceN2Name", canonical.as_bytes()))
}

/// Computes the explicit v2 record digest field.
pub fn record_digest_field(record: &[u8]) -> pallas::Base {
    let mut bytes = Vec::with_capacity(4 + record.len());
    bytes.extend_from_slice(&(u32::try_from(record.len()).unwrap_or(u32::MAX)).to_be_bytes());
    bytes.extend_from_slice(record);
    hash_to_field("CoppiceN2Rec", &bytes)
}

/// Returns the canonical field encoding of an Ironwood `ak` key.
pub fn owner_key_field(owner_pk: OwnerKey) -> Result<pallas::Base, StateError> {
    // `ak` is serialized as a RedPallas SpendAuth verification key. Checking
    // only that its bytes fit in the Pallas base field would admit arbitrary
    // field values that do not encode a valid spend-authorizing authority.
    crate::owner::parse_v1_owner_key(owner_pk).map_err(|_| StateError::InvalidOwner)?;
    let field = canonical_field(owner_pk)?;
    if field == pallas::Base::zero() {
        return Err(StateError::InvalidOwner);
    }
    Ok(field)
}

/// Returns the canonical field encoding of an Orchard commitment or nullifier.
pub fn canonical_field(bytes: [u8; 32]) -> Result<pallas::Base, StateError> {
    Option::<pallas::Base>::from(pallas::Base::from_repr(bytes)).ok_or(StateError::InvalidField)
}

/// Computes the state digest used by the experimental Orchard circuit.
pub fn state_digest(data: &StateData, commitment: [u8; 32]) -> [u8; 32] {
    let name_field = name_id_field(data.name_id);
    let owner_field = owner_key_field(data.owner_pk).expect("validated state owner");
    let commitment_field = canonical_field(commitment).expect("validated state commitment");
    native_state_digest(name_field, owner_field, data.metadata(), commitment_field).to_repr()
}

/// Maps the canonical byte name identifier into the circuit's field domain.
pub fn name_id_field(name_id: NameId) -> pallas::Base {
    hash_to_field("CoppiceN2NID", &name_id)
}

/// Hashes bytes under an explicit v2 domain.
pub(crate) fn hash_bytes(label: &str, bytes: &[u8]) -> [u8; 32] {
    crypto::hash(label, bytes).expect("v2 hash labels are fixed and <= 16 bytes")
}

/// Hashes bytes into the Pallas base field using 512 bits of input material.
pub(crate) fn hash_to_field(label: &str, bytes: &[u8]) -> pallas::Base {
    let personal =
        crypto::personalization(label).expect("v2 hash labels are fixed and <= 16 bytes");
    let digest = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(&personal)
        .hash(bytes);
    let wide: [u8; 64] = digest
        .as_bytes()
        .try_into()
        .expect("fixed 64-byte field hash");
    pallas::Base::from_uniform_bytes(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::circuit::state_note_binding::spend_auth_owner_key_bytes;
    use orchard::keys::{SpendAuthorizingKey, SpendingKey};

    #[test]
    fn owner_field_requires_a_real_non_identity_ak() {
        let spending_key = SpendingKey::from_bytes([7; 32]).unwrap();
        let ask = SpendAuthorizingKey::from(&spending_key);
        assert!(owner_key_field(spend_auth_owner_key_bytes(&ask)).is_ok());
        assert_eq!(owner_key_field([0; 32]), Err(StateError::InvalidOwner));
        let invalid_curve_encoding = (1..10_000u64)
            .map(|value| pallas::Base::from(value).to_repr())
            .find(|bytes| crate::owner::parse_v1_owner_key(*bytes).is_err())
            .expect("a small canonical field search finds a non-key encoding");
        assert_eq!(
            owner_key_field(invalid_curve_encoding),
            Err(StateError::InvalidOwner)
        );
    }
}
