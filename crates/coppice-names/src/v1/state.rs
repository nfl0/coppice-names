//! Canonical values for the Names state-note lineage.
//!
//! The v1 state is deliberately a value object. It has no application root
//! and no implicit transaction identity; the producer position is carried by
//! [`StateRef`] and is authenticated by the resolver when it follows a
//! lineage.

use orchard::circuit::state_note_binding::{
    STATUS_ACTIVE, STATUS_RELEASED, StateMetadata as OrchardStateMetadata, native_state_digest,
};
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};
use pasta_curves::group::ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

/// Maximum destination/record size.
pub const MAX_RECORD_BYTES: usize = 1024;
/// Maximum canonical bare-name length.
pub const MAX_NAME_LEN: usize = 63;

/// The canonical 32-byte name identifier used by v1.
pub type NameId = [u8; 32];
/// The canonical Ironwood `ak`/RedPallas SpendAuth validating-key encoding
/// used by v1.
pub type OwnerKey = [u8; 32];

/// Errors from canonical v1 state construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// The name is not a canonical bare label.
    InvalidName,
    /// The owner key is not a non-identity canonical Ironwood `ak` key.
    InvalidOwner,
    /// A state commitment or digest is not a canonical Pallas field encoding.
    InvalidField,
    /// The destination/record exceeds the Names v1 bound.
    RecordTooLarge,
    /// Active states cannot carry a terminal height.
    ActiveTerminalHeight,
    /// Released states must carry a nonzero terminal height.
    ReleasedTerminalHeight,
    /// The state reference does not name the supplied commitment.
    ReferenceCommitmentMismatch,
}

/// The only state statuses in the v1 milestone.
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

/// The canonical, non-note portion of a v1 name state.
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
    /// Exact v1 carrier-message index that declared this state note.
    pub producer_operation_index: u32,
    /// The state-note commitment created by that action.
    pub commitment: [u8; 32],
    /// Authenticated future nullifier of that state note.
    pub nullifier: [u8; 32],
}

impl StateRef {
    /// Constructs a state reference from a transaction position and action.
    pub const fn new(
        position: ProducerPosition,
        action_index: u32,
        operation_index: u32,
        commitment: [u8; 32],
        nullifier: [u8; 32],
    ) -> Self {
        Self {
            producer_height: position.height,
            producer_tx_index: position.tx_index,
            producer_txid: position.txid,
            producer_action_index: action_index,
            producer_operation_index: operation_index,
            commitment,
            nullifier,
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

    /// Returns the explicit v1 field binding used in a transition proof.
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(4 + 4 + 32 + 4 + 4 + 32 + 32);
        bytes.extend_from_slice(&self.producer_height.to_be_bytes());
        bytes.extend_from_slice(&self.producer_tx_index.to_be_bytes());
        bytes.extend_from_slice(&self.producer_txid);
        bytes.extend_from_slice(&self.producer_action_index.to_be_bytes());
        bytes.extend_from_slice(&self.producer_operation_index.to_be_bytes());
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.nullifier);
        hash_to_field("CoppiceN1Ref", &bytes).to_repr()
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
    /// Canonical height that spent this note without an accepted Names
    /// successor transition. This is derived from ordinary nullifier effects,
    /// not part of the proof-authenticated state payload.
    pub abandoned_height: Option<u32>,
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
        canonical_field(state_ref.nullifier)?;
        let state_digest = state_digest(&data, commitment);
        Ok(Self {
            data,
            commitment,
            state_ref,
            state_digest,
            abandoned_height: None,
        })
    }

    /// Returns true only while this state is active and its lease is live.
    pub fn is_active_at(&self, height: u32) -> bool {
        self.abandoned_height.is_none()
            && self.data.status == StateStatus::Active
            && height < self.data.lease_expiry
    }

    /// Marks the current note as ordinarily spent without a Names successor.
    pub fn abandon(&mut self, height: u32) {
        self.abandoned_height.get_or_insert(height);
    }
}

/// Computes the deterministic name identifier after canonical name validation.
pub fn name_id(name: &str) -> Result<NameId, StateError> {
    let canonical = normalize_name(name)?;
    Ok(hash_bytes("CoppiceN1Name", canonical.as_bytes()))
}

/// Normalizes a presented name to its canonical bare-label form.
fn normalize_name(name: &str) -> Result<String, StateError> {
    let bare = name.strip_suffix(".zec").unwrap_or(name);
    if bare.is_empty()
        || bare.len() > MAX_NAME_LEN
        || !bare.is_ascii()
        || bare
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
        || bare.starts_with('-')
        || bare.ends_with('-')
    {
        return Err(StateError::InvalidName);
    }
    Ok(bare.to_owned())
}

/// Computes the explicit v1 record digest field.
pub fn record_digest_field(record: &[u8]) -> pallas::Base {
    let mut bytes = Vec::with_capacity(4 + record.len());
    bytes.extend_from_slice(&(u32::try_from(record.len()).unwrap_or(u32::MAX)).to_be_bytes());
    bytes.extend_from_slice(record);
    hash_to_field("CoppiceN1Rec", &bytes)
}

/// Returns the canonical field encoding of an Ironwood `ak` key.
pub fn owner_key_field(owner_pk: OwnerKey) -> Result<pallas::Base, StateError> {
    // `ak` is serialized as a RedPallas SpendAuth verification key. Checking
    // only that its bytes fit in the Pallas base field would admit arbitrary
    // field values that do not encode a valid spend-authorizing authority.
    let key =
        VerificationKey::<SpendAuth>::try_from(owner_pk).map_err(|_| StateError::InvalidOwner)?;
    if key.is_identity() {
        return Err(StateError::InvalidOwner);
    }
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

/// Computes the state digest used by the Orchard state-note circuit.
pub fn state_digest(data: &StateData, commitment: [u8; 32]) -> [u8; 32] {
    let name_field = name_id_field(data.name_id);
    let owner_field = owner_key_field(data.owner_pk).expect("validated state owner");
    let commitment_field = canonical_field(commitment).expect("validated state commitment");
    native_state_digest(name_field, owner_field, data.metadata(), commitment_field).to_repr()
}

/// Maps the canonical byte name identifier into the circuit's field domain.
pub fn name_id_field(name_id: NameId) -> pallas::Base {
    hash_to_field("CoppiceN1NID", &name_id)
}

/// Hashes bytes under an explicit v1 domain.
pub(crate) fn hash_bytes(label: &str, bytes: &[u8]) -> [u8; 32] {
    let personal = personalization(label);
    let digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(&personal)
        .hash(bytes);
    digest.as_bytes().try_into().expect("fixed 32-byte hash")
}

/// Hashes bytes into the Pallas base field using 512 bits of input material.
pub(crate) fn hash_to_field(label: &str, bytes: &[u8]) -> pallas::Base {
    let personal = personalization(label);
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

fn personalization(label: &str) -> [u8; 16] {
    let bytes = label.as_bytes();
    assert!(
        bytes.len() <= 16,
        "v1 hash labels are fixed and <= 16 bytes"
    );
    let mut personal = [0u8; 16];
    personal[..bytes.len()].copy_from_slice(bytes);
    personal
}

#[cfg(test)]
#[path = "tests/state.rs"]
mod tests;
