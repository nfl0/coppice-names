//! Canonical Names v1 application-envelope encoding.

use super::operation::{V1Operation, operations_have_canonical_order};
use super::{NAMES_APPLICATION_VERSION, names_application_id};
use coppice::application::{ApplicationEnvelopeV1, ApplicationKey};

const MAGIC: &[u8; 4] = b"CNV1";
/// Names v1 envelope revision.
///
/// The v1 reset deliberately uses a fresh CNV1 prefix and revision byte, so
/// bytes from the abandoned corrected-v2 experiment are rejected at the
/// decoder boundary.
pub const CNV1_WIRE_VERSION: u8 = 1;

/// Errors from the Names v1 wire codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The envelope magic or wire version is not Names v1.
    WrongVersion,
    /// The payload is malformed or has a non-canonical encoding.
    InvalidEncoding,
    /// The operation cannot fit the frozen CPV1 transport.
    TooLarge,
}

/// Encoded operation, proof, and CPV1 transport footprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationFootprint {
    /// Complete v1 operation-envelope bytes.
    pub operation_bytes: usize,
    /// Proof bytes carried by this operation.
    pub proof_bytes: usize,
    /// Frozen CPV1 frame count.
    pub cpv1_frames: usize,
    /// Minimum Ironwood actions with unrestricted cross-address pairing,
    /// excluding fee-funding and change effects.
    pub minimum_ironwood_actions: usize,
}

/// Encodes one operation under an unambiguous Names-v1-only prefix.
pub fn encode_operation(operation: &V1Operation) -> Result<Vec<u8>, WireError> {
    encode_operations(core::slice::from_ref(operation))
}

/// Encodes the canonically ordered v1 messages carried by one transaction.
pub fn encode_operations(operations: &[V1Operation]) -> Result<Vec<u8>, WireError> {
    if !operations_have_canonical_order(operations) {
        return Err(WireError::InvalidEncoding);
    }
    let encoded = postcard::to_allocvec(operations).map_err(|_| WireError::InvalidEncoding)?;
    let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + encoded.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(CNV1_WIRE_VERSION);
    bytes.extend_from_slice(&encoded);
    if bytes.len() > coppice::carrier::MAX_CPV1_PAYLOAD_LEN {
        return Err(WireError::TooLarge);
    }
    Ok(bytes)
}

/// Decodes one canonical Names v1 operation and rejects alternate encodings.
pub fn decode_operation(bytes: &[u8]) -> Result<V1Operation, WireError> {
    let mut operations = decode_operations(bytes)?;
    if operations.len() != 1 {
        return Err(WireError::InvalidEncoding);
    }
    Ok(operations.remove(0))
}

/// Decodes one canonical ordered v1 message list.
pub fn decode_operations(bytes: &[u8]) -> Result<Vec<V1Operation>, WireError> {
    if bytes.get(..MAGIC.len()) != Some(MAGIC)
        || bytes.get(MAGIC.len()).copied() != Some(CNV1_WIRE_VERSION)
    {
        return Err(WireError::WrongVersion);
    }
    let operations = postcard::from_bytes::<Vec<V1Operation>>(&bytes[MAGIC.len() + 1..])
        .map_err(|_| WireError::InvalidEncoding)?;
    if operations.is_empty()
        || encode_operations(&operations).map_err(|_| WireError::InvalidEncoding)? != bytes
    {
        return Err(WireError::InvalidEncoding);
    }
    Ok(operations)
}

/// Measures the exact CPV1 footprint without changing Core framing limits.
pub fn operation_footprint(operation: &V1Operation) -> Result<OperationFootprint, WireError> {
    let bytes = encode_operation(operation)?;
    let proof_bytes = match operation {
        V1Operation::Commit { .. } => 0,
        V1Operation::Reveal { proof, .. }
        | V1Operation::Update { proof, .. }
        | V1Operation::Renew { proof, .. }
        | V1Operation::Release { proof, .. } => proof.len(),
    };
    let envelope = ApplicationEnvelopeV1::new(
        ApplicationKey::new(names_application_id(), NAMES_APPLICATION_VERSION),
        bytes.clone(),
    )
    .map_err(|_| WireError::TooLarge)?
    .encode();
    let cpv1_frames =
        coppice::transport::required_frames(envelope.len()).map_err(|_| WireError::TooLarge)?;
    // Every CPV1 memo frame requires a distinct rendezvous output. State
    // operations add one successor state-note output; their one designated
    // spend can share that action when cross-address pairing is enabled.
    let minimum_ironwood_actions = match operation {
        V1Operation::Commit { .. } => cpv1_frames,
        V1Operation::Reveal { .. }
        | V1Operation::Update { .. }
        | V1Operation::Renew { .. }
        | V1Operation::Release { .. } => cpv1_frames.checked_add(1).ok_or(WireError::TooLarge)?,
    };
    Ok(OperationFootprint {
        operation_bytes: bytes.len(),
        proof_bytes,
        cpv1_frames,
        minimum_ironwood_actions,
    })
}

#[cfg(test)]
#[path = "tests/wire.rs"]
mod tests;
