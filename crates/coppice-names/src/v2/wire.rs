//! Canonical experimental Names v2 application-envelope encoding.

use super::operation::V2Operation;

const MAGIC: &[u8; 4] = b"CNV2";
const WIRE_VERSION: u8 = 1;

/// Errors from the experimental v2 wire codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The envelope magic or wire version is not Names v2.
    WrongVersion,
    /// The payload is malformed or has a non-canonical encoding.
    InvalidEncoding,
    /// The operation cannot fit the frozen CPV1 transport.
    TooLarge,
}

/// Encoded operation, proof, and CPV1 transport footprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationFootprint {
    /// Complete v2 operation-envelope bytes.
    pub operation_bytes: usize,
    /// Proof bytes carried by this operation.
    pub proof_bytes: usize,
    /// Frozen CPV1 frame count.
    pub cpv1_frames: usize,
}

/// Encodes one operation under an unambiguous Names-v2-only prefix.
pub fn encode_operation(operation: &V2Operation) -> Result<Vec<u8>, WireError> {
    encode_operations(core::slice::from_ref(operation))
}

/// Encodes the canonically ordered v2 messages carried by one transaction.
pub fn encode_operations(operations: &[V2Operation]) -> Result<Vec<u8>, WireError> {
    let encoded = postcard::to_allocvec(operations).map_err(|_| WireError::InvalidEncoding)?;
    let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + encoded.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(WIRE_VERSION);
    bytes.extend_from_slice(&encoded);
    if bytes.len() > coppice::carrier::MAX_CPV1_PAYLOAD_LEN {
        return Err(WireError::TooLarge);
    }
    Ok(bytes)
}

/// Decodes one canonical Names v2 operation and rejects alternate encodings.
pub fn decode_operation(bytes: &[u8]) -> Result<V2Operation, WireError> {
    let mut operations = decode_operations(bytes)?;
    if operations.len() != 1 {
        return Err(WireError::InvalidEncoding);
    }
    Ok(operations.remove(0))
}

/// Decodes one canonical ordered v2 message list.
pub fn decode_operations(bytes: &[u8]) -> Result<Vec<V2Operation>, WireError> {
    if bytes.get(..MAGIC.len()) != Some(MAGIC)
        || bytes.get(MAGIC.len()).copied() != Some(WIRE_VERSION)
    {
        return Err(WireError::WrongVersion);
    }
    let operations = postcard::from_bytes::<Vec<V2Operation>>(&bytes[MAGIC.len() + 1..])
        .map_err(|_| WireError::InvalidEncoding)?;
    if operations.is_empty()
        || encode_operations(&operations).map_err(|_| WireError::InvalidEncoding)? != bytes
    {
        return Err(WireError::InvalidEncoding);
    }
    Ok(operations)
}

/// Measures the exact CPV1 footprint without changing Core framing limits.
pub fn operation_footprint(operation: &V2Operation) -> Result<OperationFootprint, WireError> {
    let bytes = encode_operation(operation)?;
    let proof_bytes = match operation {
        V2Operation::Commit { .. } => 0,
        V2Operation::Reveal { proof, .. }
        | V2Operation::Update { proof, .. }
        | V2Operation::Renew { proof, .. }
        | V2Operation::Release { proof, .. } => proof.len(),
    };
    let cpv1_frames =
        coppice::transport::required_frames(bytes.len()).map_err(|_| WireError::TooLarge)?;
    Ok(OperationFootprint {
        operation_bytes: bytes.len(),
        proof_bytes,
        cpv1_frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{
        CommitRef, ProducerPosition, RegistrationIntent, StateData, StateRef, StateStatus,
    };
    use orchard::{
        circuit::state_note_binding::spend_auth_owner_key_bytes,
        keys::{SpendAuthorizingKey, SpendingKey},
    };
    use pasta_curves::{group::ff::PrimeField, pallas};

    #[test]
    fn commit_encoding_is_canonical_and_v1_ambiguous_prefixes_are_rejected() {
        let operation = V2Operation::Commit {
            commitment: [7; 32],
        };
        let bytes = encode_operation(&operation).unwrap();
        assert_eq!(&bytes[..5], b"CNV2\x01");
        assert_eq!(decode_operation(&bytes).unwrap(), operation);
        let mut wrong = bytes;
        wrong[3] = b'1';
        assert_eq!(decode_operation(&wrong), Err(WireError::WrongVersion));
    }

    #[test]
    fn realistic_proof_operations_fit_frozen_cpv1() {
        let ask = SpendAuthorizingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap());
        let owner_pk = spend_auth_owner_key_bytes(&ask);
        let intent = RegistrationIntent {
            name: "footprint".to_owned(),
            owner_pk,
            record: vec![9; 64],
            secret: [8; 32],
        };
        let name_id = intent.name_id().unwrap();
        let commitment = pallas::Base::from(11).to_repr();
        let nullifier = pallas::Base::from(12).to_repr();
        let state = StateData {
            name_id,
            owner_pk,
            sequence: 0,
            record: intent.record.clone(),
            lease_expiry: 1_000,
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let commit = CommitRef::new(
            ProducerPosition::new(900, 1, [3; 32]),
            0,
            intent.commitment().unwrap(),
        );
        let reveal = V2Operation::Reveal {
            intent: Box::new(intent),
            commit,
            replacement_predecessor: None,
            state: state.clone(),
            state_commitment: commitment,
            state_nullifier: nullifier,
            action_index: 0,
            proof: vec![0; 4_640],
        };
        let predecessor = StateRef::new(
            ProducerPosition::new(950, 2, [4; 32]),
            0,
            0,
            commitment,
            nullifier,
        );
        let mut successor = state;
        successor.sequence = 1;
        successor.record.push(1);
        let update = V2Operation::Update {
            predecessor,
            state: successor.clone(),
            state_commitment: pallas::Base::from(13).to_repr(),
            state_nullifier: pallas::Base::from(14).to_repr(),
            action_index: 0,
            proof: vec![0; 4_640],
        };
        successor.record.pop();
        successor.lease_expiry = 2_000;
        let renew = V2Operation::Renew {
            predecessor,
            state: successor,
            state_commitment: pallas::Base::from(15).to_repr(),
            state_nullifier: pallas::Base::from(16).to_repr(),
            action_index: 0,
            proof: vec![0; 4_640],
        };
        let footprints = [
            operation_footprint(&reveal).unwrap(),
            operation_footprint(&update).unwrap(),
            operation_footprint(&renew).unwrap(),
        ];
        assert_eq!(
            footprints,
            [
                OperationFootprint {
                    operation_bytes: 5_056,
                    proof_bytes: 4_640,
                    cpv1_frames: 11,
                },
                OperationFootprint {
                    operation_bytes: 4_950,
                    proof_bytes: 4_640,
                    cpv1_frames: 10,
                },
                OperationFootprint {
                    operation_bytes: 4_949,
                    proof_bytes: 4_640,
                    cpv1_frames: 10,
                },
            ]
        );
    }
}
