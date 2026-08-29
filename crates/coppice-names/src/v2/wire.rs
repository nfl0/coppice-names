//! Canonical Names v2 application-envelope encoding.

use super::operation::{V2Operation, operations_have_canonical_order};

const MAGIC: &[u8; 4] = b"CNV2";
/// Corrected Names v2 envelope revision.
///
/// Revision 1 was the pre-correction proof envelope. Revision 2 is the
/// release artifact for the complete local-transition proof and deliberately
/// rejects revision-1 operation bytes at the decoder boundary.
pub const CNV2_WIRE_VERSION: u8 = 2;

/// Errors from the Names v2 wire codec.
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
    /// Minimum Ironwood actions with unrestricted cross-address pairing,
    /// excluding fee-funding and change effects.
    pub minimum_ironwood_actions: usize,
}

/// Encodes one operation under an unambiguous Names-v2-only prefix.
pub fn encode_operation(operation: &V2Operation) -> Result<Vec<u8>, WireError> {
    encode_operations(core::slice::from_ref(operation))
}

/// Encodes the canonically ordered v2 messages carried by one transaction.
pub fn encode_operations(operations: &[V2Operation]) -> Result<Vec<u8>, WireError> {
    if !operations_have_canonical_order(operations) {
        return Err(WireError::InvalidEncoding);
    }
    let encoded = postcard::to_allocvec(operations).map_err(|_| WireError::InvalidEncoding)?;
    let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + encoded.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(CNV2_WIRE_VERSION);
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
        || bytes.get(MAGIC.len()).copied() != Some(CNV2_WIRE_VERSION)
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
    // Every CPV1 memo frame requires a distinct rendezvous output. State
    // operations add one successor state-note output; their one designated
    // spend can share that action when cross-address pairing is enabled.
    let minimum_ironwood_actions = match operation {
        V2Operation::Commit { .. } => cpv1_frames,
        V2Operation::Reveal { .. }
        | V2Operation::Update { .. }
        | V2Operation::Renew { .. }
        | V2Operation::Release { .. } => cpv1_frames.checked_add(1).ok_or(WireError::TooLarge)?,
    };
    Ok(OperationFootprint {
        operation_bytes: bytes.len(),
        proof_bytes,
        cpv1_frames,
        minimum_ironwood_actions,
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
        assert_eq!(&bytes[..5], b"CNV2\x02");
        assert_eq!(decode_operation(&bytes).unwrap(), operation);
        let mut old_revision = bytes.clone();
        old_revision[4] = 1;
        assert_eq!(
            decode_operation(&old_revision),
            Err(WireError::WrongVersion)
        );
        let mut wrong = bytes;
        wrong[3] = b'1';
        assert_eq!(decode_operation(&wrong), Err(WireError::WrongVersion));
    }

    #[test]
    fn noncanonical_operation_order_is_rejected_at_the_wire_boundary() {
        let state = StateData {
            name_id: [1; 32],
            owner_pk: [2; 32],
            sequence: 1,
            record: Vec::new(),
            lease_expiry: 10,
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let predecessor =
            StateRef::new(ProducerPosition::new(1, 0, [3; 32]), 0, 0, [4; 32], [5; 32]);
        let update = V2Operation::Update {
            predecessor,
            state,
            state_commitment: [6; 32],
            state_nullifier: [7; 32],
            action_index: 1,
            proof: Vec::new(),
        };
        let commit = V2Operation::Commit {
            commitment: [8; 32],
        };
        let noncanonical = [update, commit];
        assert_eq!(
            encode_operations(&noncanonical),
            Err(WireError::InvalidEncoding)
        );

        // Model hostile bytes without going through the canonical encoder.
        let mut bytes = Vec::from(MAGIC.as_slice());
        bytes.push(CNV2_WIRE_VERSION);
        bytes.extend(postcard::to_allocvec(&noncanonical).unwrap());
        assert_eq!(decode_operations(&bytes), Err(WireError::InvalidEncoding));
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
                    minimum_ironwood_actions: 12,
                },
                OperationFootprint {
                    operation_bytes: 4_950,
                    proof_bytes: 4_640,
                    cpv1_frames: 10,
                    minimum_ironwood_actions: 11,
                },
                OperationFootprint {
                    operation_bytes: 4_949,
                    proof_bytes: 4_640,
                    cpv1_frames: 10,
                    minimum_ironwood_actions: 11,
                },
            ]
        );
    }
}
