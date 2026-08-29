use super::*;
use crate::v1::{
    CommitRef, ProducerPosition, RegistrationIntent, StateData, StateRef, StateStatus,
};
use orchard::{
    circuit::state_note_binding::spend_auth_owner_key_bytes,
    keys::{SpendAuthorizingKey, SpendingKey},
};
use pasta_curves::{group::ff::PrimeField, pallas};

#[test]
fn commit_encoding_is_canonical_and_superseded_prefixes_are_rejected() {
    let operation = V1Operation::Commit {
        commitment: [7; 32],
    };
    let bytes = encode_operation(&operation).unwrap();
    assert_eq!(&bytes[..5], b"CNV1\x01");
    assert_eq!(decode_operation(&bytes).unwrap(), operation);
    let mut old_revision = bytes.clone();
    old_revision[4] = 2;
    assert_eq!(
        decode_operation(&old_revision),
        Err(WireError::WrongVersion)
    );
    let mut wrong = bytes;
    wrong[3] = b'2';
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
    let predecessor = StateRef::new(ProducerPosition::new(1, 0, [3; 32]), 0, 0, [4; 32], [5; 32]);
    let update = V1Operation::Update {
        predecessor,
        state,
        state_commitment: [6; 32],
        state_nullifier: [7; 32],
        action_index: 1,
        proof: Vec::new(),
    };
    let commit = V1Operation::Commit {
        commitment: [8; 32],
    };
    let noncanonical = [update, commit];
    assert_eq!(
        encode_operations(&noncanonical),
        Err(WireError::InvalidEncoding)
    );

    // Model hostile bytes without going through the canonical encoder.
    let mut bytes = Vec::from(MAGIC.as_slice());
    bytes.push(CNV1_WIRE_VERSION);
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
    let reveal = V1Operation::Reveal {
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
    let update = V1Operation::Update {
        predecessor,
        state: successor.clone(),
        state_commitment: pallas::Base::from(13).to_repr(),
        state_nullifier: pallas::Base::from(14).to_repr(),
        action_index: 0,
        proof: vec![0; 4_640],
    };
    successor.record.pop();
    successor.lease_expiry = 2_000;
    let renew = V1Operation::Renew {
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
