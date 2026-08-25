use crate::{
    envelope::Operation,
    owner,
    record::{self, NameRecord},
    registration::address_digest,
};
use orchard::primitives::redpallas::Signature;
use rand_core::OsRng;

const OWNER_SIGNATURE_PREFIX: &[u8] = b"CoppiceOwnerSigV1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1AuthorizationError {
    UnsupportedOperation,
    RecordHash(record::RecordEncodingError),
}

fn prefix(deployment_id: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(OWNER_SIGNATURE_PREFIX.len() + 32);
    bytes.extend_from_slice(OWNER_SIGNATURE_PREFIX);
    bytes.extend_from_slice(&deployment_id);
    bytes
}

pub fn update_authorization_message(
    deployment_id: [u8; 32],
    name: &str,
    previous_record_hash: [u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    new_address: &[u8],
) -> Vec<u8> {
    let mut bytes = prefix(deployment_id);
    bytes.push(0x03);
    bytes.extend_from_slice(&owner::name_id(name));
    bytes.extend_from_slice(&previous_record_hash);
    bytes.extend_from_slice(&previous_sequence.to_be_bytes());
    bytes.extend_from_slice(&next_sequence.to_be_bytes());
    bytes.extend_from_slice(&address_digest(new_address));
    bytes
}

pub fn release_authorization_message(
    deployment_id: [u8; 32],
    name: &str,
    previous_record_hash: [u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
) -> Vec<u8> {
    let mut bytes = prefix(deployment_id);
    bytes.push(0x04);
    bytes.extend_from_slice(&owner::name_id(name));
    bytes.extend_from_slice(&previous_record_hash);
    bytes.extend_from_slice(&previous_sequence.to_be_bytes());
    bytes.extend_from_slice(&next_sequence.to_be_bytes());
    bytes
}

pub fn authorization_message_v1(
    deployment_id: [u8; 32],
    operation: &Operation,
    previous: &NameRecord,
) -> Result<Vec<u8>, V1AuthorizationError> {
    match operation {
        Operation::Update {
            name,
            sequence,
            address,
            ..
        } => {
            let previous_record_hash =
                record::record_hash(previous).map_err(V1AuthorizationError::RecordHash)?;
            Ok(update_authorization_message(
                deployment_id,
                name,
                previous_record_hash,
                previous.sequence,
                *sequence,
                address,
            ))
        }
        Operation::Release { name, sequence, .. } => {
            let previous_record_hash =
                record::record_hash(previous).map_err(V1AuthorizationError::RecordHash)?;
            Ok(release_authorization_message(
                deployment_id,
                name,
                previous_record_hash,
                previous.sequence,
                *sequence,
            ))
        }
        _ => Err(V1AuthorizationError::UnsupportedOperation),
    }
}

pub fn sign_v1(
    deployment_id: [u8; 32],
    key: &owner::OwnerSigningKey,
    operation: &Operation,
    previous: &NameRecord,
) -> Result<[u8; 64], V1AuthorizationError> {
    let message = authorization_message_v1(deployment_id, operation, previous)?;
    Ok(<[u8; 64]>::from(&key.sign(OsRng, &message)))
}

pub fn verify_v1(deployment_id: [u8; 32], operation: &Operation, previous: &NameRecord) -> bool {
    let signature = match operation {
        Operation::Update { signature, .. } | Operation::Release { signature, .. } => signature,
        _ => return false,
    };
    let Ok(signature): Result<[u8; 64], _> = signature.as_slice().try_into() else {
        return false;
    };
    let Ok(key) = owner::parse_v1_owner_key(previous.owner_pk) else {
        return false;
    };
    let Ok(message) = authorization_message_v1(deployment_id, operation, previous) else {
        return false;
    };
    key.verify(&message, &Signature::from(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const DEPLOYMENT_ID: &str = "0f769b29c0ed5c5f9a101300e15c846ca15aeae2198043da3e785f839a56f5d7";

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn operations_fixture() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/operations.json")).unwrap()
    }

    fn vector<'a>(fixture: &'a Value, id: &str) -> &'a Value {
        fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"].as_str() == Some(id))
            .unwrap()
    }

    fn expected_bytes(fixture: &Value, id: &str) -> Vec<u8> {
        hex::decode(vector(fixture, id)["expected_hex"].as_str().unwrap()).unwrap()
    }

    fn previous_record_hash() -> [u8; 32] {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../test-vectors/records.json")).unwrap();
        let active = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"].as_str() == Some("active"))
            .unwrap();
        fixed32(active["record_hash_hex"].as_str().unwrap())
    }

    fn frozen_active_record() -> NameRecord {
        NameRecord {
            owner_pk: core::array::from_fn(|index| index as u8),
            bond_tag: [0x42; 32],
            sequence: 0,
            address: b"u1synthetic-conformance-address".to_vec(),
            status: record::NameStatus::Active,
        }
    }

    fn valid_record(key: &owner::OwnerSigningKey) -> NameRecord {
        NameRecord {
            owner_pk: owner::owner_key_bytes(&key.into()),
            bond_tag: [0x42; 32],
            sequence: 0,
            address: b"u1synthetic-conformance-address".to_vec(),
            status: record::NameStatus::Active,
        }
    }

    fn update_operation(sequence: u64, address: &[u8]) -> Operation {
        Operation::Update {
            name: "alice".into(),
            sequence,
            address: address.to_vec(),
            signature: Vec::new(),
        }
    }

    fn release_operation(sequence: u64) -> Operation {
        Operation::Release {
            name: "alice".into(),
            sequence,
            signature: Vec::new(),
        }
    }

    fn install_signature(operation: &mut Operation, signature: [u8; 64]) {
        match operation {
            Operation::Update {
                signature: output, ..
            }
            | Operation::Release {
                signature: output, ..
            } => *output = signature.to_vec(),
            _ => panic!("expected UPDATE or RELEASE"),
        }
    }

    #[test]
    fn update_owner_message_vector_matches() {
        let fixture = operations_fixture();
        let previous = frozen_active_record();
        assert_eq!(
            record::record_hash(&previous).unwrap(),
            previous_record_hash()
        );
        let operation = update_operation(1, b"u1synthetic-new-address");
        let actual =
            authorization_message_v1(fixed32(DEPLOYMENT_ID), &operation, &previous).unwrap();
        assert_eq!(actual, expected_bytes(&fixture, "update-owner-message"));
    }

    #[test]
    fn release_owner_message_vector_matches() {
        let fixture = operations_fixture();
        let previous = frozen_active_record();
        assert_eq!(
            record::record_hash(&previous).unwrap(),
            previous_record_hash()
        );
        let operation = release_operation(1);
        let actual =
            authorization_message_v1(fixed32(DEPLOYMENT_ID), &operation, &previous).unwrap();
        assert_eq!(actual, expected_bytes(&fixture, "release-owner-message"));
    }

    #[test]
    fn presentation_suffix_does_not_change_owner_authorization_bytes() {
        let deployment_id = fixed32(DEPLOYMENT_ID);
        let previous_hash = previous_record_hash();
        assert_eq!(
            update_authorization_message(deployment_id, "alice", previous_hash, 0, 1, b"UA_B",),
            update_authorization_message(deployment_id, "alice.zec", previous_hash, 0, 1, b"UA_B",)
        );
        assert_eq!(
            release_authorization_message(deployment_id, "alice", previous_hash, 0, 1),
            release_authorization_message(deployment_id, "alice.zec", previous_hash, 0, 1)
        );
    }

    #[test]
    fn v1_update_signature_round_trip() {
        let deployment_id = fixed32(DEPLOYMENT_ID);
        let key = owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let previous = valid_record(&key);
        let mut operation = update_operation(1, b"UA_B");

        let signature = sign_v1(deployment_id, &key, &operation, &previous).unwrap();
        install_signature(&mut operation, signature);

        assert!(verify_v1(deployment_id, &operation, &previous));
    }

    #[test]
    fn v1_release_signature_round_trip() {
        let deployment_id = fixed32(DEPLOYMENT_ID);
        let key = owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let previous = valid_record(&key);
        let mut operation = release_operation(1);

        let signature = sign_v1(deployment_id, &key, &operation, &previous).unwrap();
        install_signature(&mut operation, signature);

        assert!(verify_v1(deployment_id, &operation, &previous));
    }

    #[test]
    fn v1_signature_negative_cases() {
        let deployment_id = fixed32(DEPLOYMENT_ID);
        let key = owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let previous = valid_record(&key);
        let mut update = update_operation(1, b"UA_B");
        let update_signature = sign_v1(deployment_id, &key, &update, &previous).unwrap();
        install_signature(&mut update, update_signature);
        assert!(verify_v1(deployment_id, &update, &previous));

        assert!(!verify_v1([0xff; 32], &update, &previous));

        let mut wrong_name = update.clone();
        if let Operation::Update { name, .. } = &mut wrong_name {
            *name = "bob".into();
        }
        assert!(!verify_v1(deployment_id, &wrong_name, &previous));

        let mut wrong_previous = previous.clone();
        wrong_previous.address.push(b'!');
        assert!(!verify_v1(deployment_id, &update, &wrong_previous));

        let mut wrong_sequence = update.clone();
        if let Operation::Update { sequence, .. } = &mut wrong_sequence {
            *sequence = 2;
        }
        assert!(!verify_v1(deployment_id, &wrong_sequence, &previous));

        let mut wrong_address = update.clone();
        if let Operation::Update { address, .. } = &mut wrong_address {
            *address = b"UA_C".to_vec();
        }
        assert!(!verify_v1(deployment_id, &wrong_address, &previous));

        let other_key = owner::OwnerSigningKey::try_from([2; 32]).unwrap();
        let mut wrong_owner = previous.clone();
        wrong_owner.owner_pk = owner::owner_key_bytes(&(&other_key).into());
        assert!(!verify_v1(deployment_id, &update, &wrong_owner));

        let mut identity_owner = previous.clone();
        identity_owner.owner_pk = [0; 32];
        assert!(!verify_v1(deployment_id, &update, &identity_owner));

        let mut short_signature = update.clone();
        if let Operation::Update { signature, .. } = &mut short_signature {
            signature.truncate(63);
        }
        assert!(!verify_v1(deployment_id, &short_signature, &previous));

        let mut long_signature = update.clone();
        if let Operation::Update { signature, .. } = &mut long_signature {
            signature.push(0);
        }
        assert!(!verify_v1(deployment_id, &long_signature, &previous));

        let mut flipped_signature = update.clone();
        if let Operation::Update { signature, .. } = &mut flipped_signature {
            signature[0] ^= 1;
        }
        assert!(!verify_v1(deployment_id, &flipped_signature, &previous));

        let mut release = release_operation(1);
        let release_signature = sign_v1(deployment_id, &key, &release, &previous).unwrap();
        install_signature(&mut release, release_signature);
        let release_bytes = match &release {
            Operation::Release { signature, .. } => signature.clone(),
            _ => unreachable!(),
        };
        let update_bytes = match &update {
            Operation::Update { signature, .. } => signature.clone(),
            _ => unreachable!(),
        };
        let mut update_with_release_signature = update.clone();
        if let Operation::Update { signature, .. } = &mut update_with_release_signature {
            *signature = release_bytes;
        }
        assert!(!verify_v1(
            deployment_id,
            &update_with_release_signature,
            &previous
        ));
        let mut release_with_update_signature = release.clone();
        if let Operation::Release { signature, .. } = &mut release_with_update_signature {
            *signature = update_bytes;
        }
        assert!(!verify_v1(
            deployment_id,
            &release_with_update_signature,
            &previous
        ));
    }

    #[test]
    fn v1_message_reconstruction_reports_operation_and_record_errors() {
        let deployment_id = fixed32(DEPLOYMENT_ID);
        let key = owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let previous = valid_record(&key);
        let commit = Operation::Commit {
            commitment: [0; 32],
        };
        assert_eq!(
            authorization_message_v1(deployment_id, &commit, &previous),
            Err(V1AuthorizationError::UnsupportedOperation)
        );

        let mut invalid_previous = previous;
        invalid_previous.status = record::NameStatus::Released { terminal_height: 0 };
        assert_eq!(
            authorization_message_v1(
                deployment_id,
                &update_operation(1, b"UA_B"),
                &invalid_previous,
            ),
            Err(V1AuthorizationError::RecordHash(
                record::RecordEncodingError::InvalidTerminalHeight
            ))
        );
    }

    #[test]
    fn v1_signature_does_not_enforce_sequence_increment() {
        let deployment_id = fixed32(DEPLOYMENT_ID);
        let key = owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let previous = valid_record(&key);
        let mut skipped = update_operation(2, b"UA_B");
        let signature = sign_v1(deployment_id, &key, &skipped, &previous).unwrap();
        install_signature(&mut skipped, signature);

        assert!(verify_v1(deployment_id, &skipped, &previous));
    }
}
