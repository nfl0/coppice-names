//! Frozen Names v2 CNV2 wire vectors.
//!
//! `test-vectors/names_v2_wire.json` is immutable protocol evidence generated
//! from the reference implementation. The conformance test consumes the file
//! without regenerating expected values. The ignored generator test is the
//! documented regeneration path for a future protocol-version bump only; its
//! output must never replace the frozen file silently.

use coppice_names::v2::{
    CommitRef, ProducerPosition, RegistrationIntent, StateData, StateRef, StateStatus, V2Operation,
    decode_operation, encode_operation,
};
use orchard::circuit::state_note_binding::spend_auth_owner_key_bytes;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use pasta_curves::{group::ff::PrimeField, pallas};
use sha2::{Digest, Sha256};

const VECTOR_JSON: &str = include_str!("../../../test-vectors/names_v2_wire.json");

fn frozen_intent() -> RegistrationIntent {
    let spending_key = SpendingKey::from_bytes([0x2A; 32]).unwrap();
    let owner_pk = spend_auth_owner_key_bytes(&SpendAuthorizingKey::from(&spending_key));
    RegistrationIntent {
        name: "release-vector".to_owned(),
        owner_pk,
        record: vec![0x42; 64],
        secret: [0x33; 32],
    }
}

fn frozen_field(value: u64) -> [u8; 32] {
    pallas::Base::from(value).to_repr()
}

fn frozen_commit_ref(commitment: [u8; 32]) -> CommitRef {
    CommitRef::new(ProducerPosition::new(900, 1, [0xAB; 32]), 0, commitment)
}

fn frozen_predecessor() -> StateRef {
    StateRef::new(
        ProducerPosition::new(900, 1, [0xAB; 32]),
        3,
        0,
        frozen_field(11),
        frozen_field(12),
    )
}

fn frozen_state(overrides: impl FnOnce(&mut StateData)) -> StateData {
    let intent = frozen_intent();
    let mut state = StateData {
        name_id: intent.name_id().unwrap(),
        owner_pk: intent.owner_pk,
        sequence: 0,
        record: intent.record.clone(),
        lease_expiry: 1_000,
        status: StateStatus::Active,
        terminal_height: 0,
    };
    overrides(&mut state);
    state
}

fn frozen_proof() -> Vec<u8> {
    vec![0x5A; 1_920]
}

fn frozen_vector_operations() -> Vec<(&'static str, V2Operation)> {
    let intent = frozen_intent();
    let intent_commitment = intent.commitment().unwrap();
    let predecessor = frozen_predecessor();
    let dummy_proof = frozen_proof();

    let reveal_state = frozen_state(|state| {
        state.lease_expiry = 1_000;
    });
    let explicit_replacement = StateRef::new(
        ProducerPosition::new(950, 2, [0xCD; 32]),
        4,
        1,
        frozen_field(13),
        frozen_field(14),
    );

    vec![
        (
            "commit",
            V2Operation::Commit {
                commitment: intent_commitment,
            },
        ),
        (
            "reveal_first_registration",
            V2Operation::Reveal {
                intent: Box::new(intent.clone()),
                commit: frozen_commit_ref(intent_commitment),
                replacement_predecessor: None,
                state: reveal_state.clone(),
                state_commitment: frozen_field(11),
                state_nullifier: frozen_field(12),
                action_index: 3,
                proof: dummy_proof.clone(),
            },
        ),
        (
            "reveal_explicit_replacement",
            V2Operation::Reveal {
                intent: Box::new(intent.clone()),
                commit: frozen_commit_ref(intent_commitment),
                replacement_predecessor: Some(explicit_replacement),
                state: reveal_state.clone(),
                state_commitment: frozen_field(11),
                state_nullifier: frozen_field(12),
                action_index: 3,
                proof: dummy_proof.clone(),
            },
        ),
        // A bounded-history no-predecessor reset REVEAL carries
        // `replacement_predecessor: None`, so it shares the first-registration
        // encoding by construction. The conformance test asserts that equality
        // explicitly instead of freezing duplicate bytes.
        (
            "update",
            V2Operation::Update {
                predecessor: predecessor.clone(),
                state: frozen_state(|state| {
                    state.sequence = 1;
                    state.record = vec![0x43; 64];
                }),
                state_commitment: frozen_field(15),
                state_nullifier: frozen_field(16),
                action_index: 3,
                proof: dummy_proof.clone(),
            },
        ),
        (
            "renew",
            V2Operation::Renew {
                predecessor: predecessor.clone(),
                state: frozen_state(|state| {
                    state.sequence = 1;
                    state.lease_expiry = 2_000;
                }),
                state_commitment: frozen_field(17),
                state_nullifier: frozen_field(18),
                action_index: 3,
                proof: dummy_proof.clone(),
            },
        ),
        (
            "release",
            V2Operation::Release {
                predecessor,
                state: frozen_state(|state| {
                    state.sequence = 1;
                    state.status = StateStatus::Released;
                    state.terminal_height = 950;
                }),
                state_commitment: frozen_field(19),
                state_nullifier: frozen_field(20),
                action_index: 3,
                proof: dummy_proof,
            },
        ),
    ]
}

fn canonical_envelopes() -> Vec<(&'static str, Vec<u8>)> {
    frozen_vector_operations()
        .into_iter()
        .map(|(name, operation)| {
            (
                name,
                encode_operation(&operation).expect("frozen vector operation fits CNV2 and CPV1"),
            )
        })
        .collect()
}

fn vector_set_digest(envelopes: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for envelope in envelopes {
        hasher.update((envelope.len() as u64).to_be_bytes());
        hasher.update(envelope);
    }
    hex::encode(hasher.finalize())
}

#[test]
#[ignore = "vector generator: `cargo test -p coppice-names --test names_v2_wire_vectors -- --ignored --nocapture generate` regenerates test-vectors/names_v2_wire.json for a new protocol version only"]
fn generate_names_v2_wire_vectors() {
    let envelopes = canonical_envelopes();
    let reset_shaped = envelopes
        .iter()
        .find(|(name, _)| *name == "reveal_first_registration")
        .map(|(_, bytes)| bytes.clone())
        .expect("first-registration vector exists");
    let entries = envelopes
        .into_iter()
        .map(|(name, bytes)| {
            serde_json::json!({
                "id": name,
                "envelope_hex": hex::encode(&bytes),
                "envelope_bytes": bytes.len(),
                "valid": true,
            })
        })
        .chain([serde_json::json!({
            "id": "reveal_no_predecessor_reset_shaped",
            "envelope_hex": hex::encode(&reset_shaped),
            "envelope_bytes": reset_shaped.len(),
            "valid": true,
            "note": "byte-identical to reveal_first_registration: reset and first use share one canonical REVEAL encoding",
        })])
        .collect::<Vec<_>>();
    let envelope_pairs = canonical_envelopes();
    let envelopes_for_digest: Vec<&[u8]> = envelope_pairs
        .iter()
        .map(|(_, bytes)| bytes.as_slice())
        .collect();
    let document = serde_json::json!({
        "protocol": "coppice-names-v2",
        "wire_format": "CNV2 || 0x01 || canonical postcard operation list",
        "vector_set_sha256": vector_set_digest(&envelopes_for_digest),
        "inputs": {
            "spending_key_hex": hex::encode([0x2A; 32]),
            "name": "release-vector",
            "record_hex": hex::encode([0x42; 64]),
            "secret_hex": hex::encode([0x33; 32]),
            "commit_position": { "height": 900, "tx_index": 1, "txid_hex": hex::encode([0xAB; 32]) },
            "commit_operation_index": 0,
            "successor_commitment_hex": hex::encode(frozen_field(11)),
            "successor_future_nullifier_hex": hex::encode(frozen_field(12)),
            "replacement_predecessor": {
                "position": { "height": 950, "tx_index": 2, "txid_hex": hex::encode([0xCD; 32]) },
                "producer_action_index": 4,
                "producer_operation_index": 1,
                "commitment_hex": hex::encode(frozen_field(13)),
                "nullifier_hex": hex::encode(frozen_field(14)),
            },
            "predecessor_state_ref": {
                "position": { "height": 900, "tx_index": 1, "txid_hex": hex::encode([0xAB; 32]) },
                "producer_action_index": 3,
                "producer_operation_index": 0,
                "commitment_hex": hex::encode(frozen_field(11)),
                "nullifier_hex": hex::encode(frozen_field(12)),
            },
            "designated_action_index": 3,
            "proof_hex": hex::encode(frozen_proof()),
            "update_record_hex": hex::encode([0x43; 64]),
            "initial_lease_expiry": 1000,
            "renewed_lease_expiry": 2000,
            "release_terminal_height": 950,
        },
        "vectors": entries,
    });
    println!("{}", serde_json::to_string_pretty(&document).unwrap());
}

#[test]
fn frozen_names_v2_wire_vectors_reproduce_canonical_encodings() {
    let fixture: serde_json::Value = serde_json::from_str(VECTOR_JSON).unwrap();
    assert_eq!(fixture["protocol"], "coppice-names-v2");

    let by_id: std::collections::BTreeMap<&str, &serde_json::Value> = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["id"].as_str().unwrap(), entry))
        .collect();
    let envelopes = canonical_envelopes();

    // Every frozen vector reproduces the canonical encoding of its typed
    // operation and decodes back to that operation.
    let mut digest_envelopes = Vec::new();
    for (name, encoded) in &envelopes {
        let entry = by_id
            .get(name)
            .unwrap_or_else(|| panic!("frozen vector {name} missing"));
        assert_eq!(
            hex::encode(encoded),
            entry["envelope_hex"].as_str().unwrap(),
            "vector {name} drifted from the frozen CNV2 bytes"
        );
        assert_eq!(
            encoded.len(),
            entry["envelope_bytes"].as_u64().unwrap() as usize
        );
        let operation = frozen_vector_operations()
            .into_iter()
            .find(|(operation_name, _)| operation_name == name)
            .map(|(_, operation)| operation)
            .unwrap();
        assert_eq!(decode_operation(encoded).unwrap(), operation);
        digest_envelopes.push(encoded.as_slice());
    }

    // The reset-shaped REVEAL shares the first-registration encoding exactly.
    let first = by_id
        .get("reveal_first_registration")
        .expect("first-registration vector exists");
    let reset = by_id
        .get("reveal_no_predecessor_reset_shaped")
        .expect("reset-shaped vector exists");
    assert_eq!(first["envelope_hex"], reset["envelope_hex"]);

    // The whole frozen set still hashes to the recorded identity.
    assert_eq!(
        vector_set_digest(&digest_envelopes),
        fixture["vector_set_sha256"].as_str().unwrap(),
        "Names v2 vector-set identity changed"
    );
}
