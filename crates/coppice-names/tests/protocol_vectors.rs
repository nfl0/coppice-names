//! Frozen positive vectors for Coppice Names.
//!
//! The ordinary conformance test consumes the checked-in artifact and proves
//! that deterministic key generation, proofs, encoding, and replay reproduce
//! it byte-for-byte. Regeneration is an explicit ignored test.

use coppice::identity::CoreRuntimeId;
use coppice_names::{
    codec::{CodecParameters, Operation, decode, encode},
    deployment::{DeploymentParameters, verifier_suite_id},
    names_application_id, names_family_id,
    proof::keygen,
    protocol::{
        BOND_ZATOSHIS, CanonicalUa, CommitRef, Commitment, FieldElement, Name, NameRoute, Network,
        StateRef,
    },
    reducer::{Accepted, Action, Block, Lifecycle, ProofVerifier, Reducer, Transaction},
    resolver::ExactResolver,
    schedule::Parameters,
    statement::{
        RefreshStatement, RevealStatement, commit_ref_field, deployment_field,
        registration_commitment, state_ref_field, ua_field,
    },
};
use orchard::{
    Note, NoteVersion,
    circuit::state_note_binding::v2::{
        CIRCUIT_K, REFRESH_PROOF_BYTES, REVEAL_PROOF_BYTES, owner_commitment,
    },
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    value::NoteValue,
};
use pasta_curves::{group::ff::PrimeField, pallas};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VECTOR_JSON: &str = include_str!("../../../test-vectors/protocol.json");
const WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");
const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");
const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";
const CORE_RUNTIME_ID: &str = "fa787a8cd3121b698e549c9a3e551e77c9888fb707830303cba0319ba2481cf7";
const ORCHARD_REVISION: &str = "e702d0525d5086d41b66ab870ede0a94b05fdcae";

fn bytes32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn field(bytes: [u8; 32]) -> FieldElement {
    FieldElement::from_bytes(bytes).unwrap()
}

fn block_hash(height: u32) -> [u8; 32] {
    let mut hash = [0xA5; 32];
    hash[..4].copy_from_slice(&height.to_be_bytes());
    hash
}

fn deployment(proof: coppice_names::deployment::ProofIdentity) -> DeploymentParameters {
    let candidate = Parameters::candidate([0; 32], 100_000);
    DeploymentParameters {
        core_runtime_id: CoreRuntimeId::from_bytes(bytes32(CORE_RUNTIME_ID)),
        activation_height: candidate.activation_height,
        epoch_blocks: candidate.epoch_blocks,
        window_blocks: candidate.window_blocks,
        commit_maturity_blocks: candidate.commit_maturity_blocks,
        commit_ttl_blocks: candidate.commit_ttl_blocks,
        lease_blocks: candidate.lease_blocks,
        cooldown_blocks: candidate.cooldown_blocks,
        ruleset_fingerprint: coppice_names::ruleset::ruleset_fingerprint(),
        proof,
    }
}

fn vector_set_digest(parts: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    hex::encode(digest.finalize())
}

fn build_document() -> Value {
    let spending_key = SpendingKey::from_bytes([7; 32]).unwrap();
    let fvk = FullViewingKey::from(&spending_key);
    let name = Name::parse("alice.zec").unwrap();
    let name_id = name.id().unwrap();
    let ua = CanonicalUa::parse(Network::Regtest, UA).unwrap();
    let (prover, verifier) = keygen();
    let (_, exact_verifier) = keygen();
    let proof_identity = verifier.identity();
    let deployment = deployment(proof_identity);
    let deployment_preimage = deployment.canonical_preimage().unwrap();
    let deployment_id = deployment.deployment_id().unwrap();
    let parameters = deployment.schedule(deployment_id).validate().unwrap();
    let codec = CodecParameters {
        reveal_proof_bytes: REVEAL_PROOF_BYTES,
        refresh_proof_bytes: REFRESH_PROOF_BYTES,
    };
    let reveal_epoch = 17;
    let reveal_height = parameters.window(name_id, reveal_epoch).unwrap().start;
    let commit_height = reveal_height - parameters.commit_maturity_blocks;
    let refresh_epoch = reveal_epoch + 1;
    let refresh_height = parameters.window(name_id, refresh_epoch).unwrap().start;
    let commit_ref = CommitRef {
        height: commit_height,
        tx_index: 0,
        txid: [10; 32],
    };
    let predecessor_ref = StateRef {
        height: reveal_height,
        tx_index: 0,
        txid: [20; 32],
        action_index: 0,
    };

    let owner_commit = field(owner_commitment(&spending_key).to_bytes());
    let secret = field(pallas::Base::from(77).to_repr());
    let commitment = Commitment::from_bytes(registration_commitment(
        deployment_id,
        name_id,
        reveal_epoch,
        owner_commit,
        secret,
    ))
    .unwrap();

    let reveal_rho = Rho::from_bytes(&[9; 32]).unwrap();
    let reveal_rseed = RandomSeed::from_bytes([4; 32], &reveal_rho).unwrap();
    let reveal_note = Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(BOND_ZATOSHIS),
        reveal_rho,
        reveal_rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let reveal_action = Action {
        action_index: 0,
        nullifier: field(reveal_note.rho().to_bytes()),
        commitment: field(ExtractedNoteCommitment::from(reveal_note.commitment()).to_bytes()),
    };
    let reveal_future_nf = field(reveal_note.nullifier(&fvk).to_bytes());
    let reveal_statement = RevealStatement {
        deployment_id,
        name_id,
        inclusion_epoch: reveal_epoch,
        commitment,
        commit_ref,
        ua: ua.clone(),
        action_index: 0,
        action_nullifier: reveal_action.nullifier,
        action_commitment: reveal_action.commitment,
        successor_future_nf: reveal_future_nf,
    };
    let reveal_proof = prover
        .prove_reveal(
            &reveal_statement,
            reveal_note,
            &spending_key,
            secret,
            ChaCha20Rng::from_seed([45; 32]),
        )
        .unwrap();

    let refresh_rho = Rho::from_bytes(&reveal_future_nf.to_bytes()).unwrap();
    let refresh_rseed = RandomSeed::from_bytes([5; 32], &refresh_rho).unwrap();
    let refresh_note = Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(BOND_ZATOSHIS),
        refresh_rho,
        refresh_rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let refresh_action = Action {
        action_index: 0,
        nullifier: field(refresh_note.rho().to_bytes()),
        commitment: field(ExtractedNoteCommitment::from(refresh_note.commitment()).to_bytes()),
    };
    let refresh_future_nf = field(refresh_note.nullifier(&fvk).to_bytes());
    let refresh_statement = RefreshStatement {
        deployment_id,
        name_id,
        predecessor_ref,
        predecessor_commitment: reveal_action.commitment,
        predecessor_future_nf: reveal_future_nf,
        predecessor_epoch: reveal_epoch,
        inclusion_epoch: refresh_epoch,
        ua: ua.clone(),
        action_index: 0,
        action_nullifier: refresh_action.nullifier,
        action_commitment: refresh_action.commitment,
        successor_future_nf: refresh_future_nf,
    };
    let refresh_proof = prover
        .prove_refresh(
            &refresh_statement,
            reveal_note,
            refresh_note,
            &spending_key,
            ChaCha20Rng::from_seed([46; 32]),
        )
        .unwrap();
    assert!(verifier.verify_reveal(&reveal_statement, &reveal_proof));
    assert!(verifier.verify_refresh(&refresh_statement, &refresh_proof));
    assert!(!verifier.verify_reveal(&reveal_statement, &refresh_proof));
    assert!(!verifier.verify_refresh(&refresh_statement, &reveal_proof));

    let commit_operation = Operation::Commit { commitment };
    let reveal_operation = Operation::Reveal {
        name: name.clone(),
        commit: commit_ref,
        ua: ua.clone(),
        action_index: 0,
        successor_future_nf: reveal_future_nf,
        proof: reveal_proof.clone(),
    };
    let refresh_operation = Operation::Refresh {
        name: name.clone(),
        predecessor: predecessor_ref,
        ua: ua.clone(),
        action_index: 0,
        successor_future_nf: refresh_future_nf,
        proof: refresh_proof.clone(),
    };
    let commit_bytes = encode(&commit_operation, codec).unwrap();
    let reveal_bytes = encode(&reveal_operation, codec).unwrap();
    let refresh_bytes = encode(&refresh_operation, codec).unwrap();
    assert_eq!(
        decode(&commit_bytes, Network::Regtest, codec),
        Ok(commit_operation.clone())
    );
    assert_eq!(
        decode(&reveal_bytes, Network::Regtest, codec),
        Ok(reveal_operation.clone())
    );
    assert_eq!(
        decode(&refresh_bytes, Network::Regtest, codec),
        Ok(refresh_operation.clone())
    );

    let mut reducer = Reducer::new(parameters, [0; 32], verifier).unwrap();
    let mut exact = ExactResolver::new(parameters, [0; 32], name.clone(), exact_verifier).unwrap();
    let mut previous_hash = [0; 32];
    for height in parameters.activation_height..=refresh_height {
        let transaction = if height == commit_height {
            Some(Transaction {
                tx_index: 0,
                txid: commit_ref.txid,
                actions: vec![],
                operation: Some(commit_operation.clone()),
            })
        } else if height == reveal_height {
            Some(Transaction {
                tx_index: 0,
                txid: predecessor_ref.txid,
                actions: vec![reveal_action],
                operation: Some(reveal_operation.clone()),
            })
        } else if height == refresh_height {
            Some(Transaction {
                tx_index: 0,
                txid: [30; 32],
                actions: vec![refresh_action],
                operation: Some(refresh_operation.clone()),
            })
        } else {
            None
        };
        let hash = block_hash(height);
        let block = Block {
            height,
            hash,
            prev_hash: previous_hash,
            transactions: transaction.into_iter().collect(),
        };
        let accepted = reducer.apply_block(&block).unwrap();
        let exact_accepted = exact.apply_block(&block).unwrap();
        assert_eq!(exact_accepted, accepted);
        if height == commit_height {
            assert_eq!(accepted, [Accepted::Commit]);
        } else if height == reveal_height {
            assert_eq!(accepted, [Accepted::Reveal]);
        } else if height == refresh_height {
            assert_eq!(accepted, [Accepted::Refresh]);
        } else {
            assert!(accepted.is_empty());
        }
        previous_hash = hash;
    }
    let resolution = reducer.resolve(&name, refresh_height);
    let exact_resolution = exact.resolve(refresh_height).unwrap();
    assert_eq!(exact_resolution, resolution);
    assert_eq!(resolution.lifecycle, Lifecycle::Active);
    assert_eq!(resolution.ua.as_ref(), Some(&ua));
    let head = resolution.head.unwrap();
    let route = NameRoute::derive(deployment_id, name_id).unwrap();
    let route_ivk = route.incoming_viewing_key();
    let route_receiver = route.receiver();
    let reveal_digest = reveal_statement.digest();
    let refresh_digest = refresh_statement.digest();
    let identity_parts = [
        deployment_preimage.as_slice(),
        route_ivk.as_slice(),
        route_receiver.as_slice(),
        reveal_digest.as_slice(),
        refresh_digest.as_slice(),
        commit_bytes.as_slice(),
        reveal_bytes.as_slice(),
        refresh_bytes.as_slice(),
    ];

    json!({
        "status": "qualification-only; no public deployment is declared",
        "protocol": "coppice-names",
        "wire": "operation_tag || canonical fields",
        "vector_set_sha256": vector_set_digest(&identity_parts),
        "dependencies": {
            "orchard_coppice_revision": ORCHARD_REVISION,
            "zakura_halo2_proofs": "1.0.0/7c1386cce49a4d9e4a1b1e32fbbb3ba34d23e53dcefd700ee976d736d72f302a",
            "zakura_pasta_curves": "1.0.0/9b11ea111779520b119485fdb0fd69c3ec96b6eaab0e1bfbfb3f9cb67c55815a"
        },
        "identity": {
            "core_runtime_id_hex": CORE_RUNTIME_ID,
            "names_family_id_hex": hex::encode(names_family_id().to_bytes()),
            "application_id_hex": hex::encode(names_application_id(deployment_id).to_bytes()),
            "ruleset_fingerprint_hex": hex::encode(deployment.ruleset_fingerprint),
            "verifier_suite_manifest_utf8": String::from_utf8_lossy(coppice_names::deployment::VERIFIER_SUITE_MANIFEST),
            "verifier_suite_id_hex": hex::encode(verifier_suite_id()),
            "circuit_k": CIRCUIT_K,
            "reveal_key_fingerprint_hex": hex::encode(proof_identity.reveal_key_fingerprint()),
            "refresh_key_fingerprint_hex": hex::encode(proof_identity.refresh_key_fingerprint()),
            "reveal_verifier_id_hex": hex::encode(proof_identity.reveal().to_bytes()),
            "refresh_verifier_id_hex": hex::encode(proof_identity.refresh().to_bytes()),
            "reveal_proof_bytes": REVEAL_PROOF_BYTES,
            "refresh_proof_bytes": REFRESH_PROOF_BYTES,
            "deployment_preimage_hex": hex::encode(deployment_preimage),
            "deployment_id_hex": hex::encode(deployment_id)
        },
        "parameters": {
            "activation_height": parameters.activation_height,
            "epoch_blocks": parameters.epoch_blocks,
            "window_blocks": parameters.window_blocks,
            "commit_maturity_blocks": parameters.commit_maturity_blocks,
            "commit_ttl_blocks": parameters.commit_ttl_blocks,
            "lease_blocks": parameters.lease_blocks,
            "cooldown_blocks": parameters.cooldown_blocks,
            "bond_zatoshis": BOND_ZATOSHIS
        },
        "name": {
            "api_input": "alice.zec",
            "canonical": name.as_str(),
            "name_id_hex": hex::encode(name_id.to_bytes()),
            "route_ivk_hex": hex::encode(route.incoming_viewing_key()),
            "route_receiver_hex": hex::encode(route.receiver()),
            "ua": UA
        },
        "wallet_witness": {
            "spending_key_hex": hex::encode([7; 32]),
            "owner_commitment_hex": hex::encode(owner_commit.to_bytes()),
            "commit_secret_hex": hex::encode(secret.to_bytes()),
            "reveal_rho_hex": hex::encode([9; 32]),
            "reveal_rseed_hex": hex::encode([4; 32]),
            "refresh_rseed_hex": hex::encode([5; 32])
        },
        "schedule": {
            "reveal_epoch": reveal_epoch,
            "reveal_window": [parameters.window(name_id, reveal_epoch).unwrap().start, parameters.window(name_id, reveal_epoch).unwrap().end],
            "commit_height": commit_height,
            "reveal_height": reveal_height,
            "refresh_epoch": refresh_epoch,
            "refresh_window": [parameters.window(name_id, refresh_epoch).unwrap().start, parameters.window(name_id, refresh_epoch).unwrap().end],
            "refresh_height": refresh_height
        },
        "fields": {
            "deployment_field_hex": hex::encode(deployment_field(deployment_id).to_repr()),
            "commitment_hex": hex::encode(commitment.to_bytes()),
            "commit_ref_field_hex": hex::encode(commit_ref_field(commit_ref).to_repr()),
            "state_ref_field_hex": hex::encode(state_ref_field(predecessor_ref).to_repr()),
            "ua_field_hex": hex::encode(ua_field(&ua).to_repr()),
            "reveal_action_nullifier_hex": hex::encode(reveal_action.nullifier.to_bytes()),
            "reveal_action_commitment_hex": hex::encode(reveal_action.commitment.to_bytes()),
            "reveal_future_nullifier_hex": hex::encode(reveal_future_nf.to_bytes()),
            "refresh_action_commitment_hex": hex::encode(refresh_action.commitment.to_bytes()),
            "refresh_future_nullifier_hex": hex::encode(refresh_future_nf.to_bytes()),
            "reveal_statement_digest_hex": hex::encode(reveal_digest),
            "refresh_statement_digest_hex": hex::encode(refresh_digest)
        },
        "operations": [
            { "id": "commit", "bytes": commit_bytes.len(), "hex": hex::encode(&commit_bytes) },
            { "id": "reveal", "bytes": reveal_bytes.len(), "proof_hex": hex::encode(&reveal_proof), "hex": hex::encode(&reveal_bytes) },
            { "id": "refresh", "bytes": refresh_bytes.len(), "proof_hex": hex::encode(&refresh_proof), "hex": hex::encode(&refresh_bytes) }
        ],
        "reducer": {
            "lifecycle": "Active",
            "resolved_ua": UA,
            "head_height": head.producer.height,
            "head_txid_hex": hex::encode(head.producer.txid),
            "head_action_index": head.producer.action_index,
            "head_commitment_hex": hex::encode(head.commitment.to_bytes()),
            "head_future_nullifier_hex": hex::encode(head.future_nf.to_bytes()),
            "head_epoch": head.producer_epoch,
            "expiry_height": head.expiry_height
        }
    })
}

fn canonical_json() -> String {
    let mut output = serde_json::to_string_pretty(&build_document()).unwrap();
    output.push('\n');
    output
}

#[test]
fn frozen_protocol_vectors_reproduce_exactly() {
    assert!(WORKSPACE_MANIFEST.contains(ORCHARD_REVISION));
    assert!(WORKSPACE_LOCK.contains(ORCHARD_REVISION));
    assert!(WORKSPACE_LOCK.contains(
        "checksum = \"7c1386cce49a4d9e4a1b1e32fbbb3ba34d23e53dcefd700ee976d736d72f302a\""
    ));
    assert!(WORKSPACE_LOCK.contains(
        "checksum = \"9b11ea111779520b119485fdb0fd69c3ec96b6eaab0e1bfbfb3f9cb67c55815a\""
    ));
    assert_eq!(
        canonical_json(),
        VECTOR_JSON,
        "checked-in current protocol vectors drifted; regenerate only after review"
    );
}

#[test]
#[ignore = "explicit generator: cargo test -p coppice-names --test protocol_vectors -- --ignored --exact regenerate_protocol_vectors"]
fn regenerate_protocol_vectors() {
    let output =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/protocol.json");
    std::fs::write(&output, canonical_json()).unwrap();
    println!("regenerated {}", output.display());
}
