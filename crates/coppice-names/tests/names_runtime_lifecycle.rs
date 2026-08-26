use ::coppice as coppice_core;
use coppice::{
    authorization,
    bond::{V1BondProver, V1BondWitness},
    bond_tag,
    config::{DeploymentParameters, Rendezvous},
    envelope::Operation,
    names_application::{encode_names_v1_envelope, names_v1_application_key},
    names_runtime::{
        CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplayActivationCheckpoint,
        IronwoodFrontier, NamesProtocolRejection, NamesRuntime, NamesTransactionOutcome,
    },
    record::NameStatus,
};
use coppice_core::{
    application::ApplicationEnvelopeError, runtime::ApplicationMessageStatus, transport,
};
use coppice_names as coppice;
use incrementalmerkletree::Retention;
use orchard::{
    Note, Proof,
    builder::{Builder, BundleType},
    bundle::{Authorized as OrchardAuthorized, BundleVersion},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::IronwoodDomain,
    primitives::redpallas::{Binding, SigningKey, SpendAuth},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_address::unified::{self, Encoding};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{Authorized, TransactionData};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkType},
    value::ZatBalance,
};

const ACTIVATION_HEIGHT: u32 = 100;
const ACTIVATION_HASH: [u8; 32] = [9; 32];

fn deployment() -> DeploymentParameters {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
    let input = &fixture["input"];
    DeploymentParameters {
        network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
        address_network: NetworkType::Regtest,
        activation_height: ACTIVATION_HEIGHT,
        minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
        commit_ttl_blocks: 20,
        reuse_delay_blocks: 10,
        bond_note_max_age_blocks: 100,
        rendezvous: Rendezvous {
            orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
    }
}

fn new_runtime() -> NamesRuntime {
    NamesRuntime::new(
        deployment(),
        CoreReplayActivationCheckpoint {
            height: ACTIVATION_HEIGHT - 1,
            block_hash: ACTIVATION_HASH,
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    )
    .unwrap()
}

fn transaction_from_envelope(
    runtime: &NamesRuntime,
    envelope: &[u8],
    tx_index: u32,
    seed: u8,
) -> CoreCanonicalTransactionInput {
    let frames =
        transport::encode_frames(runtime.core().runtime_id().to_bytes(), envelope).unwrap();
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    let receiver = coppice::carrier::bulletin_address(runtime.deployment().rendezvous).unwrap();
    for frame in frames {
        builder
            .add_output(None, receiver, NoteValue::ZERO, frame)
            .unwrap();
    }
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (unauthorized, _) = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
    let action_count = unauthorized.actions().len();
    let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).unwrap();
    let binding_key = SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).unwrap();
    let proof = Proof::new(vec![0; Proof::expected_proof_size(action_count)]);
    let bundle = unauthorized.map_authorization(
        &mut rng,
        |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceRoutedLifecycleSpend"),
        |rng, _| {
            OrchardAuthorized::from_parts(
                proof,
                binding_key.sign(&mut *rng, b"CoppiceRoutedLifecycleBinding"),
            )
        },
    );
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(runtime.tip().height.saturating_add(1)),
        None,
        None,
        None,
        Some(bundle),
    )
    .freeze()
    .unwrap();
    let effects = coppice::ironwood::extract_ironwood_effects(&transaction);
    let mut bytes = Vec::new();
    transaction.write(&mut bytes).unwrap();
    CoreCanonicalTransactionInput {
        tx_index,
        txid: transaction.txid().into(),
        ironwood_nullifiers: effects.nullifiers,
        ironwood_commitments: effects.commitments,
        full_transaction_acquisition: coppice_core::replay::FullTransactionAcquisition::Carrier,
        full_transaction: Some(bytes),
    }
}

fn operation_transaction(
    runtime: &NamesRuntime,
    operation: &Operation,
    tx_index: u32,
    seed: u8,
) -> CoreCanonicalTransactionInput {
    transaction_from_envelope(
        runtime,
        &encode_names_v1_envelope(operation).unwrap(),
        tx_index,
        seed,
    )
}

fn block(
    runtime: &NamesRuntime,
    transactions: Vec<CoreCanonicalTransactionInput>,
) -> CoreCanonicalBlockInput {
    let height = runtime.tip().height.checked_add(1).unwrap();
    CoreCanonicalBlockInput {
        height,
        block_hash: [height as u8; 32],
        prev_block_hash: runtime.tip().block_hash,
        branch_id: BranchId::Nu6_3,
        transactions,
    }
}

struct BondMaterial {
    input: CoreCanonicalTransactionInput,
    note: Note,
    full_viewing_key: FullViewingKey,
    spend_authorizing_key: SpendAuthorizingKey,
}

fn bond_transaction(runtime: &NamesRuntime, seed: u8) -> BondMaterial {
    let spending_key = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
    let spend_authorizing_key = SpendAuthorizingKey::from(&spending_key);
    let full_viewing_key = FullViewingKey::from(&spending_key);
    let incoming_viewing_key = full_viewing_key.to_ivk(Scope::External);
    let recipient = full_viewing_key.address_at(0u32, Scope::External);
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    builder
        .add_output(
            None,
            recipient,
            NoteValue::from_raw(runtime.deployment().minimum_bond_value),
            [0; 512],
        )
        .unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (unauthorized, _) = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
    let action = &unauthorized.actions()[0];
    let (note, _, _) = try_note_decryption(
        &IronwoodDomain::for_action(action),
        &incoming_viewing_key.prepare(),
        action,
    )
    .unwrap();
    let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).unwrap();
    let binding_key = SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).unwrap();
    let proof = Proof::new(vec![0; Proof::expected_proof_size(1)]);
    let bundle = unauthorized.map_authorization(
        &mut rng,
        |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceRoutedLifecycleSpend"),
        |rng, _| {
            OrchardAuthorized::from_parts(
                proof,
                binding_key.sign(&mut *rng, b"CoppiceRoutedLifecycleBinding"),
            )
        },
    );
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(runtime.tip().height.saturating_add(1)),
        None,
        None,
        None,
        Some(bundle),
    )
    .freeze()
    .unwrap();
    let effects = coppice::ironwood::extract_ironwood_effects(&transaction);
    BondMaterial {
        input: CoreCanonicalTransactionInput {
            tx_index: u32::from(seed),
            txid: transaction.txid().into(),
            ironwood_nullifiers: effects.nullifiers,
            ironwood_commitments: effects.commitments,
            full_transaction_acquisition: coppice_core::replay::FullTransactionAcquisition::None,
            full_transaction: None,
        },
        note,
        full_viewing_key,
        spend_authorizing_key,
    }
}

fn bond_witness(
    bond: BondMaterial,
    prior_commitments: impl IntoIterator<Item = [u8; 32]>,
) -> V1BondWitness {
    let bond_commitment = ExtractedNoteCommitment::from(bond.note.commitment());
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    let mut position = 0u32;
    for commitment in prior_commitments {
        let node =
            Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&commitment)).unwrap();
        tree.append(node, Retention::Ephemeral).unwrap();
        position += 1;
    }
    assert_eq!(
        bond.input.ironwood_commitments,
        vec![bond_commitment.to_bytes()]
    );
    tree.append(
        MerkleHashOrchard::from_cmx(&bond_commitment),
        Retention::Marked,
    )
    .unwrap();
    tree.checkpoint(1).unwrap();
    let merkle_path: MerklePath = tree
        .witness_at_checkpoint_depth(u64::from(position).into(), 0)
        .unwrap()
        .unwrap()
        .into();
    V1BondWitness {
        note: bond.note,
        full_viewing_key: bond.full_viewing_key,
        spend_authorizing_key: bond.spend_authorizing_key,
        merkle_path,
    }
}

fn canonical_address(runtime: &NamesRuntime, key_byte: u8) -> Vec<u8> {
    let key = Option::<SpendingKey>::from(SpendingKey::from_bytes([key_byte; 32])).unwrap();
    let receiver = FullViewingKey::from(&key)
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    unified::Address::try_from_items(vec![unified::Receiver::Orchard(receiver)])
        .unwrap()
        .encode(&runtime.deployment().address_network)
        .into_bytes()
}

#[test]
fn routed_names_lifecycle_rewind_bond_spend_pruning_and_fresh_replay() {
    let mut runtime = new_runtime();
    let owner_key = coppice::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
    let owner_pk = coppice::owner::owner_key_bytes(&(&owner_key).into());
    let address = canonical_address(&runtime, 8);
    let updated_address = canonical_address(&runtime, 9);
    let name = "alice";
    let secret = [0x55; 32];
    let bond = bond_transaction(&runtime, 21);
    let bond_nullifier = bond.note.nullifier(&bond.full_viewing_key).to_bytes();
    let bond_tag = bond_tag::derive_v1_bond_tag(&bond_nullifier).unwrap();
    let commitment = coppice::registration::registration_commitment(
        runtime.deployment(),
        name,
        owner_pk,
        bond_tag,
        &address,
        secret,
    )
    .unwrap();

    let commit_input = operation_transaction(&runtime, &Operation::Commit { commitment }, 1, 1);
    let block_100 = block(&runtime, vec![commit_input.clone()]);
    assert_eq!(
        runtime
            .apply_block(&block_100)
            .unwrap()
            .names
            .transaction_outcomes,
        vec![NamesTransactionOutcome::Applied]
    );

    let bond_input = bond.input.clone();
    let witness = bond_witness(bond, commit_input.ironwood_commitments.clone());
    let block_101 = block(&runtime, vec![bond_input.clone()]);
    let anchor = runtime
        .apply_block(&block_101)
        .unwrap()
        .core
        .ironwood_checkpoint()
        .root;
    let proof = V1BondProver::new()
        .unwrap()
        .prove_v1_bond(
            witness,
            runtime.deployment(),
            name,
            &address,
            owner_pk,
            bond_tag,
            anchor,
            0,
            ChaCha20Rng::from_seed([42; 32]),
        )
        .unwrap();
    let reveal = Operation::Reveal {
        name: name.to_owned(),
        owner_pk,
        bond_tag,
        bond_anchor_height: 101,
        bond_anchor: anchor,
        bond_proof: proof.proof,
        address: address.clone(),
        secret,
    };
    let block_102 = block(
        &runtime,
        vec![operation_transaction(&runtime, &reveal, 2, 2)],
    );
    runtime.apply_block(&block_102).unwrap();
    assert_eq!(runtime.state().names[name].status, NameStatus::Active);

    let previous = runtime.state().names[name].clone();
    let mut update = Operation::Update {
        name: name.to_owned(),
        sequence: 1,
        address: updated_address,
        signature: vec![0; 64],
    };
    let signature = authorization::sign_v1(
        runtime.names_deployment_id().to_bytes(),
        &owner_key,
        &update,
        &previous,
    )
    .unwrap();
    let Operation::Update {
        signature: slot, ..
    } = &mut update
    else {
        unreachable!()
    };
    *slot = signature.to_vec();
    let block_103 = block(
        &runtime,
        vec![operation_transaction(&runtime, &update, 3, 3)],
    );
    runtime.apply_block(&block_103).unwrap();
    assert_eq!(runtime.state().names[name].sequence, 1);

    let invalid = Operation::Update {
        name: name.to_owned(),
        sequence: 3,
        address: address.clone(),
        signature: vec![0; 64],
    };
    let block_104 = block(
        &runtime,
        vec![operation_transaction(&runtime, &invalid, 4, 4)],
    );
    assert_eq!(
        runtime
            .apply_block(&block_104)
            .unwrap()
            .names
            .transaction_outcomes,
        vec![NamesTransactionOutcome::Rejected(
            NamesProtocolRejection::InvalidSequence
        )]
    );

    let previous = runtime.state().names[name].clone();
    let mut release = Operation::Release {
        name: name.to_owned(),
        sequence: 2,
        signature: vec![0; 64],
    };
    let signature = authorization::sign_v1(
        runtime.names_deployment_id().to_bytes(),
        &owner_key,
        &release,
        &previous,
    )
    .unwrap();
    let Operation::Release {
        signature: slot, ..
    } = &mut release
    else {
        unreachable!()
    };
    *slot = signature.to_vec();
    let block_105_release = block(
        &runtime,
        vec![operation_transaction(&runtime, &release, 5, 5)],
    );
    runtime.apply_block(&block_105_release).unwrap();
    assert_eq!(
        runtime.state().names[name].status,
        NameStatus::Released {
            terminal_height: 105
        }
    );

    runtime.rewind_to(104).unwrap();
    let bond_spend = CoreCanonicalTransactionInput {
        tx_index: 0,
        txid: [0x77; 32],
        ironwood_nullifiers: vec![bond_nullifier],
        ironwood_commitments: vec![],
        full_transaction_acquisition: coppice_core::replay::FullTransactionAcquisition::None,
        full_transaction: None,
    };
    let block_105_spend = block(&runtime, vec![bond_spend]);
    runtime.apply_block(&block_105_spend).unwrap();
    assert_eq!(
        runtime.state().names[name].status,
        NameStatus::BondSpent {
            terminal_height: 105
        }
    );

    let expiring_commitment = [0xaa; 32];
    let expiring = Operation::Commit {
        commitment: expiring_commitment,
    };
    let block_106 = block(
        &runtime,
        vec![operation_transaction(&runtime, &expiring, 6, 6)],
    );
    runtime.apply_block(&block_106).unwrap();
    assert!(runtime.state().pending.contains_key(&expiring_commitment));

    let mut canonical_suffix = vec![block_105_spend.clone(), block_106.clone()];
    for _ in 107..=225 {
        let input = block(&runtime, vec![]);
        runtime.apply_block(&input).unwrap();
        canonical_suffix.push(input);
    }
    assert!(!runtime.state().pending.contains_key(&expiring_commitment));
    assert!(!runtime.state().recent_spent.contains_key(&bond_tag));

    let mut fresh = new_runtime();
    for input in [&block_100, &block_101, &block_102, &block_103, &block_104] {
        fresh.apply_block(input).unwrap();
    }
    for input in &canonical_suffix {
        fresh.apply_block(input).unwrap();
    }
    assert_eq!(runtime.tip(), fresh.tip());
    assert_eq!(runtime.state(), fresh.state());
    assert_eq!(runtime.state_root(), fresh.state_root());
    assert_eq!(runtime.ironwood_frontier(), fresh.ironwood_frontier());
}

#[test]
fn routing_isolated_unknown_apps_and_malformed_envelopes_are_nonfatal() {
    let mut runtime = new_runtime();
    let unknown = coppice_core::application::ApplicationEnvelopeV1::new(
        coppice_core::application::ApplicationKey::new(
            coppice_core::application::derive_application_id(b"test.unknown").unwrap(),
            1,
        ),
        vec![1, 2, 3],
    )
    .unwrap()
    .encode();
    let wrong_version = coppice_core::application::ApplicationEnvelopeV1::new(
        coppice_core::application::ApplicationKey::new(
            names_v1_application_key().id,
            names_v1_application_key().version + 1,
        ),
        vec![1, 2, 3],
    )
    .unwrap()
    .encode();
    let malformed = b"not-an-application-envelope";
    let sibling = coppice_core::application::ApplicationEnvelopeV1::new(
        coppice_core::application::ApplicationKey::new(
            coppice_core::application::derive_application_id(b"test.sibling").unwrap(),
            1,
        ),
        vec![4, 5, 6],
    )
    .unwrap()
    .encode();
    let block = block(
        &runtime,
        vec![
            transaction_from_envelope(&runtime, &unknown, 0, 30),
            transaction_from_envelope(&runtime, &wrong_version, 1, 31),
            transaction_from_envelope(&runtime, malformed, 2, 32),
            transaction_from_envelope(&runtime, &sibling, 3, 33),
        ],
    );
    let applied = runtime.apply_block(&block).unwrap();
    assert!(matches!(
        applied.core.transactions()[0].message(),
        ApplicationMessageStatus::Message(message) if message.key() != names_v1_application_key()
    ));
    assert!(matches!(
        applied.core.transactions()[1].message(),
        ApplicationMessageStatus::Message(message) if message.key() != names_v1_application_key()
    ));
    assert!(matches!(
        applied.core.transactions()[2].message(),
        ApplicationMessageStatus::MalformedEnvelope(ApplicationEnvelopeError::TooShort)
    ));
    assert!(matches!(
        applied.core.transactions()[3].message(),
        ApplicationMessageStatus::Message(message) if message.key() != names_v1_application_key()
    ));
    assert_eq!(
        applied.names.transaction_outcomes,
        vec![NamesTransactionOutcome::NoOperation; 4]
    );
    assert!(runtime.state().names.is_empty());
    assert!(runtime.state().pending.is_empty());
}

#[test]
fn exact_names_route_rejects_malformed_payload_but_applies_valid_operation() {
    let mut runtime = new_runtime();
    let malformed_names_payload = coppice_core::application::ApplicationEnvelopeV1::new(
        names_v1_application_key(),
        vec![0xff],
    )
    .unwrap()
    .encode();
    let commitment = [0x66; 32];
    let valid_names_payload = encode_names_v1_envelope(&Operation::Commit { commitment }).unwrap();
    let block = block(
        &runtime,
        vec![
            transaction_from_envelope(&runtime, &malformed_names_payload, 0, 34),
            transaction_from_envelope(&runtime, &valid_names_payload, 1, 35),
        ],
    );

    let applied = runtime.apply_block(&block).unwrap();
    assert!(matches!(
        applied.core.transactions()[0].message(),
        ApplicationMessageStatus::Message(message) if message.key() == names_v1_application_key()
    ));
    assert!(matches!(
        applied.core.transactions()[1].message(),
        ApplicationMessageStatus::Message(message) if message.key() == names_v1_application_key()
    ));
    assert_eq!(
        applied.names.transaction_outcomes,
        vec![
            NamesTransactionOutcome::Rejected(NamesProtocolRejection::MalformedCarrier),
            NamesTransactionOutcome::Applied,
        ]
    );
    assert!(runtime.state().pending.contains_key(&commitment));
    assert!(runtime.state().names.is_empty());
}
