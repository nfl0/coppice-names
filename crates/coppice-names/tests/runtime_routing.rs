use ::coppice as coppice_core;
use coppice::{
    config::{DeploymentParameters, Rendezvous},
    envelope::Operation,
    names_application::{encode_names_v1_envelope, names_v1_core_runtime_parameters},
    names_runtime::{NamesRuntime, NamesTransactionOutcome},
};
use coppice_core::{
    application::{
        ApplicationBlockContext, ApplicationDescriptor, ApplicationEnvelopeV1, ApplicationKey,
        ApplicationTip, CoppiceApplication, derive_application_id,
    },
    replay::{
        CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplay,
        CoreReplayActivationCheckpoint, CoreReplayConfiguration, IronwoodFrontier,
    },
    runtime::{ApplicationMessageStatus, CoreRuntime},
    transport,
};
use coppice_names as coppice;
use orchard::{
    Proof,
    builder::{Builder, BundleType},
    bundle::{Authorized as OrchardAuthorized, BundleVersion},
    keys::IncomingViewingKey,
    primitives::redpallas::{Binding, SigningKey, SpendAuth},
    value::NoteValue,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::io::Cursor;
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

fn checkpoint() -> CoreReplayActivationCheckpoint {
    CoreReplayActivationCheckpoint {
        height: ACTIVATION_HEIGHT - 1,
        block_hash: ACTIVATION_HASH,
        ironwood_frontier: IronwoodFrontier::empty(),
        ironwood_tree_size: 0,
    }
}

fn candidate_transaction(
    deployment: &DeploymentParameters,
    runtime_id: [u8; 32],
    envelope: &[u8],
    tx_index: u32,
    seed: u8,
) -> CoreCanonicalTransactionInput {
    let receiver = coppice::carrier::bulletin_address(deployment.rendezvous).unwrap();
    candidate_transaction_to_receiver(runtime_id, envelope, tx_index, seed, receiver)
}

fn candidate_transaction_to_receiver(
    runtime_id: [u8; 32],
    envelope: &[u8],
    tx_index: u32,
    seed: u8,
    receiver: orchard::Address,
) -> CoreCanonicalTransactionInput {
    let frames = transport::encode_frames(runtime_id, envelope).unwrap();
    candidate_transaction_with_frames(runtime_id, frames, tx_index, seed, receiver)
}

fn candidate_transaction_with_frames(
    _runtime_id: [u8; 32],
    frames: Vec<[u8; 512]>,
    tx_index: u32,
    seed: u8,
    receiver: orchard::Address,
) -> CoreCanonicalTransactionInput {
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    for frame in frames {
        builder
            .add_output(None, receiver, NoteValue::ZERO, frame)
            .unwrap();
    }
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (unauthorized, _) = builder.build::<ZatBalance>(&mut rng).unwrap().unwrap();
    let count = unauthorized.actions().len();
    let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).unwrap();
    let binding_key = SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).unwrap();
    let proof = Proof::new(vec![0; Proof::expected_proof_size(count)]);
    let bundle = unauthorized.map_authorization(
        &mut rng,
        |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceRuntimeTestSpend"),
        |rng, _| {
            OrchardAuthorized::from_parts(
                proof,
                binding_key.sign(&mut *rng, b"CoppiceRuntimeTestBinding"),
            )
        },
    );
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(ACTIVATION_HEIGHT),
        None,
        None,
        None,
        Some(bundle),
    )
    .freeze()
    .unwrap();
    let bundle = transaction.ironwood_bundle().unwrap();
    let nullifiers = bundle
        .actions()
        .iter()
        .map(|action| action.nullifier().to_bytes())
        .collect();
    let commitments = bundle
        .actions()
        .iter()
        .map(|action| action.cmx().to_bytes())
        .collect();
    let mut bytes = Vec::new();
    transaction.write(&mut bytes).unwrap();
    CoreCanonicalTransactionInput {
        tx_index,
        txid: transaction.txid().into(),
        ironwood_nullifiers: nullifiers,
        ironwood_commitments: commitments,
        full_transaction_acquisition: coppice_core::replay::FullTransactionAcquisition::Carrier,
        full_transaction: Some(bytes),
    }
}

fn alternate_rendezvous_receiver(deployment: &DeploymentParameters) -> orchard::Address {
    let ivk = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(
        &deployment.rendezvous.orchard_ivk,
    ))
    .unwrap();
    ivk.address_at(1u32)
}

fn block(
    tip: coppice_core::replay::CoreReplayTip,
    height: u32,
    transactions: Vec<CoreCanonicalTransactionInput>,
) -> CoreCanonicalBlockInput {
    CoreCanonicalBlockInput {
        height,
        block_hash: [height as u8; 32],
        prev_block_hash: tip.block_hash,
        branch_id: BranchId::Nu6_3,
        transactions,
    }
}

#[derive(Clone)]
struct TinyApplication {
    descriptor: ApplicationDescriptor,
    tip: ApplicationTip,
    value: u8,
    history: Vec<(ApplicationTip, u8)>,
}

impl CoppiceApplication for TinyApplication {
    type BlockOutput = u8;
    type ApplyError = ();
    type RewindError = ();

    fn descriptor(&self) -> ApplicationDescriptor {
        self.descriptor
    }

    fn tip(&self) -> ApplicationTip {
        self.tip
    }

    fn state_root(&self) -> [u8; 32] {
        [self.value; 32]
    }

    fn apply_block(&mut self, block: &ApplicationBlockContext) -> Result<u8, ()> {
        let tip = block.tip();
        if self.tip.height.checked_add(1) != Some(tip.height)
            || self.tip.block_hash
                != block
                    .core()
                    .map(|core| core.prev_block_hash())
                    .unwrap_or(self.tip.block_hash)
        {
            return Err(());
        }
        self.history.push((self.tip, self.value));
        if block.is_active() {
            for transaction in block.transactions() {
                if let Some(payload) = transaction.payload() {
                    let [increment] = payload else {
                        return Err(());
                    };
                    self.value = self.value.checked_add(*increment).ok_or(())?;
                }
            }
        }
        self.tip = tip;
        Ok(self.value)
    }

    fn rewind_to(&mut self, height: u32) -> Result<(), ()> {
        while self.tip.height > height {
            let (tip, value) = self.history.pop().ok_or(())?;
            self.tip = tip;
            self.value = value;
        }
        Ok(())
    }

    fn rewind_retention_blocks(&self) -> u32 {
        self.history.len().try_into().unwrap_or(u32::MAX)
    }

    fn oldest_rewind_height(&self) -> u32 {
        self.history
            .first()
            .map_or(self.tip.height, |(tip, _)| tip.height)
    }

    fn retained_tip_at(&self, height: u32) -> Option<ApplicationTip> {
        if height == self.tip.height {
            Some(self.tip)
        } else {
            self.history
                .iter()
                .find(|(tip, _)| tip.height == height)
                .map(|(tip, _)| *tip)
        }
    }
}

#[test]
fn core_routes_a_non_names_application_without_understanding_its_state() {
    let deployment = deployment();
    let parameters = names_v1_core_runtime_parameters(&deployment).unwrap();
    let replay = CoreReplay::new(
        CoreReplayConfiguration::new(ACTIVATION_HEIGHT, 8).unwrap(),
        checkpoint(),
    )
    .unwrap();
    let mut core = CoreRuntime::new(parameters, replay).unwrap();
    let key = ApplicationKey::new(derive_application_id(b"test.only.counter").unwrap(), 1);
    let envelope = ApplicationEnvelopeV1::new(key, vec![7]).unwrap().encode();
    let transaction =
        candidate_transaction(&deployment, core.runtime_id().to_bytes(), &envelope, 0, 3);
    let input = block(core.tip(), ACTIVATION_HEIGHT, vec![transaction]);
    let context = core.apply_block(&input).unwrap();
    assert!(matches!(
        context.transactions()[0].message(),
        ApplicationMessageStatus::Message(message) if message.key() == key
    ));
    let mut application = TinyApplication {
        descriptor: ApplicationDescriptor {
            key,
            activation_height: ACTIVATION_HEIGHT,
        },
        tip: ApplicationTip {
            height: ACTIVATION_HEIGHT - 1,
            block_hash: ACTIVATION_HASH,
        },
        value: 0,
        history: vec![],
    };
    let application_context = context.for_application(application.descriptor()).unwrap();
    assert_eq!(application.apply_block(&application_context), Ok(7));
    assert_eq!(application.state_root(), [7; 32]);
    assert_eq!(core.tip().height, application.tip().height);
}

#[test]
fn later_application_activation_withholds_effects_and_rewinds_deterministically() {
    let deployment = deployment();
    let parameters = names_v1_core_runtime_parameters(&deployment).unwrap();
    let replay = CoreReplay::new(
        CoreReplayConfiguration::new(ACTIVATION_HEIGHT, 8).unwrap(),
        checkpoint(),
    )
    .unwrap();
    let mut core = CoreRuntime::new(parameters, replay).unwrap();
    let key = ApplicationKey::new(derive_application_id(b"future.app").unwrap(), 1);
    let descriptor = ApplicationDescriptor {
        key,
        activation_height: ACTIVATION_HEIGHT + 2,
    };
    let mut application = TinyApplication {
        descriptor,
        tip: ApplicationTip {
            height: ACTIVATION_HEIGHT - 1,
            block_hash: ACTIVATION_HASH,
        },
        value: 0,
        history: vec![],
    };

    for height in [ACTIVATION_HEIGHT, ACTIVATION_HEIGHT + 1] {
        let envelope = ApplicationEnvelopeV1::new(key, vec![7]).unwrap().encode();
        let input = block(
            core.tip(),
            height,
            vec![candidate_transaction(
                &deployment,
                core.runtime_id().to_bytes(),
                &envelope,
                0,
                (height - ACTIVATION_HEIGHT + 1) as u8,
            )],
        );
        let context = core.apply_block(&input).unwrap();
        let scoped = context.for_application(descriptor).unwrap();
        assert!(!scoped.is_active());
        assert!(scoped.core().is_none());
        assert!(scoped.transactions().is_empty());
        assert_eq!(application.apply_block(&scoped), Ok(0));
    }

    let envelope = ApplicationEnvelopeV1::new(key, vec![7]).unwrap().encode();
    let input = block(
        core.tip(),
        ACTIVATION_HEIGHT + 2,
        vec![candidate_transaction(
            &deployment,
            core.runtime_id().to_bytes(),
            &envelope,
            0,
            3,
        )],
    );
    let context = core.apply_block(&input).unwrap();
    let scoped = context.for_application(descriptor).unwrap();
    assert!(scoped.is_active());
    assert!(scoped.core().is_some());
    assert_eq!(scoped.transactions().len(), 1);
    assert_eq!(application.apply_block(&scoped), Ok(7));

    core.rewind_to(ACTIVATION_HEIGHT + 1).unwrap();
    application.rewind_to(ACTIVATION_HEIGHT + 1).unwrap();
    assert_eq!(application.value, 0);
    let replayed = core.apply_block(&input).unwrap();
    let replayed_scoped = replayed.for_application(descriptor).unwrap();
    assert_eq!(application.apply_block(&replayed_scoped), Ok(7));
}

#[test]
fn names_runtime_routes_envelopes_and_restores_split_state_atomically() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    let operation = Operation::Commit {
        commitment: [0x44; 32],
    };
    let envelope = encode_names_v1_envelope(&operation).unwrap();
    let transaction = candidate_transaction(
        &deployment,
        runtime.core().runtime_id().to_bytes(),
        &envelope,
        0,
        5,
    );
    let first = block(runtime.core().tip(), ACTIVATION_HEIGHT, vec![transaction]);
    let applied = runtime.apply_block(&first).unwrap();
    assert_eq!(
        applied.names.transaction_outcomes,
        vec![NamesTransactionOutcome::Applied]
    );
    assert!(runtime.names().state().pending.contains_key(&[0x44; 32]));

    for height in (ACTIVATION_HEIGHT + 1)..=(ACTIVATION_HEIGHT + 4) {
        let input = block(runtime.core().tip(), height, vec![]);
        runtime.apply_block(&input).unwrap();
    }
    let snapshot = runtime.save_snapshot().unwrap();
    let mut restored = NamesRuntime::load_snapshot(deployment.clone(), &snapshot).unwrap();
    assert_eq!(restored.core().tip(), runtime.core().tip());
    assert_eq!(
        restored.core().ironwood_frontier(),
        runtime.core().ironwood_frontier()
    );
    assert_eq!(restored.names().state(), runtime.names().state());
    assert_eq!(restored.names().state_root(), runtime.names().state_root());

    runtime.rewind_to(ACTIVATION_HEIGHT + 1).unwrap();
    restored.rewind_to(ACTIVATION_HEIGHT + 1).unwrap();
    assert_eq!(restored.core().tip(), runtime.core().tip());
    assert_eq!(restored.names().state(), runtime.names().state());
    assert_eq!(restored.names().state_root(), runtime.names().state_root());

    let replacement = block(runtime.core().tip(), ACTIVATION_HEIGHT + 2, vec![]);
    runtime.apply_block(&replacement).unwrap();
    restored.apply_block(&replacement).unwrap();
    assert_eq!(restored.core().tip(), runtime.core().tip());
    assert_eq!(restored.names().state_root(), runtime.names().state_root());

    let mut tampered: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    tampered["application_state_root"][0] = serde_json::json!(255);
    assert!(matches!(
        NamesRuntime::load_snapshot(deployment, &serde_json::to_vec(&tampered).unwrap()),
        Err(coppice::names_runtime::NamesRuntimeSnapshotError::TipMismatch)
            | Err(coppice::names_runtime::NamesRuntimeSnapshotError::RootMismatch)
    ));
}

#[test]
fn same_ivk_alternate_receiver_is_not_routed_or_applied_by_names() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    let operation = Operation::Commit {
        commitment: [0x55; 32],
    };
    let envelope = encode_names_v1_envelope(&operation).unwrap();
    let transaction = candidate_transaction_to_receiver(
        runtime.core().runtime_id().to_bytes(),
        &envelope,
        0,
        8,
        alternate_rendezvous_receiver(&deployment),
    );
    let full_bytes = transaction.full_transaction.as_deref().unwrap();
    let parsed = zcash_primitives::transaction::Transaction::read(
        &mut Cursor::new(full_bytes),
        BranchId::Nu6_3,
    )
    .unwrap();
    let inspection = runtime.core().inspect_transaction(&parsed);
    let action = parsed
        .ironwood_bundle()
        .unwrap()
        .actions()
        .iter()
        .next()
        .unwrap();
    assert!(!runtime.core().rendezvous().action_is_rendezvous(action));
    assert!(inspection.frames().is_empty());
    assert!(matches!(
        inspection.message(),
        ApplicationMessageStatus::NoMessage
    ));

    let before = runtime.names().state().clone();
    let applied = runtime
        .apply_block(&block(
            runtime.core().tip(),
            ACTIVATION_HEIGHT,
            vec![transaction],
        ))
        .unwrap();
    assert!(matches!(
        applied.core.transactions()[0].message(),
        ApplicationMessageStatus::NoMessage
    ));
    assert_eq!(
        applied.names.transaction_outcomes,
        vec![NamesTransactionOutcome::NoOperation]
    );
    assert_eq!(runtime.names().state().names, before.names);
    assert_eq!(runtime.names().state().pending, before.pending);
    assert_eq!(runtime.names().state().recent_spent.len(), 1);
    assert!(!runtime.names().state().pending.contains_key(&[0x55; 32]));
}

#[test]
fn malformed_cpv1_transport_is_not_exposed_as_names_payload() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    let operation = Operation::Commit {
        commitment: [0x66; 32],
    };
    let envelope = encode_names_v1_envelope(&operation).unwrap();
    let mut frames =
        transport::encode_frames(runtime.core().runtime_id().to_bytes(), &envelope).unwrap();
    frames[0][511] = 1;
    let transaction = candidate_transaction_with_frames(
        runtime.core().runtime_id().to_bytes(),
        frames,
        0,
        10,
        coppice::carrier::bulletin_address(deployment.rendezvous).unwrap(),
    );

    let applied = runtime
        .apply_block(&block(
            runtime.core().tip(),
            ACTIVATION_HEIGHT,
            vec![transaction],
        ))
        .unwrap();
    assert!(matches!(
        applied.core.transactions()[0].message(),
        ApplicationMessageStatus::MalformedTransport(transport::Error::Padding)
    ));
    assert_eq!(
        applied.names.transaction_outcomes,
        vec![NamesTransactionOutcome::NoOperation]
    );
    assert!(runtime.names().state().names.is_empty());
    assert!(runtime.names().state().pending.is_empty());
}

#[test]
fn names_snapshot_validation_rewinds_core_at_the_retention_boundary() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    let retention = runtime.reorg_retention_blocks();

    for height in ACTIVATION_HEIGHT..=(ACTIVATION_HEIGHT + retention - 1) {
        let input = block(runtime.core().tip(), height, vec![]);
        runtime.apply_block(&input).unwrap();
    }

    assert_eq!(runtime.oldest_rewind_height(), ACTIVATION_HEIGHT - 1);
    assert!(
        !runtime
            .ironwood_checkpoints()
            .contains_key(&(ACTIVATION_HEIGHT - 1))
    );
    let snapshot = runtime.save_snapshot().unwrap();
    let mut restored = NamesRuntime::load_snapshot(deployment, &snapshot).unwrap();
    assert_eq!(restored.tip(), runtime.tip());
    assert_eq!(restored.state_root(), runtime.state_root());

    restored.rewind_to(ACTIVATION_HEIGHT - 1).unwrap();
    assert_eq!(restored.tip().height, ACTIVATION_HEIGHT - 1);
    assert!(
        restored
            .ironwood_checkpoints()
            .contains_key(&(ACTIVATION_HEIGHT - 1))
    );
}

#[test]
fn composed_snapshot_rejects_mismatched_core_and_names_rewind_boundaries() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    for height in ACTIVATION_HEIGHT..=(ACTIVATION_HEIGHT + 4) {
        runtime
            .apply_block(&block(runtime.core().tip(), height, vec![]))
            .unwrap();
    }
    let snapshot = runtime.save_snapshot().unwrap();
    let mut outer: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    let application_bytes: Vec<u8> =
        serde_json::from_value(outer["application_snapshot"].clone()).unwrap();
    let mut application: serde_json::Value = serde_json::from_slice(&application_bytes).unwrap();
    application["undo"].as_array_mut().unwrap().remove(0);
    outer["application_snapshot"] =
        serde_json::to_value(serde_json::to_vec(&application).unwrap()).unwrap();
    assert!(matches!(
        NamesRuntime::load_snapshot(deployment, &serde_json::to_vec(&outer).unwrap()),
        Err(coppice::names_runtime::NamesRuntimeSnapshotError::InvalidHistory)
    ));
}

#[test]
fn snapshot_rejects_recent_spent_entries_below_the_tip_retention_floor() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    runtime
        .apply_block(&block(runtime.core().tip(), ACTIVATION_HEIGHT, vec![]))
        .unwrap();
    let snapshot = runtime.save_snapshot().unwrap();
    let mut outer: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    let application_bytes: Vec<u8> =
        serde_json::from_value(outer["application_snapshot"].clone()).unwrap();
    let mut application: serde_json::Value = serde_json::from_slice(&application_bytes).unwrap();
    application["state"]["recent_spent"] = serde_json::json!([[vec![1u8; 32], 0]]);
    outer["application_snapshot"] =
        serde_json::to_value(serde_json::to_vec(&application).unwrap()).unwrap();
    assert!(matches!(
        NamesRuntime::load_snapshot(deployment, &serde_json::to_vec(&outer).unwrap()),
        Err(coppice::names_runtime::NamesRuntimeSnapshotError::InvalidState)
    ));
}

#[test]
fn rewound_snapshot_states_use_the_same_recent_spent_floor_validation() {
    let deployment = deployment();
    let mut runtime =
        NamesRuntime::from_names_deployment(deployment.clone(), checkpoint()).unwrap();
    runtime
        .apply_block(&block(runtime.core().tip(), ACTIVATION_HEIGHT, vec![]))
        .unwrap();
    let snapshot = runtime.save_snapshot().unwrap();
    let mut outer: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    let application_bytes: Vec<u8> =
        serde_json::from_value(outer["application_snapshot"].clone()).unwrap();
    let mut application: serde_json::Value = serde_json::from_slice(&application_bytes).unwrap();
    application["undo"][0]["state"]["recent_spent"] = serde_json::json!([[vec![2u8; 32], 0]]);
    outer["application_snapshot"] =
        serde_json::to_value(serde_json::to_vec(&application).unwrap()).unwrap();
    assert!(matches!(
        NamesRuntime::load_snapshot(deployment, &serde_json::to_vec(&outer).unwrap()),
        Err(coppice::names_runtime::NamesRuntimeSnapshotError::InvalidState)
    ));
}
