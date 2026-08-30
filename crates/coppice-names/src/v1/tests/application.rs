use std::{collections::BTreeMap, sync::Arc};

use super::super::application::NamesApplication;
use super::super::{
    CanonicalBlock, CanonicalTransaction, ChainTip, GenesisStatement, TransitionStatement,
    V1Operation, V1Parameters, V1StateMachine, V1StateProofVerifier,
};
use coppice::application::{CoppiceApplication, PersistedCoppiceApplication};
use coppice::identity::{CoreRuntimeParameters, ZcashNetwork};
use coppice::replay::{
    CoreCanonicalBlockInput, CoreReplay, CoreReplayActivationCheckpoint, CoreReplayConfiguration,
    IronwoodFrontier,
};
use coppice::runtime::CoreRuntime;
use zcash_protocol::consensus::BranchId;

#[derive(Clone)]
struct NoopProofs;

impl V1StateProofVerifier for NoopProofs {
    fn verify_genesis(&self, _statement: &GenesisStatement, _proof: &[u8]) -> bool {
        false
    }

    fn verify_transition(&self, _statement: &TransitionStatement, _proof: &[u8]) -> bool {
        false
    }
}

fn core() -> CoreRuntime {
    let parameters = CoreRuntimeParameters {
        runtime_protocol_id: b"coppice.runtime".to_vec(),
        runtime_protocol_version: 1,
        zcash_network_domain: b"coppice-runtime-regtest-v1".to_vec(),
        zcash_network: ZcashNetwork::Regtest,
        runtime_activation_height: 1,
        carrier_protocol_id: b"CPV1".to_vec(),
        rendezvous_ivk: hex::decode(
            "65deb2b3ee7ac69020543f40f21122cb6dc1f4201a329fcdf9d5e3bb2dfbbabe29d542352fe36c3c7b24c2989dc9d0000b9e04f444e05dc4538bde395c0e6008",
        )
        .unwrap()
        .try_into()
        .unwrap(),
        rendezvous_receiver: hex::decode(
            "9ec59e4d447ba285086cc3456cadf62004a19b6a7989c726daaa9944a6cdbf25f7bfa51afa15b66da53881",
        )
        .unwrap()
        .try_into()
        .unwrap(),
    }
    .validate()
    .unwrap();
    let replay = CoreReplay::new(
        CoreReplayConfiguration::new(1, 4).unwrap(),
        CoreReplayActivationCheckpoint {
            height: 0,
            block_hash: [0; 32],
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    )
    .unwrap();
    CoreRuntime::new(parameters, replay).unwrap()
}

fn block(core: &CoreRuntime, height: u32, hash: u8) -> CoreCanonicalBlockInput {
    CoreCanonicalBlockInput {
        height,
        block_hash: [hash; 32],
        prev_block_hash: core.tip().block_hash,
        branch_id: BranchId::Nu6_3,
        transactions: vec![],
    }
}

#[test]
fn delayed_activation_tracks_position_then_replays_active_blocks() {
    let core = core();
    let app = NamesApplication::new(
        V1Parameters {
            activation_height: 3,
            ..V1Parameters::testing()
        },
        ChainTip {
            height: core.tip().height,
            block_hash: core.tip().block_hash,
        },
        Arc::new(NoopProofs),
        4,
    )
    .unwrap();
    let mut runtime = coppice::compositor::CoppiceRuntime::new(core, app).unwrap();

    let first = runtime.apply_block(&block(runtime.core(), 1, 1)).unwrap();
    assert!(!first.applications.active);
    assert!(first.applications.replay.is_none());
    let second = runtime.apply_block(&block(runtime.core(), 2, 2)).unwrap();
    assert!(!second.applications.active);
    let third = runtime.apply_block(&block(runtime.core(), 3, 3)).unwrap();
    assert!(third.applications.active);
    assert_eq!(third.applications.replay.unwrap().tip.height, 3);
}

#[test]
fn checkpoint_restore_rebuilds_derived_indexes_and_tip() {
    let core = core();
    let app = NamesApplication::new(
        V1Parameters::testing(),
        ChainTip {
            height: core.tip().height,
            block_hash: core.tip().block_hash,
        },
        Arc::new(NoopProofs),
        4,
    )
    .unwrap();
    let mut runtime = coppice::compositor::CoppiceRuntime::new(core, app).unwrap();
    runtime.apply_block(&block(runtime.core(), 1, 1)).unwrap();
    let snapshot = runtime.applications().save_application_snapshot().unwrap();
    assert_eq!(snapshot.oldest_rewind_height, 1);

    let restored = NamesApplication::from_snapshot(snapshot, Arc::new(NoopProofs), 4).unwrap();
    assert_eq!(restored.tip().height, 1);
    assert_eq!(restored.oldest_rewind_height(), 1);
    assert_eq!(restored.state_root(), runtime.applications().state_root());
}

#[test]
fn checkpoint_metadata_cannot_claim_unpersisted_undo_history() {
    let core = core();
    let app = NamesApplication::new(
        V1Parameters::testing(),
        ChainTip {
            height: core.tip().height,
            block_hash: core.tip().block_hash,
        },
        Arc::new(NoopProofs),
        4,
    )
    .unwrap();
    let mut runtime = coppice::compositor::CoppiceRuntime::new(core, app).unwrap();
    runtime.apply_block(&block(runtime.core(), 1, 1)).unwrap();
    let mut snapshot = runtime.applications().save_application_snapshot().unwrap();
    snapshot.oldest_rewind_height = 0;
    assert!(matches!(
        NamesApplication::from_snapshot(snapshot, Arc::new(NoopProofs), 4),
        Err(super::super::application::NamesApplicationSnapshotError::InvalidRewindBoundary)
    ));
}

#[test]
fn checkpoint_runtime_validation_uses_core_activation_boundary() {
    let core = core();
    let app = NamesApplication::new(
        V1Parameters {
            activation_height: 3,
            ..V1Parameters::testing()
        },
        ChainTip {
            height: core.tip().height,
            block_hash: core.tip().block_hash,
        },
        Arc::new(NoopProofs),
        4,
    )
    .unwrap();
    let mut runtime = coppice::compositor::CoppiceRuntime::new(core, app).unwrap();
    runtime.apply_block(&block(runtime.core(), 1, 1)).unwrap();
    let snapshot = runtime.applications().save_application_snapshot().unwrap();

    assert!(
        NamesApplication::from_snapshot_at_runtime(snapshot.clone(), Arc::new(NoopProofs), 4, 2,)
            .is_ok()
    );
    assert!(matches!(
        NamesApplication::from_snapshot_at_runtime(snapshot, Arc::new(NoopProofs), 4, 3),
        Err(
            super::super::application::NamesApplicationSnapshotError::Metadata(
                coppice::application::ApplicationSnapshotValidationError::InvalidRewindBoundary
            )
        )
    ));
}

#[test]
fn machine_checkpoint_round_trip_preserves_pending_commit_without_serializing_indexes() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let commitment = [7; 32];
    machine
        .apply_block(
            &CanonicalBlock {
                height: 1,
                block_hash: [1; 32],
                prev_block_hash: [0; 32],
                transactions: vec![CanonicalTransaction {
                    tx_index: 0,
                    txid: [2; 32],
                    actions: vec![],
                    operations: vec![V1Operation::Commit { commitment }],
                }],
            },
            &NoopProofs,
        )
        .unwrap();
    let bytes = machine.snapshot_bytes().unwrap();
    let restored = V1StateMachine::from_snapshot_bytes(&bytes).unwrap();
    assert_eq!(restored.tip(), machine.tip());
    assert_eq!(restored.pending(commitment), machine.pending(commitment));
}

#[test]
fn hosted_application_exposes_bounded_exact_name_resolution() {
    let app = NamesApplication::new(
        V1Parameters::testing(),
        ChainTip {
            height: 0,
            block_hash: [0; 32],
        },
        Arc::new(NoopProofs),
        4,
    )
    .unwrap();
    let source = BTreeMap::new();
    let result = app.resolve_fresh("alice", &source).unwrap();
    assert_eq!(result.status, super::super::ResolutionStatus::Missing);
    assert!(result.state.is_none());
}
