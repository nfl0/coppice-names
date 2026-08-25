use ::coppice as coppice_core;
use coppice::{
    config::{DeploymentParameters, REGTEST},
    envelope::decode_operation,
    names_runtime::{
        CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplayActivationCheckpoint,
        IronwoodFrontier, NamesRuntime,
    },
};
use coppice_core::transport::reconstruct_frames;
use coppice_names as coppice;
use incrementalmerkletree::Hashable;
use orchard::tree::MerkleHashOrchard;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

/// Deterministic fuzz regression for the two hostile byte-oriented protocol
/// boundaries. Any generated input may be rejected, but parsing must remain
/// total and panic-free.
#[test]
fn arbitrary_operation_and_indexed_frame_bytes_are_panic_free() {
    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
    for iteration in 0..10_000usize {
        let mut operation = vec![0; iteration % 9_000];
        rng.fill_bytes(&mut operation);
        let _ = decode_operation(&operation);

        let frame_count = iteration % 34;
        let mut frames = vec![[0u8; 512]; frame_count];
        for frame in &mut frames {
            rng.fill_bytes(frame);
        }
        let _ = reconstruct_frames(&frames, [0x42; 32]);
    }
}

fn runtime() -> NamesRuntime {
    let deployment = DeploymentParameters {
        network_id: REGTEST.network_id.to_vec(),
        address_network: zcash_protocol::consensus::NetworkType::Regtest,
        activation_height: REGTEST.activation_height,
        minimum_bond_value: REGTEST.minimum_bond_value,
        commit_ttl_blocks: 20,
        reuse_delay_blocks: 10,
        bond_note_max_age_blocks: 100,
        rendezvous: REGTEST.rendezvous,
    };
    NamesRuntime::new(
        deployment,
        CoreReplayActivationCheckpoint {
            height: REGTEST.activation_height - 1,
            block_hash: [0x99; 32],
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    )
    .unwrap()
}

fn apply_generated(runtime: &mut NamesRuntime, hash: [u8; 32], append: bool) {
    let height = runtime.tip().height + 1;
    runtime
        .apply_block(&CoreCanonicalBlockInput {
            height,
            block_hash: hash,
            prev_block_hash: runtime.tip().block_hash,
            branch_id: zcash_protocol::consensus::BranchId::Nu6_3,
            transactions: append
                .then(|| CoreCanonicalTransactionInput {
                    tx_index: 0,
                    txid: [0; 32],
                    ironwood_nullifiers: vec![],
                    ironwood_commitments: vec![MerkleHashOrchard::empty_leaf().to_bytes()],
                    full_transaction_acquisition:
                        coppice_core::replay::FullTransactionAcquisition::None,
                    full_transaction: None,
                })
                .into_iter()
                .collect(),
        })
        .unwrap();
}

/// Deterministic replay property over the persisted delta undo journal: a
/// retained rewind followed by replacement replay converges to a fresh direct
/// replay of the same canonical branch, including tree and checkpoints.
#[test]
fn persisted_delta_reorgs_equal_fresh_replay() {
    for seed in 0u8..8 {
        let mut local = runtime();
        let mut prefix = vec![];
        for index in 0u8..80 {
            let hash = [seed.wrapping_mul(17).wrapping_add(index); 32];
            let append = index % 5 == 0;
            apply_generated(&mut local, hash, append);
            prefix.push((hash, append));
        }
        local = NamesRuntime::load_snapshot(
            local.deployment().clone(),
            &local.save_snapshot().unwrap(),
        )
        .unwrap();

        let rewind_count = 1 + usize::from(seed % 31);
        let common_len = prefix.len() - rewind_count;
        let common_height = (REGTEST.activation_height - 1) + common_len as u32;
        local.rewind_to(common_height).unwrap();

        let mut fresh = runtime();
        for (hash, append) in &prefix[..common_len] {
            apply_generated(&mut fresh, *hash, *append);
        }
        for index in 0..(rewind_count + 7) {
            let hash = [0x80u8.wrapping_add(seed).wrapping_add(index as u8); 32];
            let append = index % 3 == 0;
            apply_generated(&mut local, hash, append);
            apply_generated(&mut fresh, hash, append);
        }

        let restored = NamesRuntime::load_snapshot(
            local.deployment().clone(),
            &local.save_snapshot().unwrap(),
        )
        .unwrap();
        assert_eq!(restored.tip(), fresh.tip());
        assert_eq!(restored.state(), fresh.state());
        assert_eq!(restored.ironwood_frontier(), fresh.ironwood_frontier());
        assert_eq!(
            restored.ironwood_checkpoints(),
            fresh.ironwood_checkpoints()
        );
    }
}
