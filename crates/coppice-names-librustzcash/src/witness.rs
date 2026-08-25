//! Wallet-facing Ironwood freshness and historical-witness preparation.
//!
//! The runtime's authenticated checkpoints are chain authority. A wallet tree
//! is proving infrastructure only, and may lack or prune historical data. A
//! richer backend may later implement [`IronwoodWitnessSource`] to reconstruct
//! older witnesses, but callers must never silently substitute another anchor.

use coppice::names_runtime::NamesRuntime;
use incrementalmerkletree::Position;
use orchard::tree::{Anchor, MerklePath};
use shardtree::{ShardTree, error::ShardTreeError, store::ShardStore};
use zcash_client_backend::data_api::{ORCHARD_SHARD_HEIGHT, WalletCommitmentTrees};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    BondNoteSelectionPolicy, FreshnessEligibility, InventoryError, IronwoodViewingCapability,
    OwnedIronwoodNote, SelectedBondNote, select_bond_note_with_policy,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondFreshnessContext {
    pub commit_height: u32,
    pub floor_height: u32,
    pub position_floor: u32,
    pub floor_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshnessContextError {
    CommitBeforeActivation {
        commit_height: u32,
        activation_height: u32,
    },
    CanonicalCommitAboveTip {
        commit_height: u32,
        tip_height: u32,
    },
    TipHeightOverflow {
        tip_height: u32,
    },
    NotNextBlock {
        commit_height: u32,
        next_height: u32,
    },
    CheckpointUnavailable {
        height: u32,
    },
}

fn freshness_at(
    runtime: &NamesRuntime,
    commit_height: u32,
) -> Result<BondFreshnessContext, FreshnessContextError> {
    let deployment = runtime.deployment();
    if commit_height < deployment.activation_height {
        return Err(FreshnessContextError::CommitBeforeActivation {
            commit_height,
            activation_height: deployment.activation_height,
        });
    }
    let activation_floor = deployment.activation_height.checked_sub(1).ok_or(
        FreshnessContextError::CommitBeforeActivation {
            commit_height,
            activation_height: deployment.activation_height,
        },
    )?;
    let floor_height =
        activation_floor.max(commit_height.saturating_sub(deployment.bond_note_max_age_blocks));
    let checkpoint = runtime.ironwood_checkpoints().get(&floor_height).ok_or(
        FreshnessContextError::CheckpointUnavailable {
            height: floor_height,
        },
    )?;
    Ok(BondFreshnessContext {
        commit_height,
        floor_height,
        position_floor: checkpoint.tree_size,
        floor_root: checkpoint.root,
    })
}

pub fn freshness_for_canonical_commit(
    runtime: &NamesRuntime,
    commit_height: u32,
) -> Result<BondFreshnessContext, FreshnessContextError> {
    let tip_height = runtime.tip().height;
    if commit_height > tip_height {
        return Err(FreshnessContextError::CanonicalCommitAboveTip {
            commit_height,
            tip_height,
        });
    }
    freshness_at(runtime, commit_height)
}

pub fn freshness_for_next_block_commit(
    runtime: &NamesRuntime,
    commit_height: u32,
) -> Result<BondFreshnessContext, FreshnessContextError> {
    let tip_height = runtime.tip().height;
    let next_height = tip_height
        .checked_add(1)
        .ok_or(FreshnessContextError::TipHeightOverflow { tip_height })?;
    if commit_height != next_height {
        return Err(FreshnessContextError::NotNextBlock {
            commit_height,
            next_height,
        });
    }
    freshness_at(runtime, commit_height)
}

pub fn select_fresh_bond_note(
    notes: &[OwnedIronwoodNote],
    minimum_bond_value: u64,
    capability: IronwoodViewingCapability,
    context: &BondFreshnessContext,
) -> Result<Option<SelectedBondNote>, InventoryError> {
    select_fresh_bond_note_with_policy(
        notes,
        minimum_bond_value,
        capability,
        context,
        BondNoteSelectionPolicy::ExactMinimum,
    )
}

/// Selects a fresh bond note under an explicit larger-note policy.
pub fn select_fresh_bond_note_with_policy(
    notes: &[OwnedIronwoodNote],
    minimum_bond_value: u64,
    capability: IronwoodViewingCapability,
    context: &BondFreshnessContext,
    policy: BondNoteSelectionPolicy,
) -> Result<Option<SelectedBondNote>, InventoryError> {
    select_bond_note_with_policy(
        notes,
        minimum_bond_value,
        capability,
        FreshnessEligibility::new(context.position_floor),
        policy,
    )
}

#[derive(Clone, Debug)]
pub struct IronwoodWitness {
    pub position: u32,
    pub checkpoint_height: u32,
    pub root: [u8; 32],
    pub merkle_path: MerklePath,
}

pub trait IronwoodWitnessSource {
    type Error;

    fn witness_at(&mut self, position: u32, height: u32) -> Result<IronwoodWitness, Self::Error>;
}

#[derive(Debug)]
pub enum WalletIronwoodWitnessError<E> {
    IronwoodTreeUnavailable,
    CheckpointUnavailable { height: u32 },
    WitnessUnavailable { position: u32, height: u32 },
    Tree(ShardTreeError<E>),
}

impl<E> From<ShardTreeError<E>> for WalletIronwoodWitnessError<E> {
    fn from(value: ShardTreeError<E>) -> Self {
        Self::Tree(value)
    }
}

pub struct WalletCommitmentTreesIronwoodWitnessSource<'a, W> {
    wallet: &'a mut W,
}

impl<'a, W> WalletCommitmentTreesIronwoodWitnessSource<'a, W> {
    pub fn new(wallet: &'a mut W) -> Self {
        Self { wallet }
    }
}

fn witness_from_tree<S>(
    tree: &mut ShardTree<S, { ORCHARD_SHARD_HEIGHT * 2 }, ORCHARD_SHARD_HEIGHT>,
    position: u32,
    height: u32,
) -> Result<IronwoodWitness, WalletIronwoodWitnessError<S::Error>>
where
    S: ShardStore<H = orchard::tree::MerkleHashOrchard, CheckpointId = BlockHeight>,
{
    let checkpoint_height = BlockHeight::from_u32(height);
    let root: Anchor = tree
        .root_at_checkpoint_id(&checkpoint_height)?
        .ok_or(WalletIronwoodWitnessError::CheckpointUnavailable { height })?
        .into();
    let tree_position = Position::from(u64::from(position));
    let merkle_path: MerklePath = tree
        .witness_at_checkpoint_id_caching(tree_position, &checkpoint_height)?
        .ok_or(WalletIronwoodWitnessError::WitnessUnavailable { position, height })?
        .into();
    Ok(IronwoodWitness {
        position,
        checkpoint_height: height,
        root: root.to_bytes(),
        merkle_path,
    })
}

impl<W> IronwoodWitnessSource for WalletCommitmentTreesIronwoodWitnessSource<'_, W>
where
    W: WalletCommitmentTrees,
{
    type Error = WalletIronwoodWitnessError<W::Error>;

    fn witness_at(&mut self, position: u32, height: u32) -> Result<IronwoodWitness, Self::Error> {
        self.wallet
            .with_ironwood_tree_mut::<_, _, Self::Error>(|tree| {
                witness_from_tree(tree, position, height)
            })?
            .ok_or(WalletIronwoodWitnessError::IronwoodTreeUnavailable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorContext {
    pub commit_height: u32,
    pub anchor_height: u32,
    pub root: [u8; 32],
    pub tree_size: u32,
}

#[derive(Debug)]
pub enum ResolveWitnessError<E> {
    AnchorBeforeCommit {
        commit_height: u32,
        anchor_height: u32,
    },
    AnchorAboveTip {
        anchor_height: u32,
        tip_height: u32,
    },
    CheckpointUnavailable {
        height: u32,
    },
    PositionOutsideTree {
        position: u32,
        tree_size: u32,
        height: u32,
    },
    Source(E),
    WrongWitnessHeight {
        requested: u32,
        actual: u32,
    },
    WrongWitnessPosition {
        requested: u32,
        actual: u32,
    },
    RootMismatch {
        height: u32,
        canonical: [u8; 32],
        wallet: [u8; 32],
    },
}

pub fn anchor_for_registration(
    runtime: &NamesRuntime,
    commit_height: u32,
    anchor_height: u32,
) -> Result<AnchorContext, ResolveWitnessError<std::convert::Infallible>> {
    if anchor_height < commit_height {
        return Err(ResolveWitnessError::AnchorBeforeCommit {
            commit_height,
            anchor_height,
        });
    }
    let tip_height = runtime.tip().height;
    if anchor_height > tip_height {
        return Err(ResolveWitnessError::AnchorAboveTip {
            anchor_height,
            tip_height,
        });
    }
    let checkpoint = runtime.ironwood_checkpoints().get(&anchor_height).ok_or(
        ResolveWitnessError::CheckpointUnavailable {
            height: anchor_height,
        },
    )?;
    Ok(AnchorContext {
        commit_height,
        anchor_height,
        root: checkpoint.root,
        tree_size: checkpoint.tree_size,
    })
}

pub fn choose_current_anchor(
    runtime: &NamesRuntime,
    commit_height: u32,
) -> Result<AnchorContext, ResolveWitnessError<std::convert::Infallible>> {
    anchor_for_registration(runtime, commit_height, runtime.tip().height)
}

pub fn resolve_canonical_ironwood_witness<S: IronwoodWitnessSource>(
    runtime: &NamesRuntime,
    source: &mut S,
    position: u32,
    anchor_height: u32,
) -> Result<IronwoodWitness, ResolveWitnessError<S::Error>> {
    let checkpoint = runtime.ironwood_checkpoints().get(&anchor_height).ok_or(
        ResolveWitnessError::CheckpointUnavailable {
            height: anchor_height,
        },
    )?;
    if position >= checkpoint.tree_size {
        return Err(ResolveWitnessError::PositionOutsideTree {
            position,
            tree_size: checkpoint.tree_size,
            height: anchor_height,
        });
    }
    let witness = source
        .witness_at(position, anchor_height)
        .map_err(ResolveWitnessError::Source)?;
    if witness.checkpoint_height != anchor_height {
        return Err(ResolveWitnessError::WrongWitnessHeight {
            requested: anchor_height,
            actual: witness.checkpoint_height,
        });
    }
    if witness.position != position {
        return Err(ResolveWitnessError::WrongWitnessPosition {
            requested: position,
            actual: witness.position,
        });
    }
    if witness.root != checkpoint.root {
        return Err(ResolveWitnessError::RootMismatch {
            height: anchor_height,
            canonical: checkpoint.root,
            wallet: witness.root,
        });
    }
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use coppice::{
        config::{DeploymentParameters, Rendezvous},
        constants::REGTEST_NETWORK_ID,
        names_runtime::{
            CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplayActivationCheckpoint,
            IronwoodFrontier,
        },
    };
    use incrementalmerkletree::{Hashable, Marking, Retention};
    use orchard::tree::MerkleHashOrchard;
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType};

    use super::*;
    use crate::IronwoodOutputId;

    fn deployment(max_age: u32) -> DeploymentParameters {
        DeploymentParameters {
            network_id: REGTEST_NETWORK_ID.to_vec(),
            address_network: NetworkType::Regtest,
            activation_height: 100,
            minimum_bond_value: 10,
            commit_ttl_blocks: 20,
            reuse_delay_blocks: 10,
            bond_note_max_age_blocks: max_age,
            rendezvous: Rendezvous::default(),
        }
    }

    fn runtime(max_age: u32) -> NamesRuntime {
        NamesRuntime::new(
            deployment(max_age),
            CoreReplayActivationCheckpoint {
                height: 99,
                block_hash: [99; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap()
    }

    fn apply_block(runtime: &mut NamesRuntime, commitments: usize) {
        let tip = runtime.tip();
        let height = tip.height.checked_add(1).unwrap();
        let transactions = (commitments > 0)
            .then(|| CoreCanonicalTransactionInput {
                tx_index: 0,
                txid: [height as u8; 32],
                ironwood_nullifiers: vec![],
                ironwood_commitments: (0..commitments)
                    .map(|index| leaf((height as u8).wrapping_add(index as u8)).to_bytes())
                    .collect(),
                full_tx_required: false,
                candidate_full_tx: None,
            })
            .into_iter()
            .collect();
        runtime
            .apply_block(&CoreCanonicalBlockInput {
                height,
                block_hash: [height as u8; 32],
                prev_block_hash: tip.block_hash,
                branch_id: BranchId::Nu6_3,
                transactions,
            })
            .unwrap();
    }

    fn leaf(seed: u8) -> MerkleHashOrchard {
        let mut bytes = [0; 32];
        bytes[0] = seed;
        Option::from(MerkleHashOrchard::from_bytes(&bytes)).unwrap()
    }

    fn advance_to(runtime: &mut NamesRuntime, height: u32) {
        while runtime.tip().height < height {
            apply_block(runtime, 0);
        }
    }

    fn test_witness(position: u32, height: u32) -> IronwoodWitness {
        type Tree = ShardTree<MemoryShardStore<MerkleHashOrchard, BlockHeight>, 32, 16>;
        let mut tree = Tree::new(MemoryShardStore::empty(), 200);
        for i in 0..=position {
            tree.append(
                MerkleHashOrchard::empty_leaf(),
                Retention::Checkpoint {
                    id: BlockHeight::from_u32(height + i),
                    marking: Marking::Marked,
                },
            )
            .unwrap();
        }
        witness_from_tree(&mut tree, position, height + position).unwrap()
    }

    fn note(id: u8, position: Option<u32>) -> OwnedIronwoodNote {
        OwnedIronwoodNote {
            output_id: IronwoodOutputId::new([id; 32], u32::from(id)),
            value_zat: 10,
            nullifier: [id; 32],
            position,
            locked: false,
            spendable: true,
        }
    }

    #[test]
    fn freshness_formula_activation_saturation_and_normal_boundaries() {
        let mut early = runtime(50);
        apply_block(&mut early, 0);
        let context = freshness_for_canonical_commit(&early, 100).unwrap();
        assert_eq!(context.floor_height, 99);

        let mut saturated = runtime(150);
        apply_block(&mut saturated, 0);
        assert_eq!(
            freshness_for_canonical_commit(&saturated, 100)
                .unwrap()
                .floor_height,
            99
        );

        let mut normal = runtime(100);
        advance_to(&mut normal, 250);
        assert_eq!(
            freshness_for_canonical_commit(&normal, 250)
                .unwrap()
                .floor_height,
            150
        );
    }

    #[test]
    fn commit_height_modes_are_bounded_and_missing_floor_is_explicit() {
        let mut runtime = runtime(100);
        apply_block(&mut runtime, 0);
        assert!(freshness_for_next_block_commit(&runtime, 101).is_ok());
        assert!(matches!(
            freshness_for_next_block_commit(&runtime, 102),
            Err(FreshnessContextError::NotNextBlock { .. })
        ));
        assert!(matches!(
            freshness_for_canonical_commit(&runtime, 101),
            Err(FreshnessContextError::CanonicalCommitAboveTip { .. })
        ));
        advance_to(&mut runtime, 250);
        assert_eq!(
            freshness_for_canonical_commit(&runtime, 100),
            Err(FreshnessContextError::CheckpointUnavailable { height: 99 })
        );
    }

    #[test]
    fn selection_delegates_exact_floor_policy() {
        let context = BondFreshnessContext {
            commit_height: 100,
            floor_height: 99,
            position_floor: 7,
            floor_root: [0; 32],
        };
        let at = note(3, Some(7));
        let selected = select_fresh_bond_note(
            &[note(1, Some(6)), note(2, None), at],
            10,
            IronwoodViewingCapability::FullViewing,
            &context,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.output_id, at.output_id);
    }

    #[test]
    fn shardtree_helper_uses_exact_checkpoint_and_witness() {
        type Tree = ShardTree<MemoryShardStore<MerkleHashOrchard, BlockHeight>, 32, 16>;
        let mut tree = Tree::new(MemoryShardStore::empty(), 10);
        tree.append(
            MerkleHashOrchard::empty_leaf(),
            Retention::Checkpoint {
                id: BlockHeight::from_u32(100),
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let witness = witness_from_tree(&mut tree, 0, 100).unwrap();
        assert_eq!(witness.position, 0);
        assert_eq!(witness.checkpoint_height, 100);
        let expected: Anchor = tree
            .root_at_checkpoint_id(&BlockHeight::from_u32(100))
            .unwrap()
            .unwrap()
            .into();
        assert_eq!(witness.root, expected.to_bytes());
        assert!(matches!(
            witness_from_tree(&mut tree, 0, 101),
            Err(WalletIronwoodWitnessError::CheckpointUnavailable { height: 101 })
        ));
        assert!(matches!(
            witness_from_tree(&mut tree, 1, 100),
            Err(WalletIronwoodWitnessError::Tree(_))
                | Err(WalletIronwoodWitnessError::WitnessUnavailable { .. })
        ));
    }

    struct FakeSource {
        witness: Option<IronwoodWitness>,
        calls: usize,
    }

    impl IronwoodWitnessSource for FakeSource {
        type Error = Infallible;

        fn witness_at(
            &mut self,
            _position: u32,
            _height: u32,
        ) -> Result<IronwoodWitness, Self::Error> {
            self.calls += 1;
            Ok(self.witness.take().unwrap())
        }
    }

    #[test]
    fn canonical_resolution_checks_order_position_height_and_root() {
        let mut runtime = runtime(100);
        apply_block(&mut runtime, 1);
        let checkpoint = runtime.ironwood_checkpoints()[&100];

        let mut missing = FakeSource {
            witness: None,
            calls: 0,
        };
        assert!(matches!(
            resolve_canonical_ironwood_witness(&runtime, &mut missing, 0, 101),
            Err(ResolveWitnessError::CheckpointUnavailable { height: 101 })
        ));
        assert_eq!(missing.calls, 0);

        let mut outside = FakeSource {
            witness: None,
            calls: 0,
        };
        assert!(matches!(
            resolve_canonical_ironwood_witness(&runtime, &mut outside, 1, 100),
            Err(ResolveWitnessError::PositionOutsideTree { .. })
        ));
        assert_eq!(outside.calls, 0);

        for (witness, expected) in [
            (
                {
                    let mut w = test_witness(0, 100);
                    w.root = checkpoint.root;
                    w
                },
                "ok",
            ),
            (
                {
                    let mut w = test_witness(0, 100);
                    w.checkpoint_height = 99;
                    w.root = checkpoint.root;
                    w
                },
                "height",
            ),
            (
                {
                    let mut w = test_witness(0, 100);
                    w.position = 1;
                    w.root = checkpoint.root;
                    w
                },
                "position",
            ),
            (
                {
                    let mut w = test_witness(0, 100);
                    w.root = checkpoint.root;
                    w.root[0] ^= 1;
                    w
                },
                "root",
            ),
        ] {
            let result = resolve_canonical_ironwood_witness(
                &runtime,
                &mut FakeSource {
                    witness: Some(witness),
                    calls: 0,
                },
                0,
                100,
            );
            match expected {
                "ok" => assert!(result.is_ok()),
                "height" => assert!(matches!(
                    result,
                    Err(ResolveWitnessError::WrongWitnessHeight { .. })
                )),
                "position" => assert!(matches!(
                    result,
                    Err(ResolveWitnessError::WrongWitnessPosition { .. })
                )),
                "root" => assert!(matches!(
                    result,
                    Err(ResolveWitnessError::RootMismatch { .. })
                )),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn reorg_rejects_old_branch_root_and_accepts_current_root() {
        let mut runtime = runtime(100);
        apply_block(&mut runtime, 1);
        let old_root = runtime.ironwood_checkpoints()[&100].root;
        runtime.rewind_to(99).unwrap();
        apply_block(&mut runtime, 2);
        let replacement_root = runtime.ironwood_checkpoints()[&100].root;
        assert_ne!(old_root, replacement_root);

        let mut old = test_witness(0, 100);
        old.root = old_root;
        assert!(matches!(
            resolve_canonical_ironwood_witness(
                &runtime,
                &mut FakeSource {
                    witness: Some(old),
                    calls: 0
                },
                0,
                100,
            ),
            Err(ResolveWitnessError::RootMismatch { .. })
        ));

        let mut replacement = test_witness(0, 100);
        replacement.root = replacement_root;
        assert!(
            resolve_canonical_ironwood_witness(
                &runtime,
                &mut FakeSource {
                    witness: Some(replacement),
                    calls: 0
                },
                0,
                100,
            )
            .is_ok()
        );
    }
}
