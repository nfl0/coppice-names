//! Thin wallet composition for the core dedicated v1 BondProof prover.

use coppice::{
    bond::{V1BondProof, V1BondProver, V1BondProverError, V1BondWitness},
    bond_tag::derive_v1_bond_tag,
    config::DeploymentParameters,
};
use orchard::{Note, keys::FullViewingKey, keys::SpendAuthorizingKey};
use rand_core::{CryptoRng, RngCore};

use crate::{AnchorContext, BondFreshnessContext, IronwoodWitness, SelectedBondNote};

/// Private material supplied by the wallet's ordinary key-management layer.
/// This intentionally has no `Debug` implementation.
pub struct WalletBondPrivateMaterial {
    pub note: Note,
    pub full_viewing_key: FullViewingKey,
    pub spend_authorizing_key: SpendAuthorizingKey,
}

#[derive(Debug)]
pub enum WalletBondProverError {
    CommitContextMismatch,
    WitnessPositionMismatch,
    WitnessHeightMismatch,
    WitnessRootMismatch,
    PositionOutsideAnchorTree,
    PositionBelowFreshnessFloor,
    NoteValueMismatch,
    BondTagMismatch,
    Core(V1BondProverError),
}

#[allow(clippy::too_many_arguments)]
pub fn prove_selected_bond<R: RngCore + CryptoRng>(
    prover: &V1BondProver,
    deployment: &DeploymentParameters,
    name: &str,
    canonical_address: &[u8],
    owner_pk: [u8; 32],
    selected_bond: SelectedBondNote,
    private_material: WalletBondPrivateMaterial,
    freshness_context: &BondFreshnessContext,
    anchor_context: &AnchorContext,
    canonical_witness: IronwoodWitness,
    rng: R,
) -> Result<V1BondProof, WalletBondProverError> {
    if freshness_context.commit_height != anchor_context.commit_height {
        return Err(WalletBondProverError::CommitContextMismatch);
    }
    if selected_bond.position != canonical_witness.position {
        return Err(WalletBondProverError::WitnessPositionMismatch);
    }
    if canonical_witness.checkpoint_height != anchor_context.anchor_height {
        return Err(WalletBondProverError::WitnessHeightMismatch);
    }
    if canonical_witness.root != anchor_context.root {
        return Err(WalletBondProverError::WitnessRootMismatch);
    }
    if selected_bond.position >= anchor_context.tree_size {
        return Err(WalletBondProverError::PositionOutsideAnchorTree);
    }
    if selected_bond.position < freshness_context.position_floor {
        return Err(WalletBondProverError::PositionBelowFreshnessFloor);
    }

    let WalletBondPrivateMaterial {
        note,
        full_viewing_key,
        spend_authorizing_key,
    } = private_material;
    if note.value().inner() != selected_bond.value_zat {
        return Err(WalletBondProverError::NoteValueMismatch);
    }
    let derived_tag = derive_v1_bond_tag(&note.nullifier(&full_viewing_key).to_bytes())
        .map_err(|_| WalletBondProverError::BondTagMismatch)?;
    if derived_tag != selected_bond.bond_tag {
        return Err(WalletBondProverError::BondTagMismatch);
    }

    prover
        .prove_v1_bond(
            V1BondWitness {
                note,
                full_viewing_key,
                spend_authorizing_key,
                merkle_path: canonical_witness.merkle_path,
            },
            deployment,
            name,
            canonical_address,
            owner_pk,
            selected_bond.bond_tag,
            anchor_context.root,
            freshness_context.position_floor,
            rng,
        )
        .map_err(WalletBondProverError::Core)
}

#[cfg(test)]
mod tests {
    use coppice::{
        bond::V1BondProver,
        config::Rendezvous,
        owner::{OwnerSigningKey, owner_key_bytes},
    };
    use incrementalmerkletree::{Hashable, Retention};
    use orchard::{
        NoteVersion,
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, RandomSeed, Rho},
        tree::MerkleHashOrchard,
        value::NoteValue,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use zcash_address::unified::{self, Encoding};
    use zcash_protocol::consensus::NetworkType;

    use super::*;
    use crate::IronwoodOutputId;

    struct Case {
        selected: SelectedBondNote,
        material: WalletBondPrivateMaterial,
        freshness: BondFreshnessContext,
        anchor: AnchorContext,
        witness: IronwoodWitness,
    }

    fn deployment() -> DeploymentParameters {
        DeploymentParameters {
            network_id: b"wallet-test".to_vec(),
            address_network: NetworkType::Regtest,
            activation_height: 100,
            minimum_bond_value: 10,
            commit_ttl_blocks: 20,
            reuse_delay_blocks: 10,
            bond_note_max_age_blocks: 100,
            rendezvous: Rendezvous::default(),
        }
    }

    fn address(deployment: &DeploymentParameters) -> Vec<u8> {
        unified::Address::try_from_items(vec![unified::Receiver::Orchard(
            deployment.rendezvous.orchard_receiver,
        )])
        .unwrap()
        .encode(&NetworkType::Regtest)
        .into_bytes()
    }

    fn case() -> Case {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let rho = Option::<Rho>::from(Rho::from_bytes(&[1; 32])).unwrap();
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([55; 32], &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(10),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .unwrap();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 10);
        tree.append(MerkleHashOrchard::empty_leaf(), Retention::Ephemeral)
            .unwrap();
        tree.append(MerkleHashOrchard::from_cmx(&cmx), Retention::Marked)
            .unwrap();
        tree.checkpoint(100).unwrap();
        let path: orchard::tree::MerklePath = tree
            .witness_at_checkpoint_depth(1u64.into(), 0)
            .unwrap()
            .unwrap()
            .into();
        let root = path.root(cmx).to_bytes();
        let tag = derive_v1_bond_tag(&note.nullifier(&fvk).to_bytes()).unwrap();
        Case {
            selected: SelectedBondNote {
                output_id: IronwoodOutputId::new([1; 32], 0),
                value_zat: 10,
                bond_tag: tag,
                position: 1,
            },
            material: WalletBondPrivateMaterial {
                note,
                full_viewing_key: fvk,
                spend_authorizing_key: SpendAuthorizingKey::from(&sk),
            },
            freshness: BondFreshnessContext {
                commit_height: 100,
                floor_height: 99,
                position_floor: 1,
                floor_root: [0; 32],
            },
            anchor: AnchorContext {
                commit_height: 100,
                anchor_height: 100,
                root,
                tree_size: 2,
            },
            witness: IronwoodWitness {
                position: 1,
                checkpoint_height: 100,
                root,
                merkle_path: path,
            },
        }
    }

    fn prove(case: Case) -> Result<V1BondProof, WalletBondProverError> {
        let deployment = deployment();
        let owner = owner_key_bytes(&(&OwnerSigningKey::try_from([1; 32]).unwrap()).into());
        prove_selected_bond(
            &V1BondProver::new().unwrap(),
            &deployment,
            "bonded",
            &address(&deployment),
            owner,
            case.selected,
            case.material,
            &case.freshness,
            &case.anchor,
            case.witness,
            ChaCha20Rng::from_seed([4; 32]),
        )
    }

    #[test]
    fn bridge_accepts_exact_composed_wallet_facts() {
        let result = prove(case()).unwrap();
        assert_eq!(result.position, 1);
        assert_eq!(result.position_floor, 1);
        assert_eq!(result.proof.len(), 4_960);
    }

    #[test]
    fn bridge_rejects_each_mismatched_composed_fact() {
        let mut value = case();
        value.selected.value_zat += 1;
        assert!(matches!(
            prove(value),
            Err(WalletBondProverError::NoteValueMismatch)
        ));

        let mut tag = case();
        tag.selected.bond_tag[0] ^= 1;
        assert!(matches!(
            prove(tag),
            Err(WalletBondProverError::BondTagMismatch)
        ));

        let mut commit = case();
        commit.anchor.commit_height += 1;
        assert!(matches!(
            prove(commit),
            Err(WalletBondProverError::CommitContextMismatch)
        ));

        let mut position = case();
        position.witness.position = 0;
        assert!(matches!(
            prove(position),
            Err(WalletBondProverError::WitnessPositionMismatch)
        ));

        let mut height = case();
        height.witness.checkpoint_height += 1;
        assert!(matches!(
            prove(height),
            Err(WalletBondProverError::WitnessHeightMismatch)
        ));

        let mut root = case();
        root.witness.root[0] ^= 1;
        assert!(matches!(
            prove(root),
            Err(WalletBondProverError::WitnessRootMismatch)
        ));

        let mut outside = case();
        outside.anchor.tree_size = 1;
        assert!(matches!(
            prove(outside),
            Err(WalletBondProverError::PositionOutsideAnchorTree)
        ));

        let mut floor = case();
        floor.freshness.position_floor = 2;
        assert!(matches!(
            prove(floor),
            Err(WalletBondProverError::PositionBelowFreshnessFloor)
        ));
    }
}
