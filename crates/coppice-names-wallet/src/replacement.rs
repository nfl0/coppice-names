//! Wallet-side construction for the replacement Names protocol.

use anyhow::{Context, Result, ensure};
use coppice_names::{
    codec::Operation,
    deployment::DeploymentParameters,
    proof::OrchardProofProver,
    protocol::{BOND_ZATOSHIS, CanonicalUa, CommitRef, FieldElement, Name},
    publication::{PreparedPublication, prepare_publication},
    reducer::{Head, Lifecycle},
    statement::{RefreshStatement, RevealStatement},
};
use orchard::{
    Address,
    keys::{FullViewingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note},
    value::NoteValue,
};
use rand_core::Rng;

use crate::builder::{CarrierOutput, ChangeOutput, FundingSpend, NamesIronwoodPlan};
use crate::recovery::{
    derive_commit_opening, derive_name_spending_key, derive_refresh_bond_note,
    derive_reveal_bond_note,
};

/// Recoverable COMMIT material ready for an ordinary reviewed send.
pub struct PreparedCommit {
    target_epoch: u32,
    publication: PreparedPublication,
}

impl PreparedCommit {
    pub const fn target_epoch(&self) -> u32 {
        self.target_epoch
    }

    pub const fn publication(&self) -> &PreparedPublication {
        &self.publication
    }
}

/// Proven REVEAL publication and the exact designated successor opening that
/// the Ironwood PCZT builder must place in the declared action.
pub struct PreparedReveal {
    statement: RevealStatement,
    successor_note: Note,
    publication: PreparedPublication,
    operation_height: u32,
}

impl PreparedReveal {
    pub const fn statement(&self) -> &RevealStatement {
        &self.statement
    }

    pub const fn successor_note(&self) -> &Note {
        &self.successor_note
    }

    pub const fn publication(&self) -> &PreparedPublication {
        &self.publication
    }

    /// Produces the physical designated-pair plan consumed by the pinned
    /// Ironwood PCZT builder. Every carrier is fixed to the derived name route
    /// and zero value; callers control only ordinary fee funding and change.
    pub fn ironwood_plan(
        &self,
        designated_fvk: FullViewingKey,
        designated_spend: Note,
        funding_spends: Vec<FundingSpend>,
        change_outputs: Vec<ChangeOutput>,
    ) -> Result<NamesIronwoodPlan> {
        replacement_ironwood_plan(
            &self.publication,
            self.successor_note,
            designated_fvk,
            designated_spend,
            funding_spends,
            change_outputs,
            self.operation_height,
        )
    }
}

/// Proven REFRESH publication and its exact successor opening. UPDATE and
/// RENEW are the same protocol operation: the supplied UA may change or stay
/// equal, and every accepted REFRESH starts a fresh lease.
pub struct PreparedRefresh {
    statement: RefreshStatement,
    successor_note: Note,
    publication: PreparedPublication,
    operation_height: u32,
}

impl PreparedRefresh {
    pub const fn statement(&self) -> &RefreshStatement {
        &self.statement
    }

    pub const fn successor_note(&self) -> &Note {
        &self.successor_note
    }

    pub const fn publication(&self) -> &PreparedPublication {
        &self.publication
    }

    pub fn ironwood_plan(
        &self,
        designated_fvk: FullViewingKey,
        designated_spend: Note,
        funding_spends: Vec<FundingSpend>,
        change_outputs: Vec<ChangeOutput>,
    ) -> Result<NamesIronwoodPlan> {
        replacement_ironwood_plan(
            &self.publication,
            self.successor_note,
            designated_fvk,
            designated_spend,
            funding_spends,
            change_outputs,
            self.operation_height,
        )
    }
}

/// Prepares a COMMIT for one exact scheduled REVEAL height. No secret is
/// retained: the same wallet seed, name, deployment, and epoch rederive the
/// opening when REVEAL is built.
pub fn prepare_commit(
    wallet_seed: &[u8],
    deployment: DeploymentParameters,
    name: &Name,
    reveal_height: u32,
) -> Result<PreparedCommit> {
    let deployment = deployment
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid Names deployment: {error:?}"))?;
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow::anyhow!("derive Names deployment ID: {error:?}"))?;
    let schedule = deployment.schedule(deployment_id);
    let name_id = name
        .id()
        .map_err(|error| anyhow::anyhow!("derive canonical name ID: {error:?}"))?;
    ensure!(
        schedule.accepts_operation(name_id, reveal_height),
        "REVEAL height is outside the name's canonical operation window"
    );
    let target_epoch = schedule
        .epoch(reveal_height)
        .map_err(|error| anyhow::anyhow!("derive REVEAL epoch: {error:?}"))?;
    let spending_key = derive_name_spending_key(wallet_seed, deployment_id, name)
        .map_err(|error| anyhow::anyhow!("derive per-name authority: {error:?}"))?;
    let opening = derive_commit_opening(&spending_key, deployment_id, name, target_epoch)
        .map_err(|error| anyhow::anyhow!("derive recoverable COMMIT opening: {error:?}"))?;
    let publication = prepare_publication(
        Operation::Commit {
            commitment: opening.commitment(),
        },
        deployment,
    )
    .map_err(|error| anyhow::anyhow!("prepare COMMIT publication: {error:?}"))?;
    Ok(PreparedCommit {
        target_epoch,
        publication,
    })
}

/// Inputs already fixed by note selection and the intended Ironwood layout.
pub struct RevealInputs<'a> {
    pub wallet_seed: &'a [u8],
    pub deployment: DeploymentParameters,
    pub name: Name,
    pub commit_ref: CommitRef,
    pub ua: CanonicalUa,
    pub operation_height: u32,
    pub designated_action_index: u32,
    pub registration_fvk: &'a FullViewingKey,
    pub registration_note: Note,
}

/// Constructs the deterministic successor, proves the hidden COMMIT/authority
/// relation, and freezes the complete name-routed publication.
pub fn prepare_reveal(
    inputs: RevealInputs<'_>,
    prover: &OrchardProofProver,
    rng: impl Rng,
) -> Result<PreparedReveal> {
    let RevealInputs {
        wallet_seed,
        deployment,
        name,
        commit_ref,
        ua,
        operation_height,
        designated_action_index,
        registration_fvk,
        registration_note,
    } = inputs;
    let deployment = deployment
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid Names deployment: {error:?}"))?;
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow::anyhow!("derive Names deployment ID: {error:?}"))?;
    let schedule = deployment.schedule(deployment_id);
    let name_id = name
        .id()
        .map_err(|error| anyhow::anyhow!("derive canonical name ID: {error:?}"))?;
    ensure!(
        schedule.accepts_operation(name_id, operation_height),
        "REVEAL height is outside the name's canonical operation window"
    );
    ensure!(
        schedule.accepts_commit(commit_ref.height, operation_height),
        "referenced COMMIT is not mature and unexpired at the REVEAL height"
    );
    ensure!(
        registration_note.value().inner() == BOND_ZATOSHIS,
        "REVEAL designated input is not exactly the one-ZEC bond"
    );
    let target_epoch = schedule
        .epoch(operation_height)
        .map_err(|error| anyhow::anyhow!("derive REVEAL epoch: {error:?}"))?;
    let spending_key = derive_name_spending_key(wallet_seed, deployment_id, &name)
        .map_err(|error| anyhow::anyhow!("derive per-name authority: {error:?}"))?;
    let opening = derive_commit_opening(&spending_key, deployment_id, &name, target_epoch)
        .map_err(|error| anyhow::anyhow!("derive recoverable COMMIT opening: {error:?}"))?;
    let action_nullifier =
        FieldElement::from_bytes(registration_note.nullifier(registration_fvk).to_bytes())
            .map_err(|error| anyhow::anyhow!("derive designated nullifier: {error:?}"))?;
    let successor_note = derive_reveal_bond_note(
        &spending_key,
        deployment_id,
        commit_ref,
        target_epoch,
        &ua,
        designated_action_index,
        action_nullifier,
    )
    .map_err(|error| anyhow::anyhow!("derive recoverable REVEAL bond note: {error:?}"))?;
    let successor_fvk = FullViewingKey::from(&spending_key);
    let action_commitment = FieldElement::from_bytes(
        ExtractedNoteCommitment::from(successor_note.commitment()).to_bytes(),
    )
    .map_err(|error| anyhow::anyhow!("derive successor commitment: {error:?}"))?;
    let successor_future_nf =
        FieldElement::from_bytes(successor_note.nullifier(&successor_fvk).to_bytes())
            .map_err(|error| anyhow::anyhow!("derive successor nullifier: {error:?}"))?;
    let statement = RevealStatement {
        deployment_id,
        name_id,
        inclusion_epoch: target_epoch,
        commitment: opening.commitment(),
        commit_ref,
        ua: ua.clone(),
        action_index: designated_action_index,
        action_nullifier,
        action_commitment,
        successor_future_nf,
    };
    let proof = prover
        .prove_reveal(
            &statement,
            successor_note,
            &spending_key,
            opening.secret(),
            rng,
        )
        .map_err(|error| anyhow::anyhow!("prove REVEAL: {error:?}"))?;
    let operation = Operation::Reveal {
        name,
        commit: commit_ref,
        ua,
        action_index: designated_action_index,
        successor_future_nf,
        proof,
    };
    let publication = prepare_publication(operation, deployment)
        .map_err(|error| anyhow::anyhow!("prepare REVEAL publication: {error:?}"))?;
    ensure!(
        publication.carrier_value_zatoshis() == 0,
        "replacement Names carrier value is not zero"
    );
    Ok(PreparedReveal {
        statement,
        successor_note,
        publication,
        operation_height,
    })
}

/// Inputs fixed by the accepted predecessor and intended Ironwood layout.
pub struct RefreshInputs<'a> {
    pub wallet_seed: &'a [u8],
    pub deployment: DeploymentParameters,
    pub name: Name,
    pub predecessor: Head,
    pub predecessor_note: Note,
    pub ua: CanonicalUa,
    pub operation_height: u32,
    pub designated_action_index: u32,
}

/// Proves one same-authority predecessor-to-successor REFRESH and freezes its
/// complete name-routed publication.
pub fn prepare_refresh(
    inputs: RefreshInputs<'_>,
    prover: &OrchardProofProver,
    rng: impl Rng,
) -> Result<PreparedRefresh> {
    let RefreshInputs {
        wallet_seed,
        deployment,
        name,
        predecessor,
        predecessor_note,
        ua,
        operation_height,
        designated_action_index,
    } = inputs;
    let deployment = deployment
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid Names deployment: {error:?}"))?;
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow::anyhow!("derive Names deployment ID: {error:?}"))?;
    let schedule = deployment.schedule(deployment_id);
    let name_id = name
        .id()
        .map_err(|error| anyhow::anyhow!("derive canonical name ID: {error:?}"))?;
    ensure!(
        predecessor.name == name,
        "predecessor belongs to another name"
    );
    ensure!(
        predecessor.lifecycle(operation_height, schedule) == Lifecycle::Active,
        "predecessor is not active at the REFRESH height"
    );
    ensure!(
        schedule.accepts_operation(name_id, operation_height),
        "REFRESH height is outside the name's canonical operation window"
    );
    let target_epoch = schedule
        .epoch(operation_height)
        .map_err(|error| anyhow::anyhow!("derive REFRESH epoch: {error:?}"))?;
    ensure!(
        predecessor.producer_epoch < target_epoch,
        "REFRESH must occur in a later epoch than its predecessor"
    );
    ensure!(
        predecessor_note.value().inner() == BOND_ZATOSHIS,
        "REFRESH predecessor is not exactly the one-ZEC bond"
    );
    let spending_key = derive_name_spending_key(wallet_seed, deployment_id, &name)
        .map_err(|error| anyhow::anyhow!("derive per-name authority: {error:?}"))?;
    let fvk = FullViewingKey::from(&spending_key);
    let predecessor_commitment = FieldElement::from_bytes(
        ExtractedNoteCommitment::from(predecessor_note.commitment()).to_bytes(),
    )
    .map_err(|error| anyhow::anyhow!("derive predecessor commitment: {error:?}"))?;
    let predecessor_future_nf =
        FieldElement::from_bytes(predecessor_note.nullifier(&fvk).to_bytes())
            .map_err(|error| anyhow::anyhow!("derive predecessor nullifier: {error:?}"))?;
    ensure!(
        predecessor_commitment == predecessor.commitment
            && predecessor_future_nf == predecessor.future_nf,
        "reconstructed predecessor note does not match the canonical head"
    );
    let successor_note = derive_refresh_bond_note(
        &spending_key,
        deployment_id,
        predecessor.producer,
        target_epoch,
        &ua,
        designated_action_index,
        predecessor_future_nf,
    )
    .map_err(|error| anyhow::anyhow!("derive recoverable REFRESH bond note: {error:?}"))?;
    let action_commitment = FieldElement::from_bytes(
        ExtractedNoteCommitment::from(successor_note.commitment()).to_bytes(),
    )
    .map_err(|error| anyhow::anyhow!("derive successor commitment: {error:?}"))?;
    let successor_future_nf =
        FieldElement::from_bytes(successor_note.nullifier(&fvk).to_bytes())
            .map_err(|error| anyhow::anyhow!("derive successor nullifier: {error:?}"))?;
    let statement = RefreshStatement {
        deployment_id,
        name_id,
        predecessor_ref: predecessor.producer,
        predecessor_commitment,
        predecessor_future_nf,
        predecessor_epoch: predecessor.producer_epoch,
        inclusion_epoch: target_epoch,
        ua: ua.clone(),
        action_index: designated_action_index,
        action_nullifier: predecessor_future_nf,
        action_commitment,
        successor_future_nf,
    };
    let proof = prover
        .prove_refresh(
            &statement,
            predecessor_note,
            successor_note,
            &spending_key,
            rng,
        )
        .map_err(|error| anyhow::anyhow!("prove REFRESH: {error:?}"))?;
    let publication = prepare_publication(
        Operation::Refresh {
            name,
            predecessor: predecessor.producer,
            ua,
            action_index: designated_action_index,
            successor_future_nf,
            proof,
        },
        deployment,
    )
    .map_err(|error| anyhow::anyhow!("prepare REFRESH publication: {error:?}"))?;
    ensure!(
        publication.carrier_value_zatoshis() == 0,
        "replacement Names carrier value is not zero"
    );
    Ok(PreparedRefresh {
        statement,
        successor_note,
        publication,
        operation_height,
    })
}

#[allow(clippy::too_many_arguments)]
fn replacement_ironwood_plan(
    publication: &PreparedPublication,
    successor_note: Note,
    designated_fvk: FullViewingKey,
    designated_spend: Note,
    funding_spends: Vec<FundingSpend>,
    change_outputs: Vec<ChangeOutput>,
    operation_height: u32,
) -> Result<NamesIronwoodPlan> {
    let (route, designated_action_index) = match (publication.route(), publication.operation()) {
        (
            coppice_names::publication::PublicationRoute::Name(route),
            Operation::Reveal { action_index, .. } | Operation::Refresh { action_index, .. },
        ) => (route, *action_index),
        _ => anyhow::bail!("only name-routed REVEAL/REFRESH has a designated Ironwood plan"),
    };
    let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&route.receiver()))
        .context("derived name route receiver is invalid")?;
    let carrier_outputs = publication
        .frames()
        .iter()
        .map(|memo| CarrierOutput {
            recipient,
            value: NoteValue::from_raw(publication.carrier_value_zatoshis()),
            memo: *memo,
        })
        .collect();
    Ok(NamesIronwoodPlan {
        designated_fvk,
        designated_spend,
        successor_note,
        successor_ovk: None,
        successor_memo: [0; 512],
        carrier_outputs,
        funding_spends,
        change_outputs,
        designated_action_index: usize::try_from(designated_action_index)
            .context("designated action index does not fit usize")?,
        operation_height,
    })
}

/// Returns the per-name FVK needed to manage or reconstruct the successor.
pub fn recover_name_fvk(
    wallet_seed: &[u8],
    deployment: DeploymentParameters,
    name: &Name,
) -> Result<FullViewingKey> {
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow::anyhow!("derive Names deployment ID: {error:?}"))?;
    let spending_key: SpendingKey = derive_name_spending_key(wallet_seed, deployment_id, name)
        .map_err(|error| anyhow::anyhow!("derive per-name authority: {error:?}"))?;
    Ok(FullViewingKey::from(&spending_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{
        ChangeOutput, FundingSpend, NamesIronwoodSigningKey, NamesIronwoodWitness, NamesPcztPlan,
        NamesSigningPlan, NamesWitnessPlan, build_names_bundle, build_names_pczt,
        extract_names_transaction, finalize_names_pczt_io, install_names_ironwood_witnesses,
        prove_names_ironwood_pczt, sign_names_ironwood_pczt,
    };
    use coppice::{
        identity::{CoreRuntimeId, CoreRuntimeParameters, ZcashNetwork},
        replay::{
            CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplay,
            CoreReplayActivationCheckpoint, CoreReplayConfiguration, FullTransactionAcquisition,
            IronwoodFrontier,
        },
    };
    use coppice_names::{
        proof::keygen,
        protocol::Network,
        publication::PublicationRoute,
        reducer::ProofVerifier,
        transport::{NamesTransportStatus, inspect_name_transaction},
    };
    use incrementalmerkletree::{Marking, Position, Retention};
    use orchard::{
        NoteVersion,
        bundle::BundleVersion,
        keys::{Scope, SpendAuthorizingKey},
        note::{RandomSeed, Rho},
        value::NoteValue,
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        local_consensus::LocalNetwork,
    };

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    fn runtime(activation_height: u32) -> coppice::identity::ValidatedCoreRuntimeParameters {
        CoreRuntimeParameters {
            zcash_network_domain: b"coppice-runtime-regtest".to_vec(),
            zcash_network: ZcashNetwork::Regtest,
            runtime_activation_height: activation_height,
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
        .unwrap()
    }

    fn local_v6_params() -> LocalNetwork {
        let one = Some(BlockHeight::from_u32(1));
        let two = Some(BlockHeight::from_u32(2));
        LocalNetwork {
            overwinter: one,
            sapling: one,
            blossom: one,
            heartwood: one,
            canopy: one,
            nu5: two,
            nu6: two,
            nu6_1: two,
            nu6_2: two,
            nu6_3: two,
            #[cfg(zcash_unstable = "nu7")]
            nu7: two,
        }
    }

    #[test]
    fn recoverable_registration_and_refresh_prove_one_hidden_lineage() {
        let (prover, verifier) = keygen();
        let deployment = DeploymentParameters {
            core_runtime_id: CoreRuntimeId::from_bytes([3; 32]),
            activation_height: 100,
            epoch_blocks: 1_152,
            window_blocks: 24,
            commit_maturity_blocks: 24,
            commit_ttl_blocks: 192,
            lease_blocks: 250_000,
            cooldown_blocks: 1_152,
            ruleset_fingerprint: coppice_names::ruleset::ruleset_fingerprint(),
            proof: verifier.identity(),
        };
        let deployment_id = deployment.deployment_id().unwrap();
        let schedule = deployment.schedule(deployment_id);
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        let reveal_height = (100 + 1_152..100 + 2 * 1_152)
            .find(|height| schedule.accepts_operation(name_id, *height))
            .unwrap();
        let commit_height = reveal_height - deployment.commit_maturity_blocks;
        let seed = [7; 64];
        let commit = prepare_commit(&seed, deployment, &name, reveal_height).unwrap();
        assert_eq!(
            commit.target_epoch(),
            schedule.epoch(reveal_height).unwrap()
        );
        assert_eq!(commit.publication().route(), PublicationRoute::Generic);
        let commitment = match commit.publication().operation() {
            Operation::Commit { commitment } => *commitment,
            _ => panic!("COMMIT preparation returned another operation"),
        };

        let registration_key = SpendingKey::from_bytes([21; 32]).unwrap();
        let registration_fvk = FullViewingKey::from(&registration_key);
        let rho = Rho::from_bytes(&[9; 32]).unwrap();
        let registration_note = Note::from_parts(
            registration_fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(BOND_ZATOSHIS),
            rho,
            RandomSeed::from_bytes([4; 32], &rho).unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let ua = CanonicalUa::parse(Network::Regtest, UA).unwrap();
        let reveal = prepare_reveal(
            RevealInputs {
                wallet_seed: &seed,
                deployment,
                name: name.clone(),
                commit_ref: CommitRef {
                    height: commit_height,
                    tx_index: 2,
                    txid: [4; 32],
                },
                ua: ua.clone(),
                operation_height: reveal_height,
                designated_action_index: 0,
                registration_fvk: &registration_fvk,
                registration_note,
            },
            &prover,
            ChaCha20Rng::from_seed([44; 32]),
        )
        .unwrap();
        assert_eq!(reveal.statement().commitment, commitment);
        assert!(verifier.verify_reveal(
            reveal.statement(),
            match reveal.publication().operation() {
                Operation::Reveal { proof, .. } => proof,
                _ => panic!("REVEAL preparation returned another operation"),
            }
        ));
        assert_eq!(
            reveal.publication().route(),
            PublicationRoute::Name(
                coppice_names::protocol::NameRoute::derive(deployment_id, name_id).unwrap()
            )
        );
        assert_eq!(reveal.publication().frames().len(), 11);
        assert_eq!(reveal.publication().carrier_value_zatoshis(), 0);
        assert_eq!(reveal.successor_note().value().inner(), BOND_ZATOSHIS);
        assert_eq!(
            reveal.successor_note().rho().to_bytes(),
            registration_note.nullifier(&registration_fvk).to_bytes()
        );
        let reveal_plan = reveal
            .ironwood_plan(registration_fvk.clone(), registration_note, vec![], vec![])
            .unwrap();
        assert!(
            reveal_plan
                .carrier_outputs
                .iter()
                .all(|carrier| carrier.value.inner() == 0)
        );
        let reveal_bundle =
            build_names_bundle(reveal_plan, ChaCha20Rng::from_seed([46; 32])).unwrap();
        assert_eq!(
            reveal_bundle.designated_nullifier,
            reveal.statement().action_nullifier.to_bytes()
        );
        assert_eq!(
            reveal_bundle.designated_commitment,
            reveal.statement().action_commitment.to_bytes()
        );

        let refresh_height = (100 + 2 * 1_152..100 + 3 * 1_152)
            .find(|height| schedule.accepts_operation(name_id, *height))
            .unwrap();
        let predecessor = Head {
            name: name.clone(),
            ua: ua.clone(),
            producer: coppice_names::protocol::StateRef {
                height: reveal_height,
                tx_index: 7,
                txid: [5; 32],
                action_index: 0,
            },
            commitment: reveal.statement().action_commitment,
            future_nf: reveal.statement().successor_future_nf,
            producer_epoch: reveal.statement().inclusion_epoch,
            expiry_height: schedule.expiry(reveal_height).unwrap(),
            terminal_height: None,
        };
        let refresh = prepare_refresh(
            RefreshInputs {
                wallet_seed: &seed,
                deployment,
                name: name.clone(),
                predecessor: predecessor.clone(),
                predecessor_note: *reveal.successor_note(),
                ua,
                operation_height: refresh_height,
                designated_action_index: 1,
            },
            &prover,
            ChaCha20Rng::from_seed([45; 32]),
        )
        .unwrap();
        assert_eq!(refresh.statement().predecessor_ref, predecessor.producer);
        assert_eq!(
            refresh.successor_note().rho().to_bytes(),
            predecessor.future_nf.to_bytes()
        );
        assert!(verifier.verify_refresh(
            refresh.statement(),
            match refresh.publication().operation() {
                Operation::Refresh { proof, .. } => proof,
                _ => panic!("REFRESH preparation returned another operation"),
            }
        ));
        assert_eq!(refresh.publication().frames().len(), 11);
        assert_eq!(
            refresh.publication().route(),
            PublicationRoute::Name(
                coppice_names::protocol::NameRoute::derive(deployment_id, name_id).unwrap()
            )
        );
        let name_fvk = recover_name_fvk(&seed, deployment, &name).unwrap();
        let refresh_plan = refresh
            .ironwood_plan(name_fvk, *reveal.successor_note(), vec![], vec![])
            .unwrap();
        assert!(
            refresh_plan
                .carrier_outputs
                .iter()
                .all(|carrier| carrier.value.inner() == 0)
        );
        let refresh_bundle =
            build_names_bundle(refresh_plan, ChaCha20Rng::from_seed([47; 32])).unwrap();
        assert_eq!(
            refresh_bundle.designated_nullifier,
            refresh.statement().action_nullifier.to_bytes()
        );
        assert_eq!(
            refresh_bundle.designated_commitment,
            refresh.statement().action_commitment.to_bytes()
        );
    }

    #[test]
    #[ignore = "generates replacement and Ironwood consensus proofs"]
    fn replacement_reveal_round_trips_through_authenticated_core_transport() {
        type TestTree = ShardTree<MemoryShardStore<orchard::tree::MerkleHashOrchard, u32>, 32, 4>;

        let runtime = runtime(100);
        let (prover, verifier) = keygen();
        let deployment = DeploymentParameters {
            core_runtime_id: runtime.core_runtime_id(),
            activation_height: 100,
            epoch_blocks: 1_152,
            window_blocks: 24,
            commit_maturity_blocks: 24,
            commit_ttl_blocks: 192,
            lease_blocks: 250_000,
            cooldown_blocks: 1_152,
            ruleset_fingerprint: coppice_names::ruleset::ruleset_fingerprint(),
            proof: verifier.identity(),
        };
        let deployment_id = deployment.deployment_id().unwrap();
        let schedule = deployment.schedule(deployment_id);
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        let reveal_height = (100 + 1_152..100 + 2 * 1_152)
            .find(|height| schedule.accepts_operation(name_id, *height))
            .unwrap();
        let commit_height = reveal_height - deployment.commit_maturity_blocks;
        let wallet_seed = [7; 64];
        let commit = prepare_commit(&wallet_seed, deployment, &name, reveal_height).unwrap();
        let commitment = match commit.publication().operation() {
            Operation::Commit { commitment } => *commitment,
            _ => unreachable!(),
        };

        let registration_key = SpendingKey::from_bytes([21; 32]).unwrap();
        let registration_ask = SpendAuthorizingKey::from(&registration_key);
        let registration_fvk = FullViewingKey::from(&registration_key);
        let registration_rho = Rho::from_bytes(&[9; 32]).unwrap();
        let registration_note = Note::from_parts(
            registration_fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(BOND_ZATOSHIS),
            registration_rho,
            RandomSeed::from_bytes([4; 32], &registration_rho).unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let registration_commitment = ExtractedNoteCommitment::from(registration_note.commitment());
        let registration_nullifier = registration_note.nullifier(&registration_fvk).to_bytes();
        let reveal = prepare_reveal(
            RevealInputs {
                wallet_seed: &wallet_seed,
                deployment,
                name: name.clone(),
                commit_ref: CommitRef {
                    height: commit_height,
                    tx_index: 2,
                    txid: [4; 32],
                },
                ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
                operation_height: reveal_height,
                designated_action_index: 0,
                registration_fvk: &registration_fvk,
                registration_note,
            },
            &prover,
            ChaCha20Rng::from_seed([44; 32]),
        )
        .unwrap();
        assert_eq!(reveal.statement().commitment, commitment);

        let funding_key = SpendingKey::from_bytes([22; 32]).unwrap();
        let funding_ask = SpendAuthorizingKey::from(&funding_key);
        let funding_fvk = FullViewingKey::from(&funding_key);
        let funding_rho = Rho::from_bytes(&[10; 32]).unwrap();
        let funding_note = Note::from_parts(
            funding_fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(100_000),
            funding_rho,
            RandomSeed::from_bytes([5; 32], &funding_rho).unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let funding_commitment = ExtractedNoteCommitment::from(funding_note.commitment());
        let funding_nullifier = funding_note.nullifier(&funding_fvk).to_bytes();
        let plan = reveal
            .ironwood_plan(
                registration_fvk,
                registration_note,
                vec![FundingSpend {
                    fvk: funding_fvk.clone(),
                    note: funding_note,
                }],
                vec![ChangeOutput {
                    fvk: funding_fvk.clone(),
                    ovk: None,
                    recipient: funding_fvk.address_at(0u32, Scope::Internal),
                    value: NoteValue::from_raw(35_000),
                    memo: [0; 512],
                }],
            )
            .unwrap();
        let built = build_names_bundle(plan, ChaCha20Rng::from_seed([46; 32])).unwrap();
        assert_eq!(built.action_count, 13);
        assert_eq!(built.ironwood_value_balance, 65_000);
        assert_eq!(
            built.designated_nullifier,
            reveal.statement().action_nullifier.to_bytes()
        );
        assert_eq!(
            built.designated_commitment,
            reveal.statement().action_commitment.to_bytes()
        );

        let mut tree = TestTree::new(MemoryShardStore::empty(), 4);
        tree.append(
            orchard::tree::MerkleHashOrchard::from_cmx(&registration_commitment),
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        tree.append(
            orchard::tree::MerkleHashOrchard::from_cmx(&funding_commitment),
            Retention::Checkpoint {
                id: 1,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let anchor: orchard::Anchor = tree.root_at_checkpoint_id(&1).unwrap().unwrap().into();
        let registration_path: orchard::tree::MerklePath = tree
            .witness_at_checkpoint_id(Position::from(0), &1)
            .unwrap()
            .unwrap()
            .into();
        let funding_path: orchard::tree::MerklePath = tree
            .witness_at_checkpoint_id(Position::from(1), &1)
            .unwrap()
            .unwrap()
            .into();

        let pczt = build_names_pczt(NamesPcztPlan {
            ironwood: built,
            params: local_v6_params(),
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(reveal_height),
            fallback_lock_time: 0,
        })
        .unwrap();
        let finalized = finalize_names_pczt_io(pczt).unwrap();
        let witnessed = install_names_ironwood_witnesses(
            finalized,
            NamesWitnessPlan {
                anchor,
                spends: vec![
                    NamesIronwoodWitness {
                        nullifier: funding_nullifier,
                        merkle_path: funding_path,
                    },
                    NamesIronwoodWitness {
                        nullifier: registration_nullifier,
                        merkle_path: registration_path,
                    },
                ],
            },
        )
        .unwrap();
        let proving_key =
            orchard::circuit::ProvingKey::build(BundleVersion::ironwood_v3().circuit_version());
        let proved = prove_names_ironwood_pczt(witnessed, &proving_key).unwrap();
        let signed = sign_names_ironwood_pczt(
            proved,
            NamesSigningPlan {
                spends: vec![
                    NamesIronwoodSigningKey {
                        nullifier: registration_nullifier,
                        ask: registration_ask,
                    },
                    NamesIronwoodSigningKey {
                        nullifier: funding_nullifier,
                        ask: funding_ask,
                    },
                ],
            },
        )
        .unwrap();
        let extracted = extract_names_transaction(signed).unwrap();
        assert_eq!(extracted.action_count, 13);
        assert_eq!(extracted.ironwood_value_balance, 65_000);
        assert_eq!(extracted.designated_action_index, 0);

        let ironwood = extracted.transaction.ironwood_bundle().unwrap();
        let nullifiers = ironwood
            .actions()
            .iter()
            .map(|action| action.nullifier().to_bytes())
            .collect::<Vec<_>>();
        let commitments = ironwood
            .actions()
            .iter()
            .map(|action| action.cmx().to_bytes())
            .collect::<Vec<_>>();
        let mut transaction_bytes = Vec::new();
        extracted.transaction.write(&mut transaction_bytes).unwrap();
        let mut replay = CoreReplay::new(
            CoreReplayConfiguration::new(reveal_height, 20).unwrap(),
            CoreReplayActivationCheckpoint {
                height: reveal_height - 1,
                block_hash: [8; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap();
        let core_block = replay
            .apply_block(&CoreCanonicalBlockInput {
                height: reveal_height,
                block_hash: [9; 32],
                prev_block_hash: [8; 32],
                branch_id: BranchId::Nu6_3,
                transactions: vec![CoreCanonicalTransactionInput {
                    tx_index: 7,
                    txid: *extracted.txid.as_ref(),
                    ironwood_nullifiers: nullifiers,
                    ironwood_commitments: commitments,
                    full_transaction_acquisition: FullTransactionAcquisition::ExtendedEffects,
                    full_transaction: Some(transaction_bytes),
                }],
            })
            .unwrap();
        let decoded = inspect_name_transaction(
            &core_block.transactions()[0],
            &runtime,
            deployment,
            Network::Regtest,
            &name,
        )
        .unwrap();
        assert_eq!(
            decoded,
            NamesTransportStatus::Operation(reveal.publication().operation().clone())
        );
    }
}
