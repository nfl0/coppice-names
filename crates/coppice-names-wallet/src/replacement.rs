//! Wallet-side construction for the replacement Names protocol.

use anyhow::{Result, ensure};
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
    keys::{FullViewingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note},
};
use rand_core::Rng;

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
}

/// Proven REFRESH publication and its exact successor opening. UPDATE and
/// RENEW are the same protocol operation: the supplied UA may change or stay
/// equal, and every accepted REFRESH starts a fresh lease.
pub struct PreparedRefresh {
    statement: RefreshStatement,
    successor_note: Note,
    publication: PreparedPublication,
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
    use coppice::identity::CoreRuntimeId;
    use coppice_names::{
        proof::keygen, protocol::Network, publication::PublicationRoute, reducer::ProofVerifier,
    };
    use orchard::{
        NoteVersion,
        keys::Scope,
        note::{RandomSeed, Rho},
        value::NoteValue,
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

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
    }
}
