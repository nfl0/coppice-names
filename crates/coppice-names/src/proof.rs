//! Orchard prover and verifier adapters for the replacement Names relations.

use crate::{
    protocol::FieldElement,
    reducer::ProofVerifier,
    statement::{RefreshStatement, RevealStatement},
};
use orchard::{
    Note,
    circuit::state_note_binding::v2::{
        self as orchard_names, RefreshStatementFields, RefreshWitness, RevealStatementFields,
        RevealWitness, StatementDigest, TranscriptField,
    },
    keys::SpendingKey,
};
use pasta_curves::{group::ff::PrimeField, pallas};
use rand_core::Rng;

/// Errors constructing or proving a Names relation.
#[derive(Debug)]
pub enum ProofError {
    InvalidSecret,
    InvalidStatement,
    Proving,
}

/// Wallet-facing proving-key adapter.
#[derive(Debug)]
pub struct OrchardProofProver {
    keys: orchard_names::ProvingKeys,
}

/// Replay-facing verifying-key adapter.
#[derive(Debug)]
pub struct OrchardProofVerifier {
    keys: orchard_names::VerifyingKeys,
}

/// Generates the paired prover and verifier for one deployment.
pub fn keygen() -> (OrchardProofProver, OrchardProofVerifier) {
    let (proving, verifying) = orchard_names::keygen();
    (
        OrchardProofProver { keys: proving },
        OrchardProofVerifier { keys: verifying },
    )
}

impl OrchardProofProver {
    /// Proves a REVEAL-created bond note and hidden COMMIT opening.
    pub fn prove_reveal<R: Rng>(
        &self,
        statement: &RevealStatement,
        successor: Note,
        spending_key: &SpendingKey,
        secret: FieldElement,
        rng: R,
    ) -> Result<Vec<u8>, ProofError> {
        let secret = orchard_names::CommitSecret::from_bytes(secret.to_bytes())
            .ok_or(ProofError::InvalidSecret)?;
        let digest = digest(statement.digest())?;
        let witness = RevealWitness::new(
            successor,
            spending_key,
            secret,
            RevealStatementFields::new(transcript(statement.fields())),
        );
        orchard_names::prove_reveal(&self.keys, witness, digest, rng)
            .map_err(|_| ProofError::Proving)
    }

    /// Proves one exact-value bond refresh under unchanged hidden authority.
    pub fn prove_refresh<R: Rng>(
        &self,
        statement: &RefreshStatement,
        predecessor: Note,
        successor: Note,
        spending_key: &SpendingKey,
        rng: R,
    ) -> Result<Vec<u8>, ProofError> {
        let digest = digest(statement.digest())?;
        let witness = RefreshWitness::new(
            predecessor,
            successor,
            spending_key,
            RefreshStatementFields::new(transcript(statement.fields())),
        );
        orchard_names::prove_refresh(&self.keys, witness, digest, rng)
            .map_err(|_| ProofError::Proving)
    }
}

impl ProofVerifier for OrchardProofVerifier {
    fn verify_reveal(&self, statement: &RevealStatement, proof: &[u8]) -> bool {
        digest(statement.digest())
            .is_ok_and(|digest| orchard_names::verify_reveal(&self.keys, proof, digest))
    }

    fn verify_refresh(&self, statement: &RefreshStatement, proof: &[u8]) -> bool {
        digest(statement.digest())
            .is_ok_and(|digest| orchard_names::verify_refresh(&self.keys, proof, digest))
    }
}

fn digest(bytes: [u8; 32]) -> Result<StatementDigest, ProofError> {
    StatementDigest::from_bytes(bytes).ok_or(ProofError::InvalidStatement)
}

fn transcript<const N: usize>(fields: [pallas::Base; N]) -> [TranscriptField; N] {
    fields.map(|field| {
        TranscriptField::from_bytes(field.to_repr())
            .expect("native statement fields are canonical Pallas elements")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{CodecParameters, Operation, decode, encode},
        protocol::{CanonicalUa, CommitRef, Commitment, Name, Network},
        reducer::{Action, Block, Lifecycle, Reducer, Transaction},
        schedule::Parameters,
        statement::registration_commitment,
    };
    use orchard::{
        NoteVersion,
        circuit::state_note_binding::v2::owner_commitment,
        keys::{FullViewingKey, Scope},
        note::{ExtractedNoteCommitment, RandomSeed, Rho},
        value::NoteValue,
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    #[test]
    fn real_reveal_proof_verifies_through_reducer_adapter() {
        let spending_key = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&spending_key);
        let rho = Rho::from_bytes(&[9; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([4; 32], &rho).unwrap();
        let successor = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(crate::protocol::BOND_ZATOSHIS),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let deployment_id = [1; 32];
        let name_id = Name::parse("alice").unwrap().id().unwrap();
        let owner = FieldElement::from_bytes(owner_commitment(&spending_key).to_bytes()).unwrap();
        let secret = FieldElement::from_bytes(pallas::Base::from(77).to_repr()).unwrap();
        let commitment = Commitment::from_bytes(registration_commitment(
            deployment_id,
            name_id,
            18,
            owner,
            secret,
        ))
        .unwrap();
        let statement = RevealStatement {
            deployment_id,
            name_id,
            inclusion_epoch: 18,
            commitment,
            commit_ref: CommitRef {
                height: 10,
                tx_index: 0,
                txid: [2; 32],
            },
            ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
            action_index: 0,
            action_nullifier: FieldElement::from_bytes(successor.rho().to_bytes()).unwrap(),
            action_commitment: FieldElement::from_bytes(
                ExtractedNoteCommitment::from(successor.commitment()).to_bytes(),
            )
            .unwrap(),
            successor_future_nf: FieldElement::from_bytes(successor.nullifier(&fvk).to_bytes())
                .unwrap(),
        };
        let (prover, verifier) = keygen();
        let proof = prover
            .prove_reveal(
                &statement,
                successor,
                &spending_key,
                secret,
                ChaCha20Rng::from_seed([44; 32]),
            )
            .unwrap();
        assert_eq!(proof.len(), orchard_names::REVEAL_PROOF_BYTES);
        assert!(verifier.verify_reveal(&statement, &proof));

        let mut wrong_statement = statement;
        wrong_statement.action_index = 1;
        assert!(!verifier.verify_reveal(&wrong_statement, &proof));
    }

    #[test]
    fn real_refresh_proof_verifies_through_reducer_adapter() {
        let spending_key = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&spending_key);
        let predecessor_rho = Rho::from_bytes(&[1; 32]).unwrap();
        let predecessor = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(crate::protocol::BOND_ZATOSHIS),
            predecessor_rho,
            RandomSeed::from_bytes([2; 32], &predecessor_rho).unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let successor_rho = Rho::from_bytes(&predecessor.nullifier(&fvk).to_bytes()).unwrap();
        let successor = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(crate::protocol::BOND_ZATOSHIS),
            successor_rho,
            RandomSeed::from_bytes([4; 32], &successor_rho).unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let predecessor_nf =
            FieldElement::from_bytes(predecessor.nullifier(&fvk).to_bytes()).unwrap();
        let statement = RefreshStatement {
            deployment_id: [1; 32],
            name_id: Name::parse("alice").unwrap().id().unwrap(),
            predecessor_ref: crate::protocol::StateRef {
                height: 100,
                tx_index: 0,
                txid: [2; 32],
                action_index: 0,
            },
            predecessor_commitment: FieldElement::from_bytes(
                ExtractedNoteCommitment::from(predecessor.commitment()).to_bytes(),
            )
            .unwrap(),
            predecessor_future_nf: predecessor_nf,
            predecessor_epoch: 17,
            inclusion_epoch: 18,
            ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
            action_index: 0,
            action_nullifier: predecessor_nf,
            action_commitment: FieldElement::from_bytes(
                ExtractedNoteCommitment::from(successor.commitment()).to_bytes(),
            )
            .unwrap(),
            successor_future_nf: FieldElement::from_bytes(successor.nullifier(&fvk).to_bytes())
                .unwrap(),
        };
        let (prover, verifier) = keygen();
        let proof = prover
            .prove_refresh(
                &statement,
                predecessor,
                successor,
                &spending_key,
                ChaCha20Rng::from_seed([43; 32]),
            )
            .unwrap();
        assert_eq!(proof.len(), orchard_names::REFRESH_PROOF_BYTES);
        assert!(verifier.verify_refresh(&statement, &proof));

        let mut wrong_statement = statement;
        wrong_statement.inclusion_epoch += 1;
        assert!(!verifier.verify_refresh(&wrong_statement, &proof));
    }

    #[test]
    fn canonical_commit_reveal_fixture_resolves_through_real_proof() {
        let spending_key = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&spending_key);
        let name = Name::parse("alice").unwrap();
        let name_id = name.id().unwrap();
        let parameters = Parameters {
            deployment_id: [1; 32],
            activation_height: 0,
            epoch_blocks: 20,
            window_blocks: 4,
            commit_maturity_blocks: 4,
            commit_ttl_blocks: 10,
            lease_blocks: 50,
            cooldown_blocks: 20,
        };
        let initial_window = (0..20)
            .find(|height| parameters.accepts_operation(name_id, *height))
            .unwrap();
        let reveal_height = if initial_window < parameters.commit_maturity_blocks {
            initial_window + parameters.epoch_blocks
        } else {
            initial_window
        };
        let commit_height = reveal_height - parameters.commit_maturity_blocks;
        let commit_ref = CommitRef {
            height: commit_height,
            tx_index: 0,
            txid: [10; 32],
        };
        let owner = FieldElement::from_bytes(owner_commitment(&spending_key).to_bytes()).unwrap();
        let secret = FieldElement::from_bytes(pallas::Base::from(77).to_repr()).unwrap();
        let commitment = Commitment::from_bytes(registration_commitment(
            parameters.deployment_id,
            name_id,
            parameters.epoch(reveal_height).unwrap(),
            owner,
            secret,
        ))
        .unwrap();
        let rho = Rho::from_bytes(&[9; 32]).unwrap();
        let successor = Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(crate::protocol::BOND_ZATOSHIS),
            rho,
            RandomSeed::from_bytes([4; 32], &rho).unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let action = Action {
            action_index: 0,
            nullifier: FieldElement::from_bytes(successor.rho().to_bytes()).unwrap(),
            commitment: FieldElement::from_bytes(
                ExtractedNoteCommitment::from(successor.commitment()).to_bytes(),
            )
            .unwrap(),
        };
        let successor_future_nf =
            FieldElement::from_bytes(successor.nullifier(&fvk).to_bytes()).unwrap();
        let statement = RevealStatement {
            deployment_id: parameters.deployment_id,
            name_id,
            inclusion_epoch: parameters.epoch(reveal_height).unwrap(),
            commitment,
            commit_ref,
            ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
            action_index: action.action_index,
            action_nullifier: action.nullifier,
            action_commitment: action.commitment,
            successor_future_nf,
        };
        let (prover, verifier) = keygen();
        let proof = prover
            .prove_reveal(
                &statement,
                successor,
                &spending_key,
                secret,
                ChaCha20Rng::from_seed([45; 32]),
            )
            .unwrap();
        let codec = CodecParameters {
            reveal_proof_bytes: orchard_names::REVEAL_PROOF_BYTES,
            refresh_proof_bytes: orchard_names::REFRESH_PROOF_BYTES,
        };
        let commit_operation = Operation::Commit { commitment };
        assert_eq!(
            decode(
                &encode(&commit_operation, codec).unwrap(),
                Network::Regtest,
                codec
            ),
            Ok(commit_operation.clone())
        );
        let reveal_operation = Operation::Reveal {
            name: name.clone(),
            commit: commit_ref,
            ua: statement.ua.clone(),
            action_index: action.action_index,
            successor_future_nf,
            proof,
        };
        assert_eq!(
            decode(
                &encode(&reveal_operation, codec).unwrap(),
                Network::Regtest,
                codec
            ),
            Ok(reveal_operation.clone())
        );

        let mut reducer = Reducer::new(parameters, [0; 32], verifier).unwrap();
        for height in 0..=reveal_height {
            let operation = if height == commit_height {
                Some(commit_operation.clone())
            } else if height == reveal_height {
                Some(reveal_operation.clone())
            } else {
                None
            };
            let transactions = operation
                .map(|operation| Transaction {
                    tx_index: 0,
                    txid: if height == commit_height {
                        commit_ref.txid
                    } else {
                        [20; 32]
                    },
                    actions: if height == reveal_height {
                        vec![action]
                    } else {
                        vec![]
                    },
                    operation: Some(operation),
                })
                .into_iter()
                .collect();
            reducer
                .apply_block(&Block {
                    height,
                    hash: [u8::try_from(height + 1).unwrap(); 32],
                    prev_hash: [u8::try_from(height).unwrap(); 32],
                    transactions,
                })
                .unwrap();
        }
        let resolution = reducer.resolve(&name, reveal_height);
        assert_eq!(resolution.lifecycle, Lifecycle::Active);
        assert_eq!(resolution.ua, Some(statement.ua));
        assert_eq!(resolution.head.unwrap().producer.txid, [20; 32]);
    }
}
