//! Exact arbitrary-name replay without validating unrelated Names lineages.

use crate::{
    codec::Operation,
    protocol::{Name, NameId},
    reducer::{Accepted, ApplyError, Block, ProofVerifier, Reducer, Resolution},
    schedule::Parameters,
};

/// Name-only replay with the same acceptance rules as the full reducer.
///
/// Every authenticated Ironwood action remains visible because an otherwise
/// unrelated transaction can spend the requested name's current bond. Generic
/// COMMITs remain until their bounded TTL because a later requested-name
/// REVEAL can reference them. Proof-valid operations for other `NameId`s are
/// discarded before proof verification and state construction.
pub struct ExactResolver<V> {
    name: Name,
    name_id: NameId,
    reducer: Reducer<V>,
}

impl<V: ProofVerifier> ExactResolver<V> {
    /// Starts exact replay at the deployment activation parent.
    pub fn new(
        parameters: Parameters,
        activation_parent_hash: [u8; 32],
        name: Name,
        verifier: V,
    ) -> Result<Self, ApplyError> {
        let name_id = name.id().map_err(|_| ApplyError::InvalidParameters)?;
        Ok(Self {
            name,
            name_id,
            reducer: Reducer::new(parameters, activation_parent_hash, verifier)?,
        })
    }

    /// Applies one authenticated canonical block after removing unrelated
    /// application payloads but retaining every action effect.
    pub fn apply_block(&mut self, block: &Block) -> Result<Vec<Accepted>, ApplyError> {
        let mut filtered = block.clone();
        for transaction in &mut filtered.transactions {
            let relevant = match transaction.operation.as_ref() {
                Some(Operation::Commit { .. }) => true,
                Some(Operation::Reveal { name, .. } | Operation::Refresh { name, .. }) => {
                    name.id() == Ok(self.name_id)
                }
                None => false,
            };
            if !relevant {
                transaction.operation = None;
            }
        }
        self.reducer.apply_block(&filtered)
    }

    /// Resolves at an applied canonical height.
    pub fn resolve(&self, height: u32) -> Resolution {
        self.reducer.resolve(&self.name, height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::Operation,
        protocol::{CanonicalUa, CommitRef, Commitment, FieldElement, Network},
        reducer::{Action, Lifecycle, Transaction},
        statement::{RefreshStatement, RevealStatement},
    };
    use pasta_curves::{group::ff::PrimeField, pallas};

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    struct AcceptProofs;

    impl ProofVerifier for AcceptProofs {
        fn verify_reveal(&self, _: &RevealStatement, proof: &[u8]) -> bool {
            proof == [1]
        }

        fn verify_refresh(&self, _: &RefreshStatement, proof: &[u8]) -> bool {
            proof == [1]
        }
    }

    fn field(value: u64) -> FieldElement {
        FieldElement::from_bytes(pallas::Base::from(value).to_repr()).unwrap()
    }

    fn hash(height: u32) -> [u8; 32] {
        let mut value = [0; 32];
        value[..4].copy_from_slice(&(height + 1).to_be_bytes());
        value
    }

    #[test]
    fn unrelated_bulletin_is_not_verified_but_its_spend_terminates_target() {
        let parameters = Parameters {
            deployment_id: [7; 32],
            activation_height: 0,
            epoch_blocks: 20,
            window_blocks: 4,
            commit_maturity_blocks: 4,
            commit_ttl_blocks: 10,
            lease_blocks: 50,
            cooldown_blocks: 20,
        };
        let name = Name::parse("alice").unwrap();
        let reveal_height = (4..40)
            .find(|height| parameters.accepts_operation(name.id().unwrap(), *height))
            .unwrap();
        let commit_height = reveal_height - parameters.commit_maturity_blocks;
        let commit_ref = CommitRef {
            height: commit_height,
            tx_index: 0,
            txid: [10; 32],
        };
        let commitment = Commitment::from_bytes(pallas::Base::from(1).to_repr()).unwrap();
        let ua = CanonicalUa::parse(Network::Regtest, UA).unwrap();
        let reveal = Operation::Reveal {
            name: name.clone(),
            commit: commit_ref,
            ua: ua.clone(),
            action_index: 0,
            successor_future_nf: field(4),
            proof: vec![1],
        };
        let unrelated = Operation::Reveal {
            name: Name::parse("bob").unwrap(),
            commit: commit_ref,
            ua,
            action_index: 0,
            successor_future_nf: field(8),
            proof: vec![0],
        };
        let spend_height = reveal_height + 1;
        let mut resolver = ExactResolver::new(parameters, [0; 32], name, AcceptProofs).unwrap();
        let mut previous_hash = [0; 32];
        for height in 0..=spend_height {
            let transaction = if height == commit_height {
                Some(Transaction {
                    tx_index: 0,
                    txid: commit_ref.txid,
                    actions: vec![],
                    operation: Some(Operation::Commit { commitment }),
                })
            } else if height == reveal_height {
                Some(Transaction {
                    tx_index: 0,
                    txid: [20; 32],
                    actions: vec![Action {
                        action_index: 0,
                        nullifier: field(2),
                        commitment: field(3),
                    }],
                    operation: Some(reveal.clone()),
                })
            } else if height == spend_height {
                Some(Transaction {
                    tx_index: 0,
                    txid: [30; 32],
                    actions: vec![Action {
                        action_index: 0,
                        nullifier: field(4),
                        commitment: field(7),
                    }],
                    operation: Some(unrelated.clone()),
                })
            } else {
                None
            };
            let block_hash = hash(height);
            resolver
                .apply_block(&Block {
                    height,
                    hash: block_hash,
                    prev_hash: previous_hash,
                    transactions: transaction.into_iter().collect(),
                })
                .unwrap();
            previous_hash = block_hash;
        }
        assert_eq!(
            resolver.resolve(spend_height).lifecycle,
            Lifecycle::Cooldown
        );
    }
}
