//! Exact arbitrary-name replay without validating unrelated Names lineages.

use crate::{
    codec::Operation,
    protocol::{Name, NameId, Network},
    reducer::{
        Accepted, ApplyError, Block, BlockOutcome, FinalizationError, ProofVerifier,
        ProtocolIdentity, Reducer, ReducerTip, ReferencedCommit, Resolution, ResolutionError,
        RollbackError, RollbackRange, SnapshotError,
    },
    ruleset::ruleset_fingerprint,
    schedule::Parameters,
};
use serde::{Deserialize, Serialize};

const EXACT_RESOLVER_SNAPSHOT_FORMAT_VERSION: u32 = 3;

#[derive(Serialize, Deserialize)]
struct StoredExactResolver {
    format_version: u32,
    deployment_id: [u8; 32],
    ruleset_fingerprint: [u8; 32],
    rollback_range: Option<RollbackRange>,
    name: String,
    reducer: Vec<u8>,
}

/// Name-only replay with the same acceptance rules as the full reducer.
///
/// Every authenticated Ironwood action remains visible because an otherwise
/// unrelated transaction can spend the requested name's current bond. Generic
/// COMMITs remain until their bounded TTL because a later requested-name
/// REVEAL can reference them. Proof-valid operations for other `NameId`s are
/// discarded before proof verification and state construction.
#[derive(Clone)]
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
        self.apply_block_with_referenced_commits(block, &[])
    }

    /// Applies exact-name state with bounded historical COMMIT evidence fetched
    /// only after a candidate REVEAL identifies its canonical reference.
    pub fn apply_block_with_referenced_commits(
        &mut self,
        block: &Block,
        referenced_commits: &[ReferencedCommit],
    ) -> Result<Vec<Accepted>, ApplyError> {
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
        self.reducer
            .apply_block_with_referenced_commits(&filtered, referenced_commits)
    }

    /// Applies exact-name state and exposes normative lifecycle transitions for
    /// cross-client trace qualification.
    pub fn apply_block_detailed(
        &mut self,
        block: &Block,
        referenced_commits: &[ReferencedCommit],
    ) -> Result<BlockOutcome, ApplyError> {
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
        self.reducer
            .apply_block_detailed(&filtered, referenced_commits)
    }

    /// Resolves at an applied canonical height.
    pub fn resolve(&self, height: u32) -> Result<Resolution, ResolutionError> {
        self.reducer.resolve_authenticated(&self.name, height)
    }

    pub fn tip(&self) -> Option<ReducerTip> {
        self.reducer.tip()
    }

    pub fn protocol_identity(&self) -> ProtocolIdentity {
        self.reducer.protocol_identity()
    }

    pub fn pending_commit(
        &self,
        reference: &crate::protocol::CommitRef,
    ) -> Option<crate::protocol::Commitment> {
        self.reducer.pending_commit(reference)
    }

    /// Reverts exactly the current canonical tip. Wallet hosts use this to
    /// abort a speculative pre-scan application when their wallet database
    /// rejects the corresponding block.
    pub fn rollback_tip(&mut self, expected_hash: [u8; 32]) -> Result<(), RollbackError> {
        self.reducer.rollback_tip(expected_hash)
    }

    /// Drops rollback journals only through a height the host has independently
    /// finalized. This does not invent a Names finality rule.
    pub fn finalize_through(&mut self, height: u32) -> Result<(), FinalizationError> {
        self.reducer.finalize_through(height)
    }

    /// Serializes this name's derived state and rollback journals. The host is
    /// responsible for integrity protection because Ironwood does not commit
    /// to Names application state.
    pub fn save_snapshot(&self) -> Result<Vec<u8>, SnapshotError> {
        let stored = StoredExactResolver {
            format_version: EXACT_RESOLVER_SNAPSHOT_FORMAT_VERSION,
            deployment_id: self.reducer.protocol_identity().deployment_id,
            ruleset_fingerprint: ruleset_fingerprint(),
            rollback_range: self.reducer.rollback_range(),
            name: self.name.as_str().to_owned(),
            reducer: self.reducer.save_snapshot()?,
        };
        serde_json::to_vec(&stored).map_err(|_| SnapshotError::Encoding)
    }

    /// Restores one structurally validated exact-name resolver. `name`,
    /// `parameters`, and `network` are supplied independently by the host and
    /// must agree with the snapshot.
    pub fn load_snapshot(
        parameters: Parameters,
        network: Network,
        name: Name,
        verifier: V,
        bytes: &[u8],
    ) -> Result<Self, SnapshotError> {
        let stored: StoredExactResolver =
            serde_json::from_slice(bytes).map_err(|_| SnapshotError::Encoding)?;
        if stored.format_version != EXACT_RESOLVER_SNAPSHOT_FORMAT_VERSION {
            return Err(SnapshotError::UnsupportedFormat);
        }
        if stored.name != name.as_str() {
            return Err(SnapshotError::NameMismatch);
        }
        if stored.deployment_id != parameters.deployment_id
            || stored.ruleset_fingerprint != ruleset_fingerprint()
        {
            return Err(SnapshotError::ParametersMismatch);
        }
        let name_id = name.id().map_err(|_| SnapshotError::NameMismatch)?;
        let reducer = Reducer::load_snapshot(parameters, network, verifier, &stored.reducer)?;
        if !reducer.is_exact_for(name_id) {
            return Err(SnapshotError::NameMismatch);
        }
        if reducer.rollback_range() != stored.rollback_range {
            return Err(SnapshotError::InvalidHistory);
        }
        Ok(Self {
            name,
            name_id,
            reducer,
        })
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

    #[derive(Clone)]
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
            resolver.resolve(spend_height).unwrap().lifecycle,
            Lifecycle::Cooldown
        );
        assert_eq!(
            resolver.tip(),
            Some(ReducerTip {
                height: spend_height,
                hash: hash(spend_height),
            })
        );
        assert_eq!(resolver.pending_commit(&commit_ref), Some(commitment));

        let mut candidate = resolver.clone();
        candidate.rollback_tip(hash(spend_height)).unwrap();
        assert_eq!(
            candidate.resolve(spend_height - 1).unwrap().lifecycle,
            Lifecycle::Active
        );
        assert_eq!(
            resolver.resolve(spend_height).unwrap().lifecycle,
            Lifecycle::Cooldown
        );

        let snapshot = resolver.save_snapshot().unwrap();
        let mut wrong_name: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        wrong_name["name"] = serde_json::Value::String("mallory".to_owned());
        assert_eq!(
            ExactResolver::load_snapshot(
                parameters,
                Network::Regtest,
                Name::parse("alice").unwrap(),
                AcceptProofs,
                &serde_json::to_vec(&wrong_name).unwrap(),
            )
            .map(|_| ()),
            Err(SnapshotError::NameMismatch)
        );
        let mut wrong_parameters = parameters;
        wrong_parameters.deployment_id = [8; 32];
        assert_eq!(
            ExactResolver::load_snapshot(
                wrong_parameters,
                Network::Regtest,
                Name::parse("alice").unwrap(),
                AcceptProofs,
                &snapshot,
            )
            .map(|_| ()),
            Err(SnapshotError::ParametersMismatch)
        );
        let mut wrong_ruleset: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        wrong_ruleset["ruleset_fingerprint"][0] = serde_json::Value::from(255);
        assert_eq!(
            ExactResolver::load_snapshot(
                parameters,
                Network::Regtest,
                Name::parse("alice").unwrap(),
                AcceptProofs,
                &serde_json::to_vec(&wrong_ruleset).unwrap(),
            )
            .map(|_| ()),
            Err(SnapshotError::ParametersMismatch)
        );
        let mut wrong_range: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        wrong_range["rollback_range"]["first_height"] = serde_json::Value::from(1_000);
        assert_eq!(
            ExactResolver::load_snapshot(
                parameters,
                Network::Regtest,
                Name::parse("alice").unwrap(),
                AcceptProofs,
                &serde_json::to_vec(&wrong_range).unwrap(),
            )
            .map(|_| ()),
            Err(SnapshotError::InvalidHistory)
        );
        let mut invalid_history: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        let reducer_bytes: Vec<u8> =
            serde_json::from_value(invalid_history["reducer"].take()).unwrap();
        let mut reducer_state: serde_json::Value = serde_json::from_slice(&reducer_bytes).unwrap();
        reducer_state["history"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["hash"][0] = serde_json::json!(99);
        invalid_history["reducer"] =
            serde_json::to_value(serde_json::to_vec(&reducer_state).unwrap()).unwrap();
        assert_eq!(
            ExactResolver::load_snapshot(
                parameters,
                Network::Regtest,
                Name::parse("alice").unwrap(),
                AcceptProofs,
                &serde_json::to_vec(&invalid_history).unwrap(),
            )
            .map(|_| ()),
            Err(SnapshotError::InvalidHistory)
        );

        let mut resolver = ExactResolver::load_snapshot(
            parameters,
            Network::Regtest,
            Name::parse("alice").unwrap(),
            AcceptProofs,
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            resolver.resolve(spend_height).unwrap().lifecycle,
            Lifecycle::Cooldown
        );

        assert_eq!(
            resolver.rollback_tip(hash(spend_height - 1)),
            Err(RollbackError::WrongTipHash)
        );
        assert_eq!(
            resolver.resolve(spend_height).unwrap().lifecycle,
            Lifecycle::Cooldown
        );

        resolver.rollback_tip(hash(spend_height)).unwrap();
        assert_eq!(
            resolver.resolve(spend_height - 1).unwrap().lifecycle,
            Lifecycle::Active
        );

        resolver
            .apply_block(&Block {
                height: spend_height,
                hash: [40; 32],
                prev_hash: hash(spend_height - 1),
                transactions: vec![],
            })
            .unwrap();
        assert_eq!(
            resolver.resolve(spend_height).unwrap().lifecycle,
            Lifecycle::Active
        );

        resolver.finalize_through(spend_height).unwrap();
        assert_eq!(
            resolver.rollback_tip([40; 32]),
            Err(RollbackError::BeyondRetention)
        );
    }

    #[test]
    fn exact_resolution_separates_missing_from_incomplete_history() {
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
        let mut resolver = ExactResolver::new(parameters, [0; 32], name, AcceptProofs).unwrap();
        assert_eq!(
            resolver.resolve(0),
            Err(ResolutionError::IncompleteHistory {
                requested_height: 0,
                tip_height: None,
            })
        );

        let pre_activation_parameters = Parameters {
            activation_height: 2,
            ..parameters
        };
        let pre_activation = ExactResolver::new(
            pre_activation_parameters,
            [9; 32],
            Name::parse("alice").unwrap(),
            AcceptProofs,
        )
        .unwrap();
        assert_eq!(
            pre_activation.resolve(1).unwrap().lifecycle,
            Lifecycle::Missing
        );
        resolver
            .apply_block(&Block {
                height: 0,
                hash: hash(0),
                prev_hash: [0; 32],
                transactions: vec![],
            })
            .unwrap();
        assert_eq!(resolver.resolve(0).unwrap().lifecycle, Lifecycle::Missing);
        assert_eq!(
            resolver.resolve(1),
            Err(ResolutionError::IncompleteHistory {
                requested_height: 1,
                tip_height: Some(0),
            })
        );
        resolver
            .apply_block(&Block {
                height: 1,
                hash: hash(1),
                prev_hash: hash(0),
                transactions: vec![],
            })
            .unwrap();
        assert_eq!(
            resolver.resolve(0),
            Err(ResolutionError::HistoricalResolutionUnavailable {
                requested_height: 0,
                tip_height: 1,
            })
        );
    }

    #[test]
    fn referenced_commit_is_equivalent_to_forward_commit_and_rolls_back_atomically() {
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
        let commit_ref = CommitRef {
            height: reveal_height - parameters.commit_maturity_blocks,
            tx_index: 3,
            txid: [10; 32],
        };
        let commitment = Commitment::from_bytes(pallas::Base::from(1).to_repr()).unwrap();
        let reveal = Operation::Reveal {
            name: name.clone(),
            commit: commit_ref,
            ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
            action_index: 0,
            successor_future_nf: field(4),
            proof: vec![1],
        };
        let mut resolver = ExactResolver::new(parameters, [0; 32], name, AcceptProofs).unwrap();
        let mut previous_hash = [0; 32];
        for height in 0..=reveal_height {
            let block_hash = hash(height);
            let block = Block {
                height,
                hash: block_hash,
                prev_hash: previous_hash,
                transactions: (height == reveal_height)
                    .then(|| Transaction {
                        tx_index: 0,
                        txid: [20; 32],
                        actions: vec![Action {
                            action_index: 0,
                            nullifier: field(2),
                            commitment: field(3),
                        }],
                        operation: Some(reveal.clone()),
                    })
                    .into_iter()
                    .collect(),
            };
            if height == reveal_height {
                let unrelated = ReferencedCommit {
                    reference: CommitRef {
                        txid: [99; 32],
                        ..commit_ref
                    },
                    commitment,
                };
                assert_eq!(
                    resolver.apply_block_with_referenced_commits(&block, &[unrelated]),
                    Err(ApplyError::InvalidReferencedCommit)
                );
                assert_eq!(
                    resolver
                        .apply_block_with_referenced_commits(
                            &block,
                            &[ReferencedCommit {
                                reference: commit_ref,
                                commitment,
                            }],
                        )
                        .unwrap(),
                    [Accepted::Reveal]
                );
            } else {
                resolver.apply_block(&block).unwrap();
            }
            previous_hash = block_hash;
        }
        assert_eq!(
            resolver.resolve(reveal_height).unwrap().lifecycle,
            Lifecycle::Active
        );
        assert_eq!(resolver.pending_commit(&commit_ref), Some(commitment));

        resolver.rollback_tip(hash(reveal_height)).unwrap();
        assert_eq!(resolver.pending_commit(&commit_ref), None);
        let alternate = Block {
            height: reveal_height,
            hash: [55; 32],
            prev_hash: hash(reveal_height - 1),
            transactions: vec![Transaction {
                tx_index: 0,
                txid: [20; 32],
                actions: vec![Action {
                    action_index: 0,
                    nullifier: field(2),
                    commitment: field(3),
                }],
                operation: Some(reveal),
            }],
        };
        assert!(resolver.apply_block(&alternate).unwrap().is_empty());
        assert_eq!(
            resolver.resolve(reveal_height).unwrap().lifecycle,
            Lifecycle::Missing
        );
    }
}
