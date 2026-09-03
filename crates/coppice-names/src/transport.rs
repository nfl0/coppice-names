//! Authenticated CPV1/CA01 transport decoding for Names operations.

use crate::{
    codec::{self, CodecError, CodecParameters, Operation},
    deployment::{DeploymentError, DeploymentParameters, NAMES_APPLICATION_VERSION},
    names_application_id,
    protocol::{Name, NameRoute, Network, ValueError},
    reducer::{Action, Block, Transaction},
};
use coppice::{
    application::ApplicationKey,
    carrier::{CoreRendezvous, RendezvousError},
    identity::ValidatedCoreRuntimeParameters,
    replay::{
        CoreBlockContext, CorePositionedBlockContext, CoreTransactionContext,
        ValidatedFullTransaction,
    },
    runtime::{ApplicationMessageStatus, RoutedFrame, inspect_transaction_at_rendezvous},
    transport::Error as Cpv1Error,
};

/// Failure to construct the immutable routing and codec configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportConfigurationError {
    InvalidDeployment(DeploymentError),
    InvalidName(ValueError),
    InvalidRendezvous(RendezvousError),
    RuntimeMismatch,
}

/// A Core block could not be represented at the narrower Names boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportError {
    Configuration(TransportConfigurationError),
    InvalidActionEffects,
    InvalidActionPosition,
}

/// Why authenticated transaction bytes did not yield a Names operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportRejection {
    /// Core did not authenticate full transaction bytes against canonical
    /// compact effects. Raw host bytes are never accepted at this boundary.
    UnauthenticatedFullTransaction,
    /// Names carrier notes must carry no ZEC; the bonded note is a separate,
    /// designated Ironwood action authenticated by the operation proof.
    NonZeroCarrierValue,
    MalformedCpv1(Cpv1Error),
    MalformedCa01,
    WrongApplication,
    InvalidOperation(CodecError),
    WrongRoute,
}

/// Result of inspecting one canonical transaction at one Names rendezvous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesTransportStatus {
    /// No complete CPV1 bulletin addressed to this exact rendezvous.
    NoOperation,
    /// A candidate was present but is not one canonical operation for this
    /// Names route. Replay keeps its authenticated Ironwood effects but treats
    /// it as having no Names operation.
    Rejected(TransportRejection),
    Operation(Operation),
}

/// Returns the canonical global Ironwood position of one action in a
/// Core-authenticated block. The pre-block tree size is derived from Core's
/// authenticated post-block checkpoint and the complete ordered action list,
/// so callers do not need an activation-one or empty-frontier assumption.
pub fn authenticated_action_position(
    block: &CoreBlockContext,
    tx_index: u32,
    action_index: u32,
) -> Result<u32, BlockTransportError> {
    let total_actions = block
        .transactions()
        .iter()
        .try_fold(0u32, |total, transaction| {
            if transaction.ironwood_effects().nullifiers().len()
                != transaction.ironwood_effects().commitments().len()
            {
                return Err(BlockTransportError::InvalidActionEffects);
            }
            total
                .checked_add(
                    u32::try_from(transaction.ironwood_effects().commitments().len())
                        .map_err(|_| BlockTransportError::InvalidActionPosition)?,
                )
                .ok_or(BlockTransportError::InvalidActionPosition)
        })?;
    let mut position = block
        .ironwood_checkpoint()
        .tree_size
        .checked_sub(total_actions)
        .ok_or(BlockTransportError::InvalidActionPosition)?;
    for transaction in block.transactions() {
        let action_count = u32::try_from(transaction.ironwood_effects().commitments().len())
            .map_err(|_| BlockTransportError::InvalidActionPosition)?;
        if transaction.tx_index() == tx_index {
            if action_index >= action_count {
                return Err(BlockTransportError::InvalidActionPosition);
            }
            return position
                .checked_add(action_index)
                .ok_or(BlockTransportError::InvalidActionPosition);
        }
        position = position
            .checked_add(action_count)
            .ok_or(BlockTransportError::InvalidActionPosition)?;
    }
    Err(BlockTransportError::InvalidActionPosition)
}

/// Returns the canonical global Ironwood position of one action when the
/// commitment tree is authenticated and owned by the calling wallet.
pub fn positioned_action_position(
    block: &CorePositionedBlockContext,
    tx_index: u32,
    action_index: u32,
) -> Result<u32, BlockTransportError> {
    action_position(
        block.transactions(),
        block.pre_ironwood_tree_size(),
        tx_index,
        action_index,
    )
}

fn action_position(
    transactions: &[CoreTransactionContext],
    mut position: u32,
    tx_index: u32,
    action_index: u32,
) -> Result<u32, BlockTransportError> {
    for transaction in transactions {
        if transaction.ironwood_effects().nullifiers().len()
            != transaction.ironwood_effects().commitments().len()
        {
            return Err(BlockTransportError::InvalidActionEffects);
        }
        let action_count = u32::try_from(transaction.ironwood_effects().commitments().len())
            .map_err(|_| BlockTransportError::InvalidActionPosition)?;
        if transaction.tx_index() == tx_index {
            if action_index >= action_count {
                return Err(BlockTransportError::InvalidActionPosition);
            }
            return position
                .checked_add(action_index)
                .ok_or(BlockTransportError::InvalidActionPosition);
        }
        position = position
            .checked_add(action_count)
            .ok_or(BlockTransportError::InvalidActionPosition)?;
    }
    Err(BlockTransportError::InvalidActionPosition)
}

/// Decodes only a COMMIT from the deployment's public Core rendezvous.
///
/// The supplied transaction context must have come from Core canonical replay.
pub fn inspect_commit_transaction(
    transaction: &CoreTransactionContext,
    runtime: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    network: Network,
) -> Result<NamesTransportStatus, TransportConfigurationError> {
    let validated = validate_runtime(deployment, runtime)?;
    let public_rendezvous = CoreRendezvous::from_validated(runtime);
    inspect_authenticated(
        transaction,
        &public_rendezvous,
        validated,
        network,
        ExpectedRoute::Commit,
    )
}

/// Decodes a historical COMMIT after Core has authenticated its full bytes
/// against the canonical compact transaction named by a REVEAL.
pub fn inspect_validated_commit_transaction(
    transaction: &ValidatedFullTransaction,
    runtime: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    network: Network,
) -> Result<NamesTransportStatus, TransportConfigurationError> {
    let validated = validate_runtime(deployment, runtime)?;
    let public_rendezvous = CoreRendezvous::from_validated(runtime);
    Ok(inspect_validated(
        transaction,
        &public_rendezvous,
        validated,
        network,
        ExpectedRoute::Commit,
    ))
}

/// Derives the public name route and decodes only a REVEAL or REFRESH for that
/// exact name. This is the arbitrary-name lookup boundary; it requires no
/// saved per-name secret or trusted index.
pub fn inspect_name_transaction(
    transaction: &CoreTransactionContext,
    runtime: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    network: Network,
    name: &Name,
) -> Result<NamesTransportStatus, TransportConfigurationError> {
    let validated = validate_runtime(deployment, runtime)?;
    let deployment_id = validated
        .deployment_id()
        .map_err(TransportConfigurationError::InvalidDeployment)?;
    let name_id = name
        .id()
        .map_err(TransportConfigurationError::InvalidName)?;
    let route = NameRoute::derive(deployment_id, name_id)
        .map_err(TransportConfigurationError::InvalidName)?;
    let rendezvous = CoreRendezvous::try_new(&route.incoming_viewing_key(), &route.receiver())
        .map_err(TransportConfigurationError::InvalidRendezvous)?;
    inspect_authenticated(
        transaction,
        &rendezvous,
        validated,
        network,
        ExpectedRoute::Name(name),
    )
}

/// Decodes a name-routed transaction after stateless Core authentication.
/// Hosts use this during batch pre-acquisition to discover bounded COMMIT
/// references without trusting raw full-transaction bytes.
pub fn inspect_validated_name_transaction(
    transaction: &ValidatedFullTransaction,
    runtime: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    network: Network,
    name: &Name,
) -> Result<NamesTransportStatus, TransportConfigurationError> {
    let validated = validate_runtime(deployment, runtime)?;
    let deployment_id = validated
        .deployment_id()
        .map_err(TransportConfigurationError::InvalidDeployment)?;
    let name_id = name
        .id()
        .map_err(TransportConfigurationError::InvalidName)?;
    let route = NameRoute::derive(deployment_id, name_id)
        .map_err(TransportConfigurationError::InvalidName)?;
    let rendezvous = CoreRendezvous::try_new(&route.incoming_viewing_key(), &route.receiver())
        .map_err(TransportConfigurationError::InvalidRendezvous)?;
    Ok(inspect_validated(
        transaction,
        &rendezvous,
        validated,
        network,
        ExpectedRoute::Name(name),
    ))
}

/// Converts one Core-authenticated block into the exact reducer input for an
/// arbitrary requested name.
///
/// Each transaction is inspected at both the runtime's authenticated generic
/// COMMIT route and the deployment-derived requested-name route. Exactly one
/// correctly routed Names operation may survive. A second Names candidate,
/// including a malformed or wrong-route candidate, makes the transaction's
/// operation ambiguous and therefore inert; canonical Ironwood actions are
/// retained in every case.
pub fn inspect_exact_name_block(
    block: &CoreBlockContext,
    runtime: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    network: Network,
    name: &Name,
) -> Result<Block, BlockTransportError> {
    inspect_exact_name_block_parts(
        block.height(),
        block.block_hash(),
        block.prev_block_hash(),
        block.transactions(),
        runtime,
        deployment,
        network,
        name,
    )
}

/// Position-only counterpart to [`inspect_exact_name_block`] for a wallet
/// that already owns and authenticates the Ironwood commitment tree.
pub fn inspect_exact_name_positioned_block(
    block: &CorePositionedBlockContext,
    runtime: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    network: Network,
    name: &Name,
) -> Result<Block, BlockTransportError> {
    inspect_exact_name_block_parts(
        block.height(),
        block.block_hash(),
        block.prev_block_hash(),
        block.transactions(),
        runtime,
        deployment,
        network,
        name,
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_exact_name_block_parts(
    height: u32,
    hash: [u8; 32],
    prev_hash: [u8; 32],
    core_transactions: &[CoreTransactionContext],
    runtime: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    network: Network,
    name: &Name,
) -> Result<Block, BlockTransportError> {
    let validated =
        validate_runtime(deployment, runtime).map_err(BlockTransportError::Configuration)?;
    let transactions = core_transactions
        .iter()
        .map(|transaction| {
            let effects = transaction.ironwood_effects();
            if effects.nullifiers().len() != effects.commitments().len() {
                return Err(BlockTransportError::InvalidActionEffects);
            }
            let actions = effects
                .nullifiers()
                .iter()
                .zip(effects.commitments())
                .enumerate()
                .map(|(action_index, (nullifier, commitment))| {
                    Ok(Action {
                        action_index: u32::try_from(action_index)
                            .map_err(|_| BlockTransportError::InvalidActionEffects)?,
                        nullifier: crate::protocol::FieldElement::from_bytes(*nullifier)
                            .map_err(|_| BlockTransportError::InvalidActionEffects)?,
                        commitment: crate::protocol::FieldElement::from_bytes(*commitment)
                            .map_err(|_| BlockTransportError::InvalidActionEffects)?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let operation = if transaction
                .full_transaction_status()
                .validated_full_transaction()
                .is_none()
            {
                None
            } else {
                let commit = inspect_commit_transaction(transaction, runtime, validated, network)
                    .map_err(BlockTransportError::Configuration)?;
                let named =
                    inspect_name_transaction(transaction, runtime, validated, network, name)
                        .map_err(BlockTransportError::Configuration)?;
                select_single_operation(commit, named)
            };
            Ok(Transaction {
                tx_index: transaction.tx_index(),
                txid: transaction.txid(),
                actions,
                operation,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Block {
        height,
        hash,
        prev_hash,
        transactions,
    })
}

fn validate_runtime(
    deployment: DeploymentParameters,
    runtime: &ValidatedCoreRuntimeParameters,
) -> Result<DeploymentParameters, TransportConfigurationError> {
    let validated = deployment
        .validate()
        .map_err(TransportConfigurationError::InvalidDeployment)?;
    if validated.core_runtime_id != runtime.core_runtime_id() {
        return Err(TransportConfigurationError::RuntimeMismatch);
    }
    Ok(validated)
}

fn select_single_operation(
    commit: NamesTransportStatus,
    named: NamesTransportStatus,
) -> Option<Operation> {
    match (commit, named) {
        (NamesTransportStatus::Operation(operation), NamesTransportStatus::NoOperation)
        | (NamesTransportStatus::NoOperation, NamesTransportStatus::Operation(operation)) => {
            Some(operation)
        }
        (
            NamesTransportStatus::Operation(operation),
            NamesTransportStatus::Rejected(TransportRejection::WrongApplication),
        )
        | (
            NamesTransportStatus::Rejected(TransportRejection::WrongApplication),
            NamesTransportStatus::Operation(operation),
        ) => Some(operation),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum ExpectedRoute<'a> {
    Commit,
    Name(&'a Name),
}

fn inspect_authenticated(
    transaction: &CoreTransactionContext,
    rendezvous: &CoreRendezvous,
    deployment: DeploymentParameters,
    network: Network,
    expected: ExpectedRoute<'_>,
) -> Result<NamesTransportStatus, TransportConfigurationError> {
    let validated = deployment
        .validate()
        .map_err(TransportConfigurationError::InvalidDeployment)?;
    let Some(full) = transaction
        .full_transaction_status()
        .validated_full_transaction()
    else {
        return Ok(NamesTransportStatus::Rejected(
            TransportRejection::UnauthenticatedFullTransaction,
        ));
    };
    Ok(inspect_validated(
        full, rendezvous, validated, network, expected,
    ))
}

fn inspect_validated(
    transaction: &ValidatedFullTransaction,
    rendezvous: &CoreRendezvous,
    deployment: DeploymentParameters,
    network: Network,
    expected: ExpectedRoute<'_>,
) -> NamesTransportStatus {
    let inspection = inspect_transaction_at_rendezvous(
        transaction.transaction(),
        rendezvous,
        deployment.core_runtime_id,
    );
    classify_inspection(
        inspection.routed_frames(),
        inspection.message(),
        deployment,
        network,
        expected,
    )
}

fn classify_inspection(
    routed_frames: &[RoutedFrame],
    message: &ApplicationMessageStatus,
    deployment: DeploymentParameters,
    network: Network,
    expected: ExpectedRoute<'_>,
) -> NamesTransportStatus {
    if routed_frames.iter().any(|frame| frame.value != 0) {
        return NamesTransportStatus::Rejected(TransportRejection::NonZeroCarrierValue);
    }
    let envelope = match message {
        ApplicationMessageStatus::NotCandidate | ApplicationMessageStatus::NoMessage => {
            return NamesTransportStatus::NoOperation;
        }
        ApplicationMessageStatus::MalformedTransport(error) => {
            return NamesTransportStatus::Rejected(TransportRejection::MalformedCpv1(*error));
        }
        ApplicationMessageStatus::MalformedEnvelope(_) => {
            return NamesTransportStatus::Rejected(TransportRejection::MalformedCa01);
        }
        ApplicationMessageStatus::Message(envelope) => envelope,
    };
    if envelope.key() != ApplicationKey::new(names_application_id(), NAMES_APPLICATION_VERSION) {
        return NamesTransportStatus::Rejected(TransportRejection::WrongApplication);
    }
    let parameters = CodecParameters {
        reveal_proof_bytes: usize::from(deployment.proof.reveal_proof_bytes()),
        refresh_proof_bytes: usize::from(deployment.proof.refresh_proof_bytes()),
    };
    let operation = match codec::decode(envelope.payload(), network, parameters) {
        Ok(operation) => operation,
        Err(error) => {
            return NamesTransportStatus::Rejected(TransportRejection::InvalidOperation(error));
        }
    };
    let on_expected_route = match (&operation, expected) {
        (Operation::Commit { .. }, ExpectedRoute::Commit) => true,
        (
            Operation::Reveal { name, .. } | Operation::Refresh { name, .. },
            ExpectedRoute::Name(expected),
        ) => name == expected,
        _ => false,
    };
    if !on_expected_route {
        return NamesTransportStatus::Rejected(TransportRejection::WrongRoute);
    }
    NamesTransportStatus::Operation(operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deployment::ProofIdentity,
        protocol::{CanonicalUa, CommitRef, Commitment, FieldElement},
    };
    use coppice::{
        application::ApplicationEnvelopeV1,
        identity::{CoreRuntimeId, CoreRuntimeParameters, ZcashNetwork},
        replay::{
            CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CorePositionReplay, CoreReplay,
            CoreReplayActivationCheckpoint, CoreReplayConfiguration, CoreReplayPositionCheckpoint,
            FullTransactionAcquisition, IronwoodFrontier,
        },
    };
    use pasta_curves::{group::ff::PrimeField, pallas};
    use zcash_protocol::consensus::BranchId;

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    fn deployment() -> DeploymentParameters {
        DeploymentParameters {
            core_runtime_id: CoreRuntimeId::from_bytes([3; 32]),
            activation_height: 100,
            epoch_blocks: 20,
            window_blocks: 4,
            commit_maturity_blocks: 4,
            commit_ttl_blocks: 10,
            lease_blocks: 50,
            cooldown_blocks: 20,
            proof: ProofIdentity::derive(11, 64, 96, [1; 32], [2; 32]),
        }
    }

    fn runtime() -> ValidatedCoreRuntimeParameters {
        CoreRuntimeParameters {
            runtime_protocol_id: b"coppice.runtime".to_vec(),
            runtime_protocol_version: 1,
            zcash_network_domain: b"coppice-runtime-regtest-v1".to_vec(),
            zcash_network: ZcashNetwork::Regtest,
            runtime_activation_height: 100,
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
        .unwrap()
    }

    fn commit() -> Operation {
        Operation::Commit {
            commitment: Commitment::from_bytes(pallas::Base::from(7).to_repr()).unwrap(),
        }
    }

    fn reveal(name: Name) -> Operation {
        Operation::Reveal {
            name,
            commit: CommitRef {
                height: 100,
                tx_index: 0,
                txid: [4; 32],
            },
            ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
            action_index: 0,
            successor_future_nf: FieldElement::from_bytes(pallas::Base::from(8).to_repr()).unwrap(),
            proof: vec![5; 64],
        }
    }

    fn status_for(operation: &Operation) -> ApplicationMessageStatus {
        let parameters = CodecParameters {
            reveal_proof_bytes: 64,
            refresh_proof_bytes: 96,
        };
        let payload = codec::encode(operation, parameters).unwrap();
        ApplicationMessageStatus::Message(
            ApplicationEnvelopeV1::new(
                ApplicationKey::new(names_application_id(), NAMES_APPLICATION_VERSION),
                payload,
            )
            .unwrap(),
        )
    }

    #[test]
    fn accepts_exactly_one_commit_on_public_route() {
        let operation = commit();
        assert_eq!(
            classify_inspection(
                &[],
                &status_for(&operation),
                deployment(),
                Network::Regtest,
                ExpectedRoute::Commit,
            ),
            NamesTransportStatus::Operation(operation)
        );
    }

    #[test]
    fn rejects_nonzero_carrier_before_decoding() {
        let frame = RoutedFrame {
            action_index: 2,
            value: 1,
            memo: [0; 512],
        };
        assert_eq!(
            classify_inspection(
                &[frame],
                &status_for(&commit()),
                deployment(),
                Network::Regtest,
                ExpectedRoute::Commit,
            ),
            NamesTransportStatus::Rejected(TransportRejection::NonZeroCarrierValue)
        );
    }

    #[test]
    fn rejects_other_application_and_wrong_route() {
        let operation = commit();
        let other = ApplicationMessageStatus::Message(
            ApplicationEnvelopeV1::new(
                ApplicationKey::new(coppice::application::ApplicationId::from_bytes([9; 32]), 2),
                codec::encode(
                    &operation,
                    CodecParameters {
                        reveal_proof_bytes: 64,
                        refresh_proof_bytes: 96,
                    },
                )
                .unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            classify_inspection(
                &[],
                &other,
                deployment(),
                Network::Regtest,
                ExpectedRoute::Commit,
            ),
            NamesTransportStatus::Rejected(TransportRejection::WrongApplication)
        );
        let name = Name::parse("alice").unwrap();
        assert_eq!(
            classify_inspection(
                &[],
                &status_for(&operation),
                deployment(),
                Network::Regtest,
                ExpectedRoute::Name(&name),
            ),
            NamesTransportStatus::Rejected(TransportRejection::WrongRoute)
        );
    }

    #[test]
    fn name_route_requires_the_exact_name_and_non_commit_operation() {
        let alice = Name::parse("alice").unwrap();
        let bob = Name::parse("bob").unwrap();
        let operation = reveal(alice.clone());
        assert_eq!(
            classify_inspection(
                &[],
                &status_for(&operation),
                deployment(),
                Network::Regtest,
                ExpectedRoute::Name(&alice),
            ),
            NamesTransportStatus::Operation(operation.clone())
        );
        assert_eq!(
            classify_inspection(
                &[],
                &status_for(&operation),
                deployment(),
                Network::Regtest,
                ExpectedRoute::Name(&bob),
            ),
            NamesTransportStatus::Rejected(TransportRejection::WrongRoute)
        );
        assert_eq!(
            classify_inspection(
                &[],
                &status_for(&operation),
                deployment(),
                Network::Regtest,
                ExpectedRoute::Commit,
            ),
            NamesTransportStatus::Rejected(TransportRejection::WrongRoute)
        );
    }

    #[test]
    fn composed_routes_accept_one_names_operation_and_reject_ambiguity() {
        let operation = commit();
        assert_eq!(
            select_single_operation(
                NamesTransportStatus::Operation(operation.clone()),
                NamesTransportStatus::NoOperation,
            ),
            Some(operation.clone())
        );
        assert_eq!(
            select_single_operation(
                NamesTransportStatus::Operation(operation.clone()),
                NamesTransportStatus::Rejected(TransportRejection::WrongApplication),
            ),
            Some(operation.clone())
        );
        assert_eq!(
            select_single_operation(
                NamesTransportStatus::Operation(operation.clone()),
                NamesTransportStatus::Operation(operation.clone()),
            ),
            None
        );
        assert_eq!(
            select_single_operation(
                NamesTransportStatus::Operation(operation),
                NamesTransportStatus::Rejected(TransportRejection::NonZeroCarrierValue),
            ),
            None
        );
    }

    #[test]
    fn exact_block_adapter_preserves_sparse_core_positions() {
        let runtime = runtime();
        let mut deployment = deployment();
        deployment.core_runtime_id = runtime.core_runtime_id();
        let mut replay = CoreReplay::new(
            CoreReplayConfiguration::new(100, 20).unwrap(),
            CoreReplayActivationCheckpoint {
                height: 99,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap();
        let transactions = [2, 7, 11]
            .map(|tx_index| CoreCanonicalTransactionInput {
                tx_index,
                txid: [tx_index as u8; 32],
                ironwood_nullifiers: vec![],
                ironwood_commitments: vec![],
                full_transaction_acquisition: FullTransactionAcquisition::None,
                full_transaction: None,
            })
            .to_vec();
        let core = replay
            .apply_block(&CoreCanonicalBlockInput {
                height: 100,
                block_hash: [10; 32],
                prev_block_hash: [9; 32],
                branch_id: BranchId::Nu6_3,
                transactions,
            })
            .unwrap();
        let names = inspect_exact_name_block(
            &core,
            &runtime,
            deployment,
            Network::Regtest,
            &Name::parse("alice").unwrap(),
        )
        .unwrap();
        assert_eq!(names.height, 100);
        assert_eq!(names.hash, [10; 32]);
        assert_eq!(names.prev_hash, [9; 32]);
        assert_eq!(
            names
                .transactions
                .iter()
                .map(|transaction| transaction.tx_index)
                .collect::<Vec<_>>(),
            [2, 7, 11]
        );
        assert!(
            names.transactions.iter().all(
                |transaction| transaction.actions.is_empty() && transaction.operation.is_none()
            )
        );
    }

    #[test]
    fn authenticated_positions_include_the_pre_block_frontier() {
        let mut replay = CoreReplay::new(
            CoreReplayConfiguration::new(100, 20).unwrap(),
            CoreReplayActivationCheckpoint {
                height: 99,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap();
        let action_bytes = |value: u64| pallas::Base::from(value).to_repr();
        replay
            .apply_block(&CoreCanonicalBlockInput {
                height: 100,
                block_hash: [10; 32],
                prev_block_hash: [9; 32],
                branch_id: BranchId::Nu6_3,
                transactions: vec![CoreCanonicalTransactionInput {
                    tx_index: 4,
                    txid: [4; 32],
                    ironwood_nullifiers: vec![action_bytes(1), action_bytes(2)],
                    ironwood_commitments: vec![action_bytes(3), action_bytes(4)],
                    full_transaction_acquisition: FullTransactionAcquisition::None,
                    full_transaction: None,
                }],
            })
            .unwrap();
        let core = replay
            .apply_block(&CoreCanonicalBlockInput {
                height: 101,
                block_hash: [11; 32],
                prev_block_hash: [10; 32],
                branch_id: BranchId::Nu6_3,
                transactions: vec![
                    CoreCanonicalTransactionInput {
                        tx_index: 2,
                        txid: [2; 32],
                        ironwood_nullifiers: vec![action_bytes(5)],
                        ironwood_commitments: vec![action_bytes(6)],
                        full_transaction_acquisition: FullTransactionAcquisition::None,
                        full_transaction: None,
                    },
                    CoreCanonicalTransactionInput {
                        tx_index: 9,
                        txid: [9; 32],
                        ironwood_nullifiers: vec![action_bytes(7), action_bytes(8)],
                        ironwood_commitments: vec![action_bytes(9), action_bytes(10)],
                        full_transaction_acquisition: FullTransactionAcquisition::None,
                        full_transaction: None,
                    },
                ],
            })
            .unwrap();

        assert_eq!(authenticated_action_position(&core, 2, 0), Ok(2));
        assert_eq!(authenticated_action_position(&core, 9, 0), Ok(3));
        assert_eq!(authenticated_action_position(&core, 9, 1), Ok(4));
        assert_eq!(
            authenticated_action_position(&core, 9, 2),
            Err(BlockTransportError::InvalidActionPosition)
        );
        assert_eq!(
            authenticated_action_position(&core, 7, 0),
            Err(BlockTransportError::InvalidActionPosition)
        );
    }

    #[test]
    fn wallet_position_replay_matches_full_replay_positions() {
        let configuration = CoreReplayConfiguration::new(100, 20).unwrap();
        let mut replay = CorePositionReplay::new(
            configuration,
            CoreReplayPositionCheckpoint {
                height: 99,
                block_hash: [9; 32],
                ironwood_tree_size: 2,
            },
        )
        .unwrap();
        let action_bytes = |value: u64| pallas::Base::from(value).to_repr();
        let core = replay
            .apply_block(&CoreCanonicalBlockInput {
                height: 100,
                block_hash: [10; 32],
                prev_block_hash: [9; 32],
                branch_id: BranchId::Nu6_3,
                transactions: vec![
                    CoreCanonicalTransactionInput {
                        tx_index: 2,
                        txid: [2; 32],
                        ironwood_nullifiers: vec![action_bytes(5)],
                        ironwood_commitments: vec![action_bytes(6)],
                        full_transaction_acquisition: FullTransactionAcquisition::None,
                        full_transaction: None,
                    },
                    CoreCanonicalTransactionInput {
                        tx_index: 9,
                        txid: [9; 32],
                        ironwood_nullifiers: vec![action_bytes(7), action_bytes(8)],
                        ironwood_commitments: vec![action_bytes(9), action_bytes(10)],
                        full_transaction_acquisition: FullTransactionAcquisition::None,
                        full_transaction: None,
                    },
                ],
            })
            .unwrap();

        assert_eq!(core.pre_ironwood_tree_size(), 2);
        assert_eq!(core.post_ironwood_tree_size(), 5);
        assert_eq!(positioned_action_position(&core, 2, 0), Ok(2));
        assert_eq!(positioned_action_position(&core, 9, 0), Ok(3));
        assert_eq!(positioned_action_position(&core, 9, 1), Ok(4));
        assert_eq!(
            positioned_action_position(&core, 9, 2),
            Err(BlockTransportError::InvalidActionPosition)
        );
    }
}
