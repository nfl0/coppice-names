//! Authenticated CPV1/CA01 transport decoding for Names operations.

use crate::{
    codec::{self, CodecError, CodecParameters, Operation},
    deployment::{DeploymentError, DeploymentParameters, NAMES_APPLICATION_VERSION},
    names_application_id,
    protocol::{Name, NameRoute, Network, ValueError},
};
use coppice::{
    application::ApplicationKey,
    carrier::{CoreRendezvous, RendezvousError},
    replay::CoreTransactionContext,
    runtime::{ApplicationMessageStatus, RoutedFrame, inspect_transaction_at_rendezvous},
    transport::Error as Cpv1Error,
};

/// Failure to construct the immutable routing and codec configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportConfigurationError {
    InvalidDeployment(DeploymentError),
    InvalidName(ValueError),
    InvalidRendezvous(RendezvousError),
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

/// Decodes only a COMMIT from the deployment's public Core rendezvous.
///
/// The supplied transaction context must have come from Core canonical replay.
pub fn inspect_commit_transaction(
    transaction: &CoreTransactionContext,
    public_rendezvous: &CoreRendezvous,
    deployment: DeploymentParameters,
    network: Network,
) -> Result<NamesTransportStatus, TransportConfigurationError> {
    inspect_authenticated(
        transaction,
        public_rendezvous,
        deployment,
        network,
        ExpectedRoute::Commit,
    )
}

/// Derives the public name route and decodes only a REVEAL or REFRESH for that
/// exact name. This is the arbitrary-name lookup boundary; it requires no
/// saved per-name secret or trusted index.
pub fn inspect_name_transaction(
    transaction: &CoreTransactionContext,
    deployment: DeploymentParameters,
    network: Network,
    name: &Name,
) -> Result<NamesTransportStatus, TransportConfigurationError> {
    let validated = deployment
        .validate()
        .map_err(TransportConfigurationError::InvalidDeployment)?;
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
    let inspection = inspect_transaction_at_rendezvous(
        full.transaction(),
        rendezvous,
        validated.core_runtime_id,
    );
    Ok(classify_inspection(
        inspection.routed_frames(),
        inspection.message(),
        validated,
        network,
        expected,
    ))
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
    use coppice::{application::ApplicationEnvelopeV1, identity::CoreRuntimeId};
    use pasta_curves::{group::ff::PrimeField, pallas};

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
}
