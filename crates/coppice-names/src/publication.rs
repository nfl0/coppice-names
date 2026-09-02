//! Canonical outbound transport construction for Names operations.

use crate::{
    codec::{self, CodecError, CodecParameters, Operation},
    deployment::{DeploymentError, DeploymentParameters, NAMES_APPLICATION_VERSION},
    names_application_id,
    protocol::{NameRoute, ValueError},
};
use coppice::{
    application::{ApplicationEnvelopeError, ApplicationEnvelopeV1, ApplicationKey},
    transport::{self, Error as Cpv1Error},
};

/// Every replacement-protocol carrier note has exactly zero zatoshis.
pub const NAMES_CARRIER_VALUE_ZATOSHIS: u64 = 0;

/// Public rendezvous selected by the operation itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationRoute {
    /// Name-hiding COMMIT uses the validated Core runtime rendezvous.
    Generic,
    /// REVEAL and REFRESH use the deployment-separated name route.
    Name(NameRoute),
}

/// Fully encoded publication material for one semantic Names operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPublication {
    operation: Operation,
    route: PublicationRoute,
    encoded_operation: Vec<u8>,
    encoded_envelope: Vec<u8>,
    frames: Vec<[u8; 512]>,
}

impl PreparedPublication {
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    pub const fn route(&self) -> PublicationRoute {
        self.route
    }

    pub fn encoded_operation(&self) -> &[u8] {
        &self.encoded_operation
    }

    pub fn encoded_envelope(&self) -> &[u8] {
        &self.encoded_envelope
    }

    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
    }

    pub const fn carrier_value_zatoshis(&self) -> u64 {
        NAMES_CARRIER_VALUE_ZATOSHIS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationError {
    InvalidDeployment(DeploymentError),
    InvalidName(ValueError),
    InvalidOperation(CodecError),
    InvalidEnvelope(ApplicationEnvelopeError),
    InvalidTransport(Cpv1Error),
}

/// Encodes exactly one operation using deployment-bound proof lengths and
/// runtime separation. The returned route is not caller-selectable.
pub fn prepare_publication(
    operation: Operation,
    deployment: DeploymentParameters,
) -> Result<PreparedPublication, PublicationError> {
    let deployment = deployment
        .validate()
        .map_err(PublicationError::InvalidDeployment)?;
    let deployment_id = deployment
        .deployment_id()
        .map_err(PublicationError::InvalidDeployment)?;
    let route = match &operation {
        Operation::Commit { .. } => PublicationRoute::Generic,
        Operation::Reveal { name, .. } | Operation::Refresh { name, .. } => {
            let name_id = name.id().map_err(PublicationError::InvalidName)?;
            PublicationRoute::Name(
                NameRoute::derive(deployment_id, name_id).map_err(PublicationError::InvalidName)?,
            )
        }
    };
    let codec_parameters = CodecParameters {
        reveal_proof_bytes: usize::from(deployment.proof.reveal_proof_bytes()),
        refresh_proof_bytes: usize::from(deployment.proof.refresh_proof_bytes()),
    };
    let encoded_operation =
        codec::encode(&operation, codec_parameters).map_err(PublicationError::InvalidOperation)?;
    let envelope = ApplicationEnvelopeV1::new(
        ApplicationKey::new(names_application_id(), NAMES_APPLICATION_VERSION),
        encoded_operation.clone(),
    )
    .map_err(PublicationError::InvalidEnvelope)?;
    let encoded_envelope = envelope.encode();
    let frames = transport::encode_frames(deployment.core_runtime_id.to_bytes(), &encoded_envelope)
        .map_err(PublicationError::InvalidTransport)?;
    Ok(PreparedPublication {
        operation,
        route,
        encoded_operation,
        encoded_envelope,
        frames,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deployment::ProofIdentity,
        protocol::{CanonicalUa, CommitRef, Commitment, FieldElement, Name, Network},
    };
    use coppice::identity::CoreRuntimeId;
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
            proof: ProofIdentity::derive(11, 4_704, 4_704, [1; 32], [2; 32]),
        }
    }

    fn field(value: u64) -> FieldElement {
        FieldElement::from_bytes(pallas::Base::from(value).to_repr()).unwrap()
    }

    #[test]
    fn commit_uses_generic_route_and_round_trips_all_layers() {
        let operation = Operation::Commit {
            commitment: Commitment::from_bytes(pallas::Base::from(7).to_repr()).unwrap(),
        };
        let prepared = prepare_publication(operation.clone(), deployment()).unwrap();
        assert_eq!(prepared.route(), PublicationRoute::Generic);
        assert_eq!(prepared.carrier_value_zatoshis(), 0);
        let reconstructed = transport::reconstruct_frames(
            prepared.frames(),
            deployment().core_runtime_id.to_bytes(),
        )
        .unwrap();
        assert_eq!(reconstructed, prepared.encoded_envelope());
        let envelope = ApplicationEnvelopeV1::decode(&reconstructed).unwrap();
        assert_eq!(
            codec::decode(
                envelope.payload(),
                Network::Regtest,
                CodecParameters {
                    reveal_proof_bytes: 4_704,
                    refresh_proof_bytes: 4_704,
                },
            ),
            Ok(operation)
        );
    }

    #[test]
    fn reveal_route_is_derived_from_its_exact_name() {
        let name = Name::parse("alice").unwrap();
        let operation = Operation::Reveal {
            name: name.clone(),
            commit: CommitRef {
                height: 100,
                tx_index: 2,
                txid: [4; 32],
            },
            ua: CanonicalUa::parse(Network::Regtest, UA).unwrap(),
            action_index: 0,
            successor_future_nf: field(8),
            proof: vec![5; 4_704],
        };
        let prepared = prepare_publication(operation, deployment()).unwrap();
        let expected =
            NameRoute::derive(deployment().deployment_id().unwrap(), name.id().unwrap()).unwrap();
        assert_eq!(prepared.route(), PublicationRoute::Name(expected));
        assert_eq!(prepared.frames().len(), 11);
    }
}
