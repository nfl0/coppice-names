//! Coppice Names v1 identity and generic application-envelope adapters.
//!
//! Names uses its frozen deployment identity internally while Core owns
//! runtime transport identity and application routing.

use coppice_core::application::{
    ApplicationDescriptor, ApplicationEnvelopeError, ApplicationEnvelopeV1, ApplicationId,
    ApplicationKey, derive_application_id,
};
use coppice_core::{
    carrier::CPV1_PROTOCOL_ID,
    identity::{
        CORE_RUNTIME_PROTOCOL_ID_V1, CORE_RUNTIME_PROTOCOL_VERSION_V1, CoreRuntimeId,
        CoreRuntimeIdentityError, CoreRuntimeParameters, ValidatedCoreRuntimeParameters,
        ZcashNetwork,
    },
};
use zcash_protocol::consensus::NetworkType;

use crate::{
    config::{DeploymentEncodingError, DeploymentParameters, DeploymentValidationError},
    constants,
    envelope::{self, Operation},
};

/// Exact application-family identity bytes frozen for Coppice Names.
///
/// The application version is carried separately, so later versions retain
/// the family ID and use a different `ApplicationKey::version`.
pub const NAMES_CANONICAL_APPLICATION_IDENTITY: &[u8] = b"coppice.names";
pub const NAMES_V1_APPLICATION_VERSION: u16 = 1;
pub const NAMES_V1_REGTEST_CORE_NETWORK_DOMAIN: &[u8] = b"coppice-runtime-regtest-v1";
pub const NAMES_V1_TESTNET_CORE_NETWORK_DOMAIN: &[u8] = b"coppice-runtime-testnet-v1";

pub fn names_application_id() -> ApplicationId {
    derive_application_id(NAMES_CANONICAL_APPLICATION_IDENTITY)
        .expect("the frozen Names application identity is nonempty")
}

pub fn names_v1_application_key() -> ApplicationKey {
    ApplicationKey::new(names_application_id(), NAMES_V1_APPLICATION_VERSION)
}

/// Names v1 initially shares the runtime activation height. This descriptor is
/// not an input to `CoreRuntimeId`; later applications may activate at later
/// heights without changing that runtime identity.
pub fn names_v1_application_descriptor(runtime_activation_height: u32) -> ApplicationDescriptor {
    ApplicationDescriptor {
        key: names_v1_application_key(),
        activation_height: runtime_activation_height,
    }
}

/// The existing Coppice Names deployment identifier, preserved byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamesDeploymentId([u8; 32]);

impl NamesDeploymentId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_parameters(
        parameters: &DeploymentParameters,
    ) -> Result<Self, DeploymentEncodingError> {
        parameters.deployment_id().map(Self)
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesCoreCompatibilityError {
    InvalidNamesDeployment(DeploymentValidationError),
    InvalidCoreRuntime(CoreRuntimeIdentityError),
    UnsupportedNamesNetworkDomain,
    RuntimeProtocol,
    ZcashNetwork,
    ZcashNetworkDomain,
    CarrierProtocol,
    RendezvousIvk,
    RendezvousReceiver,
    ApplicationKey,
    ApplicationActivation,
    NamesV1RuntimeActivation,
}

/// Derives and validates the generic Core context shared by the frozen Names
/// v1 deployment. Names policy parameters are deliberately not copied into the
/// Core parameters or identity.
pub fn names_v1_core_runtime_parameters(
    names: &DeploymentParameters,
) -> Result<ValidatedCoreRuntimeParameters, NamesCoreCompatibilityError> {
    names
        .validate()
        .map_err(NamesCoreCompatibilityError::InvalidNamesDeployment)?;
    let (zcash_network, zcash_network_domain, expected_address_network) =
        if names.network_id == constants::REGTEST_NETWORK_ID {
            (
                ZcashNetwork::Regtest,
                NAMES_V1_REGTEST_CORE_NETWORK_DOMAIN,
                NetworkType::Regtest,
            )
        } else if names.network_id == constants::TESTNET_NETWORK_ID {
            (
                ZcashNetwork::Test,
                NAMES_V1_TESTNET_CORE_NETWORK_DOMAIN,
                NetworkType::Test,
            )
        } else {
            return Err(NamesCoreCompatibilityError::UnsupportedNamesNetworkDomain);
        };
    if names.address_network != expected_address_network {
        return Err(NamesCoreCompatibilityError::ZcashNetwork);
    }
    CoreRuntimeParameters {
        runtime_protocol_id: CORE_RUNTIME_PROTOCOL_ID_V1.to_vec(),
        runtime_protocol_version: CORE_RUNTIME_PROTOCOL_VERSION_V1,
        zcash_network_domain: zcash_network_domain.to_vec(),
        zcash_network,
        runtime_activation_height: names.activation_height,
        carrier_protocol_id: CPV1_PROTOCOL_ID.to_vec(),
        rendezvous_ivk: names.rendezvous.orchard_ivk,
        rendezvous_receiver: names.rendezvous.orchard_receiver,
    }
    .validate()
    .map_err(NamesCoreCompatibilityError::InvalidCoreRuntime)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedNamesV1CoreContext {
    core_runtime_id: CoreRuntimeId,
    names_deployment_id: NamesDeploymentId,
    application: ApplicationDescriptor,
}

impl ValidatedNamesV1CoreContext {
    pub const fn core_runtime_id(&self) -> CoreRuntimeId {
        self.core_runtime_id
    }

    pub const fn names_deployment_id(&self) -> NamesDeploymentId {
        self.names_deployment_id
    }

    pub const fn application(&self) -> ApplicationDescriptor {
        self.application
    }
}

/// Validates the independently derived Core and Coppice Names v1 contexts.
///
/// This comparison never derives either identity from the other context.
pub fn validate_names_v1_core_compatibility(
    core: &ValidatedCoreRuntimeParameters,
    names: &DeploymentParameters,
    application: ApplicationDescriptor,
) -> Result<ValidatedNamesV1CoreContext, NamesCoreCompatibilityError> {
    let names_deployment_id = NamesDeploymentId::from_bytes(
        names
            .validate()
            .map_err(NamesCoreCompatibilityError::InvalidNamesDeployment)?,
    );
    let core_parameters = core.parameters();

    if core_parameters.runtime_protocol_id != CORE_RUNTIME_PROTOCOL_ID_V1
        || core_parameters.runtime_protocol_version != CORE_RUNTIME_PROTOCOL_VERSION_V1
    {
        return Err(NamesCoreCompatibilityError::RuntimeProtocol);
    }
    if core_parameters.carrier_protocol_id != CPV1_PROTOCOL_ID {
        return Err(NamesCoreCompatibilityError::CarrierProtocol);
    }
    if application.key != names_v1_application_key() {
        return Err(NamesCoreCompatibilityError::ApplicationKey);
    }

    let (expected_network, expected_network_domain, expected_address_network) =
        if names.network_id == constants::REGTEST_NETWORK_ID {
            (
                ZcashNetwork::Regtest,
                NAMES_V1_REGTEST_CORE_NETWORK_DOMAIN,
                NetworkType::Regtest,
            )
        } else if names.network_id == constants::TESTNET_NETWORK_ID {
            (
                ZcashNetwork::Test,
                NAMES_V1_TESTNET_CORE_NETWORK_DOMAIN,
                NetworkType::Test,
            )
        } else {
            return Err(NamesCoreCompatibilityError::UnsupportedNamesNetworkDomain);
        };

    if names.address_network != expected_address_network
        || core_parameters.zcash_network != expected_network
    {
        return Err(NamesCoreCompatibilityError::ZcashNetwork);
    }
    if core_parameters.zcash_network_domain != expected_network_domain {
        return Err(NamesCoreCompatibilityError::ZcashNetworkDomain);
    }
    if names.rendezvous.orchard_ivk != core_parameters.rendezvous_ivk {
        return Err(NamesCoreCompatibilityError::RendezvousIvk);
    }
    if names.rendezvous.orchard_receiver != core_parameters.rendezvous_receiver {
        return Err(NamesCoreCompatibilityError::RendezvousReceiver);
    }
    if application.activation_height != names.activation_height {
        return Err(NamesCoreCompatibilityError::ApplicationActivation);
    }
    if application.activation_height != core_parameters.runtime_activation_height {
        return Err(NamesCoreCompatibilityError::NamesV1RuntimeActivation);
    }

    Ok(ValidatedNamesV1CoreContext {
        core_runtime_id: core.core_runtime_id(),
        names_deployment_id,
        application,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamesApplicationEnvelopeError {
    Application(ApplicationEnvelopeError),
    WrongApplication,
    Operation(envelope::Error),
}

pub fn encode_names_v1_envelope(
    operation: &Operation,
) -> Result<Vec<u8>, NamesApplicationEnvelopeError> {
    let payload =
        envelope::encode_operation(operation).map_err(NamesApplicationEnvelopeError::Operation)?;
    ApplicationEnvelopeV1::new(names_v1_application_key(), payload)
        .map_err(NamesApplicationEnvelopeError::Application)
        .map(|value| value.encode())
}

pub fn decode_names_v1_envelope(bytes: &[u8]) -> Result<Operation, NamesApplicationEnvelopeError> {
    let application =
        ApplicationEnvelopeV1::decode(bytes).map_err(NamesApplicationEnvelopeError::Application)?;
    if application.key() != names_v1_application_key() {
        return Err(NamesApplicationEnvelopeError::WrongApplication);
    }
    envelope::decode_operation(application.payload())
        .map_err(NamesApplicationEnvelopeError::Operation)
}
