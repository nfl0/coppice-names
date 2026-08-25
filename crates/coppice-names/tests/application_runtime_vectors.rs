use coppice::{
    config::{DeploymentParameters, DeploymentValidationError, Rendezvous},
    envelope::{self, Operation},
    names_application::{
        NAMES_CANONICAL_APPLICATION_IDENTITY, NAMES_V1_APPLICATION_VERSION,
        NamesApplicationEnvelopeError, NamesCoreCompatibilityError, NamesDeploymentId,
        decode_names_v1_envelope, encode_names_v1_envelope, names_application_id,
        names_v1_application_descriptor, names_v1_application_key,
        validate_names_v1_core_compatibility,
    },
};
use coppice_core::{
    application::{
        APPLICATION_ENVELOPE_HEADER_LEN, APPLICATION_ID_PERSONALIZATION, ApplicationDescriptor,
        ApplicationEnvelopeError, ApplicationEnvelopeV1, ApplicationId, ApplicationKey,
        MAX_APPLICATION_ENVELOPE_LEN, derive_application_id,
    },
    identity::{CoreRuntimeId, CoreRuntimeParameters, ZcashNetwork},
    replay::{
        CoreReplay, CoreReplayActivationCheckpoint, CoreReplayConfiguration, IronwoodFrontier,
    },
    runtime::{CoreRuntime, CoreRuntimeConfigurationError},
    transport,
};
use coppice_names as coppice;
use orchard::keys::IncomingViewingKey;
use zcash_protocol::consensus::NetworkType;

fn fixed32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn alternate_rendezvous() -> ([u8; 64], [u8; 43]) {
    (
        hex::decode(
            "3c6ec816597b0ab356ec564a094ab4649a770e145bc327f1168e00b45c0c46146a0efaad6c366747a1bb45ae4bb15b4afc5d856b465757a183f104a0fb0fd318",
        )
        .unwrap()
        .try_into()
        .unwrap(),
        hex::decode(
            "6135f04526a269e5e05e2f255344256bc4f9addbc3d09e22f239fc776455468301dfcc9540c5e59dd2c983",
        )
        .unwrap()
        .try_into()
        .unwrap(),
    )
}

fn runtime_fixture() -> (serde_json::Value, CoreRuntimeParameters) {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../coppice/test-vectors/core_runtime_id.json"
    ))
    .unwrap();
    let input = &fixture["input"];
    let parameters = CoreRuntimeParameters {
        runtime_protocol_id: hex::decode(input["runtime_protocol_id_hex"].as_str().unwrap())
            .unwrap(),
        runtime_protocol_version: input["runtime_protocol_version"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        zcash_network_domain: hex::decode(input["zcash_network_domain_hex"].as_str().unwrap())
            .unwrap(),
        zcash_network: ZcashNetwork::Regtest,
        runtime_activation_height: input["runtime_activation_height"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        carrier_protocol_id: hex::decode(input["carrier_protocol_id_hex"].as_str().unwrap())
            .unwrap(),
        rendezvous_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        rendezvous_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    (fixture, parameters)
}

fn names_deployment_fixture() -> (serde_json::Value, DeploymentParameters) {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
    let input = &fixture["input"];
    let parameters = DeploymentParameters {
        network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
        address_network: NetworkType::Regtest,
        activation_height: input["activation_height"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
        commit_ttl_blocks: input["commit_ttl_blocks"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        reuse_delay_blocks: input["reuse_delay_blocks"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        bond_note_max_age_blocks: input["bond_note_max_age_blocks"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        rendezvous: Rendezvous {
            orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
    };
    (fixture, parameters)
}

#[test]
fn structurally_valid_but_unsupported_runtime_semantics_are_rejected() {
    for (field, expected) in [
        (
            "protocol",
            CoreRuntimeConfigurationError::UnsupportedRuntimeProtocol,
        ),
        (
            "version",
            CoreRuntimeConfigurationError::UnsupportedRuntimeVersion,
        ),
        (
            "carrier",
            CoreRuntimeConfigurationError::UnsupportedCarrierProtocol,
        ),
    ] {
        let (_, original) = runtime_fixture();
        let mut parameters = original;
        match field {
            "protocol" => parameters.runtime_protocol_id = b"future.runtime".to_vec(),
            "version" => parameters.runtime_protocol_version = 2,
            "carrier" => parameters.carrier_protocol_id = b"CPV2".to_vec(),
            _ => unreachable!(),
        }
        let validated = parameters.validate().unwrap();
        let replay = CoreReplay::new(
            CoreReplayConfiguration::new(10, 8).unwrap(),
            CoreReplayActivationCheckpoint {
                height: 9,
                block_hash: [9; 32],
                ironwood_frontier: IronwoodFrontier::empty(),
                ironwood_tree_size: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            CoreRuntime::new(validated, replay),
            Err(error) if error == expected
        ));
    }
}

#[test]
fn three_identity_vector_and_production_transport_binding_match() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../coppice/test-vectors/application_envelopes.json"
    ))
    .unwrap();
    let derivation = &fixture["application_id_derivation"];
    let names = &fixture["names_v1"];
    let (_, runtime_parameters) = runtime_fixture();
    let (deployment_fixture, names_parameters) = names_deployment_fixture();

    let validated_core = runtime_parameters.validate().unwrap();
    let core_runtime_id = validated_core.core_runtime_id();
    let names_deployment_id = NamesDeploymentId::from_parameters(&names_parameters).unwrap();
    assert_eq!(
        core_runtime_id,
        CoreRuntimeId::from_bytes(fixed32(names["core_runtime_id_hex"].as_str().unwrap()))
    );
    assert_eq!(
        names_deployment_id,
        NamesDeploymentId::from_bytes(fixed32(names["names_deployment_id_hex"].as_str().unwrap()))
    );
    assert_eq!(
        hex::encode(names_deployment_id.to_bytes()),
        deployment_fixture["expected_deployment_id_hex"]
            .as_str()
            .unwrap()
    );
    assert_ne!(core_runtime_id.to_bytes(), names_deployment_id.to_bytes());

    assert_eq!(
        hex::encode(APPLICATION_ID_PERSONALIZATION),
        derivation["personalization_hex"].as_str().unwrap()
    );
    assert_eq!(
        NAMES_CANONICAL_APPLICATION_IDENTITY,
        &hex::decode(
            derivation["canonical_application_identity_hex"]
                .as_str()
                .unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        names_application_id(),
        ApplicationId::from_bytes(fixed32(
            derivation["expected_application_id_hex"].as_str().unwrap()
        ))
    );
    assert_eq!(
        NAMES_V1_APPLICATION_VERSION,
        names["application_version"].as_u64().unwrap() as u16
    );

    let operation_payload = hex::decode(names["operation_payload_hex"].as_str().unwrap()).unwrap();
    let operation = envelope::decode_operation(&operation_payload).unwrap();
    let encoded = encode_names_v1_envelope(&operation).unwrap();
    assert_eq!(
        encoded,
        hex::decode(names["expected_envelope_hex"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        encoded.len(),
        names["expected_envelope_length"].as_u64().unwrap() as usize
    );
    assert_eq!(decode_names_v1_envelope(&encoded), Ok(operation));
    assert_eq!(
        MAX_APPLICATION_ENVELOPE_LEN,
        coppice_core::carrier::MAX_CPV1_PAYLOAD_LEN
    );

    let frames = transport::encode_frames(core_runtime_id.to_bytes(), &encoded).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].as_slice(),
        hex::decode(
            names["expected_production_cpv1_frame_hex"]
                .as_str()
                .unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        transport::reconstruct_frames(&frames, core_runtime_id.to_bytes()).unwrap(),
        encoded
    );
    assert_eq!(
        transport::reconstruct_frames(&frames, names_deployment_id.to_bytes()),
        Err(transport::Error::WrongRuntime)
    );

    let compatibility = validate_names_v1_core_compatibility(
        &validated_core,
        &names_parameters,
        names_v1_application_descriptor(names_parameters.activation_height),
    )
    .unwrap();
    assert_eq!(compatibility.core_runtime_id(), core_runtime_id);
    assert_eq!(compatibility.names_deployment_id(), names_deployment_id);
}

#[test]
fn core_runtime_identity_is_independent_of_names_policy_and_application_activation() {
    let envelope_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../coppice/test-vectors/application_envelopes.json"
    ))
    .unwrap();
    let (_, runtime_parameters) = runtime_fixture();
    let (_, names_parameters) = names_deployment_fixture();
    let validated_core = runtime_parameters.clone().validate().unwrap();
    let runtime_id = validated_core.core_runtime_id();
    let names_id = NamesDeploymentId::from_parameters(&names_parameters).unwrap();

    let mut mutations = Vec::new();
    let mut changed = names_parameters.clone();
    changed.minimum_bond_value += 1;
    mutations.push(changed);
    let mut changed = names_parameters.clone();
    changed.commit_ttl_blocks += 1;
    mutations.push(changed);
    let mut changed = names_parameters.clone();
    changed.reuse_delay_blocks += 1;
    mutations.push(changed);
    let mut changed = names_parameters;
    changed.bond_note_max_age_blocks += 1;
    mutations.push(changed);

    for changed in mutations {
        assert_ne!(
            NamesDeploymentId::from_parameters(&changed).unwrap(),
            names_id
        );
        assert_eq!(validated_core.core_runtime_id(), runtime_id);
    }

    let names_at_runtime =
        names_v1_application_descriptor(runtime_parameters.runtime_activation_height);
    assert_eq!(
        u64::from(names_at_runtime.activation_height),
        envelope_fixture["names_v1"]["application_activation_height"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        names_at_runtime.validate_for_runtime(runtime_parameters.runtime_activation_height),
        Ok(())
    );
    let later_application = ApplicationDescriptor {
        key: ApplicationKey::new(derive_application_id(b"example.future").unwrap(), 1),
        activation_height: runtime_parameters.runtime_activation_height + 100,
    };
    assert_eq!(
        later_application.validate_for_runtime(runtime_parameters.runtime_activation_height),
        Ok(())
    );
    assert_eq!(validated_core.core_runtime_id(), runtime_id);
}

#[test]
fn names_core_compatibility_rejects_each_shared_context_mismatch() {
    let (_, core_parameters) = runtime_fixture();
    let (_, names_parameters) = names_deployment_fixture();
    let application = names_v1_application_descriptor(names_parameters.activation_height);
    let validated_core = core_parameters.clone().validate().unwrap();
    assert!(
        validate_names_v1_core_compatibility(&validated_core, &names_parameters, application)
            .is_ok()
    );

    let mut invalid_names = names_parameters.clone();
    invalid_names.minimum_bond_value = 0;
    assert_eq!(
        validate_names_v1_core_compatibility(&validated_core, &invalid_names, application),
        Err(NamesCoreCompatibilityError::InvalidNamesDeployment(
            DeploymentValidationError::MinimumBondValue
        ))
    );

    let mut wrong_protocol = core_parameters.clone();
    wrong_protocol.runtime_protocol_version += 1;
    assert_eq!(
        validate_names_v1_core_compatibility(
            &wrong_protocol.validate().unwrap(),
            &names_parameters,
            application,
        ),
        Err(NamesCoreCompatibilityError::RuntimeProtocol)
    );

    let mut wrong_carrier = core_parameters.clone();
    wrong_carrier.carrier_protocol_id = b"CPV2".to_vec();
    assert_eq!(
        validate_names_v1_core_compatibility(
            &wrong_carrier.validate().unwrap(),
            &names_parameters,
            application,
        ),
        Err(NamesCoreCompatibilityError::CarrierProtocol)
    );

    let mut wrong_network = core_parameters.clone();
    wrong_network.zcash_network = ZcashNetwork::Test;
    assert_eq!(
        validate_names_v1_core_compatibility(
            &wrong_network.validate().unwrap(),
            &names_parameters,
            application,
        ),
        Err(NamesCoreCompatibilityError::ZcashNetwork)
    );

    let mut wrong_domain = core_parameters.clone();
    wrong_domain.zcash_network_domain.push(b'2');
    assert_eq!(
        validate_names_v1_core_compatibility(
            &wrong_domain.validate().unwrap(),
            &names_parameters,
            application,
        ),
        Err(NamesCoreCompatibilityError::ZcashNetworkDomain)
    );

    let mut unsupported_names_domain = names_parameters.clone();
    unsupported_names_domain.network_id = b"unsupported-names-domain".to_vec();
    assert_eq!(
        validate_names_v1_core_compatibility(
            &validated_core,
            &unsupported_names_domain,
            application,
        ),
        Err(NamesCoreCompatibilityError::UnsupportedNamesNetworkDomain)
    );

    let (alternate_ivk, alternate_receiver) = alternate_rendezvous();
    let mut wrong_rendezvous = core_parameters.clone();
    wrong_rendezvous.rendezvous_ivk = alternate_ivk;
    wrong_rendezvous.rendezvous_receiver = alternate_receiver;
    assert_eq!(
        validate_names_v1_core_compatibility(
            &wrong_rendezvous.validate().unwrap(),
            &names_parameters,
            application,
        ),
        Err(NamesCoreCompatibilityError::RendezvousIvk)
    );

    let ivk = Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(
        &core_parameters.rendezvous_ivk,
    ))
    .unwrap();
    let mut wrong_receiver = core_parameters.clone();
    wrong_receiver.rendezvous_receiver = ivk.address_at(1u32).to_raw_address_bytes();
    assert_ne!(
        wrong_receiver.rendezvous_receiver,
        names_parameters.rendezvous.orchard_receiver
    );
    assert_eq!(
        validate_names_v1_core_compatibility(
            &wrong_receiver.validate().unwrap(),
            &names_parameters,
            application,
        ),
        Err(NamesCoreCompatibilityError::RendezvousReceiver)
    );

    let wrong_application = ApplicationDescriptor {
        key: ApplicationKey::new(derive_application_id(b"example.other").unwrap(), 1),
        activation_height: names_parameters.activation_height,
    };
    assert_eq!(
        validate_names_v1_core_compatibility(&validated_core, &names_parameters, wrong_application,),
        Err(NamesCoreCompatibilityError::ApplicationKey)
    );

    let later_application = ApplicationDescriptor {
        key: names_v1_application_key(),
        activation_height: names_parameters.activation_height + 1,
    };
    assert_eq!(
        later_application.validate_for_runtime(core_parameters.runtime_activation_height),
        Ok(())
    );
    assert_eq!(
        validate_names_v1_core_compatibility(&validated_core, &names_parameters, later_application,),
        Err(NamesCoreCompatibilityError::ApplicationActivation)
    );

    let mut later_names = names_parameters;
    later_names.activation_height += 1;
    assert_eq!(
        validate_names_v1_core_compatibility(&validated_core, &later_names, later_application,),
        Err(NamesCoreCompatibilityError::NamesV1RuntimeActivation)
    );
}

#[test]
fn routing_is_exact_and_unknown_applications_remain_structural_envelopes() {
    let commit = Operation::Commit {
        commitment: [0x42; 32],
    };
    let encoded = encode_names_v1_envelope(&commit).unwrap();
    let decoded = ApplicationEnvelopeV1::decode(&encoded).unwrap();
    assert_eq!(decoded.key(), names_v1_application_key());
    assert_eq!(decode_names_v1_envelope(&encoded), Ok(commit));

    let unknown_id = derive_application_id(b"example.unknown").unwrap();
    let unknown = ApplicationEnvelopeV1::new(
        ApplicationKey::new(unknown_id, 1),
        decoded.payload().to_vec(),
    )
    .unwrap()
    .encode();
    assert!(ApplicationEnvelopeV1::decode(&unknown).is_ok());
    assert_eq!(
        decode_names_v1_envelope(&unknown),
        Err(NamesApplicationEnvelopeError::WrongApplication)
    );

    let unknown_version = ApplicationEnvelopeV1::new(
        ApplicationKey::new(names_application_id(), 2),
        decoded.payload().to_vec(),
    )
    .unwrap()
    .encode();
    assert!(ApplicationEnvelopeV1::decode(&unknown_version).is_ok());
    assert_eq!(
        decode_names_v1_envelope(&unknown_version),
        Err(NamesApplicationEnvelopeError::WrongApplication)
    );

    assert_eq!(
        ApplicationEnvelopeV1::decode(&encoded[..APPLICATION_ENVELOPE_HEADER_LEN - 1]),
        Err(ApplicationEnvelopeError::TooShort)
    );
    let mut wrong_magic = encoded;
    wrong_magic[3] ^= 1;
    assert_eq!(
        ApplicationEnvelopeV1::decode(&wrong_magic),
        Err(ApplicationEnvelopeError::WrongMagic)
    );
}
