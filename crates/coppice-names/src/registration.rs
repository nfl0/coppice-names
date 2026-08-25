use crate::{
    config::{DeploymentEncodingError, DeploymentParameters},
    crypto,
};

/// Computes the v1 digest of the serialized Unified Address bytes.
pub fn address_digest(address: &[u8]) -> [u8; 32] {
    crypto::hash("CoppiceAddrV1", address).expect("fixed v1 address digest label")
}

/// Computes the v1 semantic registration commitment.
pub fn registration_commitment(
    deployment: &DeploymentParameters,
    name: &str,
    owner_pk: [u8; 32],
    bond_tag: [u8; 32],
    address: &[u8],
    secret: [u8; 32],
) -> Result<[u8; 32], DeploymentEncodingError> {
    let deployment_id = deployment.deployment_id()?;
    let name_id = crate::owner::name_id(name);
    let address_digest = address_digest(address);

    let mut preimage = Vec::with_capacity(32 * 6);
    preimage.extend_from_slice(&deployment_id);
    preimage.extend_from_slice(&name_id);
    preimage.extend_from_slice(&owner_pk);
    preimage.extend_from_slice(&bond_tag);
    preimage.extend_from_slice(&address_digest);
    preimage.extend_from_slice(&secret);

    crypto::hash("CoppiceCommitV1", &preimage).map_err(DeploymentEncodingError::Hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Rendezvous,
        envelope::{Operation, decode_operation, encode_operation},
    };
    use serde_json::Value;
    use zcash_protocol::consensus::NetworkType;

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn vector<'a>(fixture: &'a Value, id: &str) -> &'a Value {
        fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["id"].as_str() == Some(id))
            .unwrap()
    }

    fn expected_bytes(fixture: &Value, id: &str) -> Vec<u8> {
        hex::decode(vector(fixture, id)["expected_hex"].as_str().unwrap()).unwrap()
    }

    fn deployment_parameters_from_fixture() -> DeploymentParameters {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let input = &fixture["input"];

        DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: match input["network_type"].as_str().unwrap() {
                "Main" => NetworkType::Main,
                "Test" => NetworkType::Test,
                "Regtest" => NetworkType::Regtest,
                other => panic!("unknown network type {other}"),
            },
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
        }
    }

    fn reveal_from_fixture(fixture: &Value) -> Operation {
        decode_operation(&expected_bytes(fixture, "reveal")).unwrap()
    }

    fn commitment_from_reveal_semantics(
        deployment: &DeploymentParameters,
        operation: &Operation,
    ) -> [u8; 32] {
        let Operation::Reveal {
            name,
            owner_pk,
            bond_tag,
            address,
            secret,
            ..
        } = operation
        else {
            panic!("expected reveal operation");
        };

        registration_commitment(deployment, name, *owner_pk, *bond_tag, address, *secret).unwrap()
    }

    #[test]
    fn registration_vectors_match_v1_oracles() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../test-vectors/operations.json")).unwrap();
        let deployment = deployment_parameters_from_fixture();
        assert_eq!(
            deployment.deployment_id().unwrap(),
            fixed32("0f769b29c0ed5c5f9a101300e15c846ca15aeae2198043da3e785f839a56f5d7")
        );

        let reveal = reveal_from_fixture(&fixture);
        let Operation::Reveal {
            name,
            owner_pk,
            bond_tag,
            address,
            secret,
            ..
        } = &reveal
        else {
            panic!("expected reveal operation");
        };
        assert_eq!(name, "alice");
        assert_eq!(
            owner_pk,
            &fixed32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
        assert_eq!(bond_tag, &[0x42; 32]);
        assert_eq!(address.as_slice(), b"u1synthetic-conformance-address");
        assert_eq!(secret, &[0xa5; 32]);

        assert_eq!(
            address_digest(address),
            fixed32(
                vector(&fixture, "registration-commitment")["address_digest_hex"]
                    .as_str()
                    .unwrap()
            )
        );
        let commitment = commitment_from_reveal_semantics(&deployment, &reveal);
        assert_eq!(
            commitment,
            fixed32(
                vector(&fixture, "registration-commitment")["expected_commitment_hex"]
                    .as_str()
                    .unwrap()
            )
        );
        assert_eq!(
            commitment,
            registration_commitment(
                &deployment,
                "alice.zec",
                *owner_pk,
                *bond_tag,
                address,
                *secret,
            )
            .unwrap()
        );

        assert_eq!(
            encode_operation(&Operation::Commit { commitment }).unwrap(),
            expected_bytes(&fixture, "commit")
        );
    }

    #[test]
    fn reveal_proof_artifacts_do_not_affect_v1_commitment() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../test-vectors/operations.json")).unwrap();
        let deployment = deployment_parameters_from_fixture();
        let reveal = reveal_from_fixture(&fixture);
        let mut changed_artifacts = reveal.clone();
        let Operation::Reveal {
            bond_anchor_height,
            bond_anchor,
            bond_proof,
            ..
        } = &mut changed_artifacts
        else {
            panic!("expected reveal operation");
        };
        *bond_anchor_height += 1;
        *bond_anchor = [0x22; 32];
        *bond_proof = vec![0xee; 23];

        assert_ne!(reveal, changed_artifacts);
        assert_eq!(
            commitment_from_reveal_semantics(&deployment, &reveal),
            commitment_from_reveal_semantics(&deployment, &changed_artifacts)
        );
    }
}
