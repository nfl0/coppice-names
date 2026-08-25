//! Deterministic canonical v1 owner-key derivation (P-OWNER-002).

use crate::owner::{OwnerSigningKey, OwnerVerificationKey};
use blake2b_simd::Params;
use pasta_curves::{
    group::ff::{Field, FromUniformBytes, PrimeField},
    pallas,
};

const PERSONALIZATION: &[u8; 16] = b"CoppiceOwnerKDF1";
const ZERO_SALT: [u8; 16] = [0; 16];
const MESSAGE_LEN: usize = 100;
const OKM_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerKdfError {
    CounterOverflow,
    InvalidSigningKey,
}

fn kdf_message(
    deployment_id: [u8; 32],
    name_id: [u8; 32],
    bond_tag: [u8; 32],
    counter: u32,
) -> [u8; MESSAGE_LEN] {
    let mut message = [0; MESSAGE_LEN];
    message[..32].copy_from_slice(&deployment_id);
    message[32..64].copy_from_slice(&name_id);
    message[64..96].copy_from_slice(&bond_tag);
    message[96..].copy_from_slice(&counter.to_be_bytes());
    message
}

fn keyed_blake2b512(
    orchard_account_spending_key_bytes: &[u8; 32],
    message: &[u8; MESSAGE_LEN],
) -> [u8; OKM_LEN] {
    Params::new()
        .hash_length(OKM_LEN)
        .key(orchard_account_spending_key_bytes)
        .salt(&ZERO_SALT)
        .personal(PERSONALIZATION)
        .fanout(1)
        .max_depth(1)
        .hash(message)
        .as_bytes()
        .try_into()
        .expect("fixed BLAKE2b-512 output length")
}

fn derive_nonzero_scalar(
    start_counter: u32,
    mut scalar_at: impl FnMut(u32) -> pallas::Scalar,
) -> Result<pallas::Scalar, OwnerKdfError> {
    let mut counter = start_counter;
    loop {
        let scalar = scalar_at(counter);
        if !bool::from(scalar.is_zero()) {
            return Ok(scalar);
        }
        counter = counter
            .checked_add(1)
            .ok_or(OwnerKdfError::CounterOverflow)?;
    }
}

pub fn derive_v1_owner_signing_key(
    orchard_account_spending_key_bytes: [u8; 32],
    deployment_id: [u8; 32],
    name_id: [u8; 32],
    bond_tag: [u8; 32],
) -> Result<OwnerSigningKey, OwnerKdfError> {
    let scalar = derive_nonzero_scalar(0, |counter| {
        let message = kdf_message(deployment_id, name_id, bond_tag, counter);
        let okm = keyed_blake2b512(&orchard_account_spending_key_bytes, &message);
        pallas::Scalar::from_uniform_bytes(&okm)
    })?;
    OwnerSigningKey::try_from(scalar.to_repr()).map_err(|_| OwnerKdfError::InvalidSigningKey)
}

pub fn derive_v1_owner_verification_key(
    orchard_account_spending_key_bytes: [u8; 32],
    deployment_id: [u8; 32],
    name_id: [u8; 32],
    bond_tag: [u8; 32],
) -> Result<OwnerVerificationKey, OwnerKdfError> {
    derive_v1_owner_signing_key(
        orchard_account_spending_key_bytes,
        deployment_id,
        name_id,
        bond_tag,
    )
    .map(|signing_key| (&signing_key).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::owner_key_bytes;
    use serde_json::Value;

    fn fixed<const N: usize>(value: &Value, field: &str) -> [u8; N] {
        hex::decode(value[field].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn vector() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/owner_keys.json")).unwrap()
    }

    #[test]
    fn full_owner_key_vector_matches_p_owner_002() {
        let fixture = vector();
        assert_eq!(fixture["status"], "FROZEN_COMPLETE");
        let vector = &fixture["vector"];
        let orchard_key = fixed::<32>(vector, "orchard_spending_key_hex");
        let deployment_id = fixed::<32>(vector, "deployment_id_hex");
        let name_id = fixed::<32>(vector, "name_id_hex");
        let bond_tag = fixed::<32>(vector, "bond_tag_hex");
        let counter = vector["counter"].as_u64().unwrap() as u32;

        let message = kdf_message(deployment_id, name_id, bond_tag, counter);
        assert_eq!(message.len(), 100);
        assert_eq!(message, fixed::<100>(vector, "kdf_message_hex"));

        let okm = keyed_blake2b512(&orchard_key, &message);
        assert_eq!(okm.len(), 64);
        assert_eq!(okm, fixed::<64>(vector, "blake2b512_okm_hex"));

        let scalar = pallas::Scalar::from_uniform_bytes(&okm);
        assert!(!bool::from(scalar.is_zero()));
        assert_eq!(
            scalar.to_repr(),
            fixed::<32>(vector, "expected_pallas_scalar_hex")
        );

        let signing_key =
            derive_v1_owner_signing_key(orchard_key, deployment_id, name_id, bond_tag).unwrap();
        let verification_key: OwnerVerificationKey = (&signing_key).into();
        assert_eq!(
            owner_key_bytes(&verification_key),
            fixed::<32>(vector, "expected_redpallas_verification_key_hex")
        );
    }

    #[test]
    fn message_counter_is_big_endian() {
        let deployment_id = [1; 32];
        let name_id = [2; 32];
        let bond_tag = [3; 32];
        assert_eq!(
            &kdf_message(deployment_id, name_id, bond_tag, 0)[96..],
            &[0, 0, 0, 0]
        );
        assert_eq!(
            &kdf_message(deployment_id, name_id, bond_tag, 1)[96..],
            &[0, 0, 0, 1]
        );
        assert_eq!(
            &kdf_message(deployment_id, name_id, bond_tag, 0x0102_0304)[96..],
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn keyed_blake2b512_vector_matches_independently() {
        let fixture = vector();
        let vector = &fixture["vector"];
        let orchard_key = fixed::<32>(vector, "orchard_spending_key_hex");
        let message = fixed::<100>(vector, "kdf_message_hex");
        assert_eq!(
            keyed_blake2b512(&orchard_key, &message),
            fixed::<64>(vector, "blake2b512_okm_hex")
        );
    }

    #[test]
    fn derivation_is_deterministic_and_domain_sensitive() {
        let fixture = vector();
        let vector = &fixture["vector"];
        let orchard_key = fixed::<32>(vector, "orchard_spending_key_hex");
        let deployment_id = fixed::<32>(vector, "deployment_id_hex");
        let name_id = fixed::<32>(vector, "name_id_hex");
        let bond_tag = fixed::<32>(vector, "bond_tag_hex");
        let derive = |deployment_id, name_id, bond_tag| {
            owner_key_bytes(
                &derive_v1_owner_verification_key(orchard_key, deployment_id, name_id, bond_tag)
                    .unwrap(),
            )
        };

        let expected = derive(deployment_id, name_id, bond_tag);
        assert_eq!(derive(deployment_id, name_id, bond_tag), expected);
        let mut changed_deployment = deployment_id;
        changed_deployment[0] ^= 1;
        assert_ne!(derive(changed_deployment, name_id, bond_tag), expected);
        let mut changed_name = name_id;
        changed_name[0] ^= 1;
        assert_ne!(derive(deployment_id, changed_name, bond_tag), expected);
        let mut changed_bond = bond_tag;
        changed_bond[0] ^= 1;
        assert_ne!(derive(deployment_id, name_id, changed_bond), expected);
    }

    #[test]
    fn zero_scalar_retries_with_checked_counter() {
        let mut attempted = Vec::new();
        let scalar = derive_nonzero_scalar(0, |counter| {
            attempted.push(counter);
            if counter == 0 {
                pallas::Scalar::zero()
            } else {
                pallas::Scalar::one()
            }
        })
        .unwrap();
        assert_eq!(attempted, vec![0, 1]);
        assert_eq!(scalar, pallas::Scalar::one());

        let mut overflow_attempted = Vec::new();
        assert_eq!(
            derive_nonzero_scalar(u32::MAX, |counter| {
                overflow_attempted.push(counter);
                pallas::Scalar::zero()
            }),
            Err(OwnerKdfError::CounterOverflow)
        );
        assert_eq!(overflow_attempted, vec![u32::MAX]);
    }
}
