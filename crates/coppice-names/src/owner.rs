//! Canonical RedPallas owner keys used by Coppice protocol and wallet flows.
use crate::crypto;
use orchard::primitives::redpallas::{SigningKey, SpendAuth, VerificationKey};

pub type OwnerSigningKey = SigningKey<SpendAuth>;
pub type OwnerVerificationKey = VerificationKey<SpendAuth>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerKeyError;

/// Parses the canonical v1 owner key and enforces P-OWNER-001's non-identity rule.
pub fn parse_v1_owner_key(bytes: [u8; 32]) -> Result<OwnerVerificationKey, OwnerKeyError> {
    let key = OwnerVerificationKey::try_from(bytes).map_err(|_| OwnerKeyError)?;
    if key.is_identity() {
        return Err(OwnerKeyError);
    }
    Ok(key)
}
pub fn owner_key_bytes(key: &OwnerVerificationKey) -> [u8; 32] {
    key.into()
}
pub fn name_id(name: &str) -> [u8; 32] {
    let canonical = crate::envelope::strip_presentation_suffix(name);
    crypto::hash("CoppiceNameV1", canonical.as_bytes()).expect("fixed v1 name hash label")
}

#[cfg(test)]
mod name_vectors {
    use super::*;

    #[test]
    fn p_name_001_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/names.json")).unwrap();

        for vector in fixture["vectors"].as_array().unwrap() {
            let name = vector["input_utf8"].as_str().unwrap();
            let valid = vector["valid"].as_bool().unwrap();
            assert_eq!(crate::envelope::valid_name(name), valid, "{name:?}");

            if valid {
                let expected: [u8; 32] =
                    hex::decode(vector["expected_name_id_hex"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap();
                assert_eq!(name_id(name), expected, "{name:?}");
            }
        }
    }

    #[test]
    fn v1_owner_parser_rejects_identity_and_malformed_encodings() {
        let identity = [0; 32];
        assert_eq!(parse_v1_owner_key(identity), Err(OwnerKeyError));

        let signing_key = OwnerSigningKey::try_from([1; 32]).unwrap();
        let valid = owner_key_bytes(&(&signing_key).into());
        assert_eq!(owner_key_bytes(&parse_v1_owner_key(valid).unwrap()), valid);
        assert_eq!(parse_v1_owner_key([0xff; 32]), Err(OwnerKeyError));
    }

    #[test]
    fn presentation_suffix_does_not_change_name_id() {
        assert_eq!(name_id("alice"), name_id("alice.zec"));
    }
}
