//! Canonical v1 bond-tag derivation.

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{group::ff::PrimeField, pallas};

pub const V1_BOND_TAG_DOMAIN: &[u8; 16] = b"CoppiceBondTagV1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondTagError {
    NonCanonicalNullifier,
}

pub fn v1_bond_tag_domain_field() -> pallas::Base {
    pallas::Base::from_u128(u128::from_le_bytes(*V1_BOND_TAG_DOMAIN))
}

pub fn derive_v1_bond_tag(canonical_nullifier: &[u8; 32]) -> Result<[u8; 32], BondTagError> {
    let nullifier_field =
        Option::<pallas::Base>::from(pallas::Base::from_repr(*canonical_nullifier))
            .ok_or(BondTagError::NonCanonicalNullifier)?;
    let tag = Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
        .hash([v1_bond_tag_domain_field(), nullifier_field]);
    Ok(tag.to_repr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bond_tags_json_matches_p_bond_003() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/bond_tags.json")).unwrap();
        let nullifier: [u8; 32] = hex::decode(vector["canonical_nullifier"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let approved_expected = "0cd5d62fa9800fe80473a8053314aee0cbf17dcb1e30f1c880f4f660c989050d";
        assert_eq!(vector["poseidon_bond_tag"], approved_expected);
        assert_eq!(
            hex::encode(derive_v1_bond_tag(&nullifier).unwrap()),
            approved_expected
        );
    }

    #[test]
    fn rejects_noncanonical_nullifier_encoding() {
        assert_eq!(
            derive_v1_bond_tag(&[0xff; 32]),
            Err(BondTagError::NonCanonicalNullifier)
        );
    }
}
