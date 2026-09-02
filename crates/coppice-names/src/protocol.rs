//! Canonical Coppice Names protocol values.

use pasta_curves::{
    group::ff::{FromUniformBytes, PrimeField},
    pallas,
};
use serde::{Deserialize, Serialize};
use zcash_address::unified::{self, Encoding};

/// Maximum canonical bare-name length.
pub const MAX_NAME_BYTES: usize = 63;
/// Maximum canonical Unified Address length.
pub const MAX_UA_BYTES: usize = 1024;
/// Exact Names bond in zatoshis.
pub const BOND_ZATOSHIS: u64 = 100_000_000;

/// Zcash network used to validate a stored Unified Address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl Network {
    fn matches_hrp(self, address: &str) -> bool {
        let hrp = match self {
            Self::Main => "u",
            Self::Test => "utest",
            Self::Regtest => "uregtest",
        };
        address
            .strip_prefix(hrp)
            .is_some_and(|suffix| suffix.starts_with('1'))
    }
}

/// Canonical value-construction error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueError {
    InvalidName,
    InvalidField,
    ZeroField,
    InvalidUa,
    NonCanonicalUa,
    WrongNetwork,
    UaTooLong,
    HashToFieldExhausted,
}

/// A validated canonical bare `.zec` label.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    /// Accepts a bare name or one lowercase `.zec` suffix.
    pub fn parse(value: &str) -> Result<Self, ValueError> {
        let bare = value.strip_suffix(".zec").unwrap_or(value);
        let bytes = bare.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_NAME_BYTES
            || !bare.is_ascii()
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(ValueError::InvalidName);
        }
        Ok(Self(bare.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Computes the nonzero canonical Pallas name identifier.
    pub fn id(&self) -> Result<NameId, ValueError> {
        for counter in 0..=u8::MAX {
            let mut input = Vec::with_capacity(self.0.len() + 2);
            input.push(u8::try_from(self.0.len()).expect("name length is bounded"));
            input.extend_from_slice(self.0.as_bytes());
            input.push(counter);
            let candidate = wide_field(b"CoppiceN2Name", &input);
            if candidate != pallas::Base::zero() {
                return Ok(NameId(candidate.to_repr()));
            }
        }
        Err(ValueError::HashToFieldExhausted)
    }
}

/// Nonzero canonical Pallas name identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameId([u8; 32]);

impl NameId {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ValueError> {
        let field = canonical_field(bytes)?;
        if field == pallas::Base::zero() {
            return Err(ValueError::ZeroField);
        }
        Ok(Self(bytes))
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn field(self) -> pallas::Base {
        canonical_field(self.0).expect("NameId is canonical")
    }
}

/// A nonzero canonical Pallas COMMIT value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment([u8; 32]);

impl Commitment {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ValueError> {
        let field = canonical_field(bytes)?;
        if field == pallas::Base::zero() {
            return Err(ValueError::ZeroField);
        }
        Ok(Self(bytes))
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn field(self) -> pallas::Base {
        canonical_field(self.0).expect("Commitment is canonical")
    }
}

/// Canonical Pallas field encoding used for nullifiers and commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement([u8; 32]);

impl FieldElement {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ValueError> {
        canonical_field(bytes)?;
        Ok(Self(bytes))
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn field(self) -> pallas::Base {
        canonical_field(self.0).expect("FieldElement is canonical")
    }
}

/// A canonical ZIP-316 Unified Address for one deployment network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalUa(String);

impl CanonicalUa {
    pub fn parse(network: Network, value: &str) -> Result<Self, ValueError> {
        if value.is_empty() || value.len() > MAX_UA_BYTES {
            return Err(ValueError::UaTooLong);
        }
        if !network.matches_hrp(value) {
            return Err(ValueError::WrongNetwork);
        }
        let (parsed_network, address) =
            unified::Address::decode(value).map_err(|_| ValueError::InvalidUa)?;
        if address.encode(&parsed_network) != value {
            return Err(ValueError::NonCanonicalUa);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Exact canonical transaction position of a COMMIT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitRef {
    pub height: u32,
    pub tx_index: u32,
    pub txid: [u8; 32],
}

/// Exact canonical action position of a state head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StateRef {
    pub height: u32,
    pub tx_index: u32,
    pub txid: [u8; 32],
    pub action_index: u32,
}

pub(crate) fn canonical_field(bytes: [u8; 32]) -> Result<pallas::Base, ValueError> {
    Option::<pallas::Base>::from(pallas::Base::from_repr(bytes)).ok_or(ValueError::InvalidField)
}

pub(crate) fn wide_field(personalization: &[u8], input: &[u8]) -> pallas::Base {
    assert!(
        personalization.len() <= 16,
        "hash personalization is bounded"
    );
    let digest = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(personalization)
        .hash(input);
    let mut wide = [0; 64];
    wide.copy_from_slice(digest.as_bytes());
    pallas::Base::from_uniform_bytes(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_grammar_and_identifier_are_canonical() {
        let name = Name::parse("alice.zec").unwrap();
        assert_eq!(name.as_str(), "alice");
        assert_eq!(
            hex::encode(name.id().unwrap().to_bytes()),
            "b646f07d05366fb8127c706843da84c62e42eec3ba2e66af0188c20d0093710a"
        );
        for invalid in [
            "",
            ".zec",
            "Alice",
            "alice.ZEC",
            "-alice",
            "alice-",
            "a.b",
            "é",
        ] {
            assert_eq!(Name::parse(invalid), Err(ValueError::InvalidName));
        }
    }

    #[test]
    fn field_wrappers_reject_noncanonical_and_required_zero() {
        assert_eq!(Commitment::from_bytes([0; 32]), Err(ValueError::ZeroField));
        assert_eq!(NameId::from_bytes([0; 32]), Err(ValueError::ZeroField));
        assert!(FieldElement::from_bytes([0; 32]).is_ok());
        assert_eq!(
            FieldElement::from_bytes([0xff; 32]),
            Err(ValueError::InvalidField)
        );
    }
}
