//! Canonical Names v1 payment-record profile.
//!
//! Names state records remain opaque bounded application bytes. This optional
//! profile gives wallet hosts a strict way to encode a shielded Unified
//! Address without making Coppice Core parse addresses or changing Names
//! transition semantics.

use super::state::MAX_RECORD_BYTES;
use serde::{Deserialize, Serialize};
use zcash_address::unified::{self, Container, Encoding, Receiver};

pub const PAYMENT_RECORD_MAGIC: [u8; 4] = *b"N1UA";
pub const PAYMENT_RECORD_VERSION: u8 = 1;
pub const PAYMENT_RECORD_HEADER_LEN: usize = 4 + 1 + 1 + 2;

/// Errors from the wallet-facing Unified Address record profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentRecordError {
    InvalidEncoding,
    NonCanonicalEncoding,
    WrongNetwork,
    NotUnified,
    NoShieldedReceiver,
    TooLong,
    InvalidFraming,
    UnsupportedVersion,
}

/// A canonical, network-bound shielded Unified Address record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRecord {
    network: PaymentNetwork,
    address: String,
}

/// Stable network discriminant used only inside the application record
/// framing. It deliberately does not rely on Rust enum discriminants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentNetwork {
    Main,
    Test,
    Regtest,
}

impl PaymentNetwork {
    const fn code(self) -> u8 {
        match self {
            Self::Main => 0,
            Self::Test => 1,
            Self::Regtest => 2,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Main),
            1 => Some(Self::Test),
            2 => Some(Self::Regtest),
            _ => None,
        }
    }

    fn matches_address(self, address: &str) -> bool {
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

impl PaymentRecord {
    /// Validates and canonicalizes one shielded Unified Address for `network`.
    pub fn new(network: PaymentNetwork, address: &str) -> Result<Self, PaymentRecordError> {
        if !network.matches_address(address) {
            return Err(PaymentRecordError::WrongNetwork);
        }
        let (parsed_network, ua) =
            unified::Address::decode(address).map_err(|error| match error {
                unified::ParseError::NotUnified | unified::ParseError::UnknownPrefix(_) => {
                    PaymentRecordError::NotUnified
                }
                _ => PaymentRecordError::InvalidEncoding,
            })?;
        if ua.encode(&parsed_network) != address {
            return Err(PaymentRecordError::NonCanonicalEncoding);
        }
        if !ua
            .items()
            .iter()
            .any(|receiver| matches!(receiver, Receiver::Orchard(_) | Receiver::Sapling(_)))
        {
            return Err(PaymentRecordError::NoShieldedReceiver);
        }
        let record = Self {
            network,
            address: address.to_owned(),
        };
        if record.encode().len() > MAX_RECORD_BYTES {
            return Err(PaymentRecordError::TooLong);
        }
        Ok(record)
    }

    pub const fn network(&self) -> PaymentNetwork {
        self.network
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// Encodes the record as bounded canonical application bytes.
    pub fn encode(&self) -> Vec<u8> {
        let address = self.address.as_bytes();
        let length = u16::try_from(address.len()).expect("validated UA fits u16");
        let mut bytes = Vec::with_capacity(PAYMENT_RECORD_HEADER_LEN + address.len());
        bytes.extend_from_slice(&PAYMENT_RECORD_MAGIC);
        bytes.push(PAYMENT_RECORD_VERSION);
        bytes.push(self.network.code());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(address);
        bytes
    }

    /// Decodes and revalidates a record for the wallet's expected network.
    pub fn decode(
        bytes: &[u8],
        expected_network: PaymentNetwork,
    ) -> Result<Self, PaymentRecordError> {
        if bytes.len() < PAYMENT_RECORD_HEADER_LEN {
            return Err(PaymentRecordError::InvalidFraming);
        }
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(PaymentRecordError::TooLong);
        }
        if bytes[..4] != PAYMENT_RECORD_MAGIC {
            return Err(PaymentRecordError::InvalidFraming);
        }
        if bytes[4] != PAYMENT_RECORD_VERSION {
            return Err(PaymentRecordError::UnsupportedVersion);
        }
        let network =
            PaymentNetwork::from_code(bytes[5]).ok_or(PaymentRecordError::InvalidFraming)?;
        if network != expected_network {
            return Err(PaymentRecordError::WrongNetwork);
        }
        let address_len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
        if bytes.len() != PAYMENT_RECORD_HEADER_LEN + address_len {
            return Err(PaymentRecordError::InvalidFraming);
        }
        let address = core::str::from_utf8(&bytes[PAYMENT_RECORD_HEADER_LEN..])
            .map_err(|_| PaymentRecordError::InvalidEncoding)?;
        let record = Self::new(expected_network, address)?;
        if record.network != network {
            return Err(PaymentRecordError::WrongNetwork);
        }
        Ok(record)
    }
}

#[cfg(test)]
#[path = "tests/payment.rs"]
mod tests;
