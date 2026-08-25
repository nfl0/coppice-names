use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameStatus {
    Active,
    Released { terminal_height: u32 },
    BondSpent { terminal_height: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub owner_pk: [u8; 32],
    pub bond_tag: [u8; 32],
    pub sequence: u64,
    pub address: Vec<u8>,
    pub status: NameStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordEncodingError {
    AddressTooLong,
    InvalidTerminalHeight,
    Hash(crypto::Error),
}

pub fn canonical_record_bytes(record: &NameRecord) -> Result<Vec<u8>, RecordEncodingError> {
    let (status, terminal_height) = match record.status {
        NameStatus::Active => (0x01, 0),
        NameStatus::Released { terminal_height } => {
            if terminal_height == 0 {
                return Err(RecordEncodingError::InvalidTerminalHeight);
            }
            (0x02, terminal_height)
        }
        NameStatus::BondSpent { terminal_height } => {
            if terminal_height == 0 {
                return Err(RecordEncodingError::InvalidTerminalHeight);
            }
            (0x03, terminal_height)
        }
    };
    let address_len =
        u16::try_from(record.address.len()).map_err(|_| RecordEncodingError::AddressTooLong)?;

    let mut bytes = Vec::with_capacity(32 + 32 + 8 + 1 + 4 + 2 + record.address.len());
    bytes.extend_from_slice(&record.owner_pk);
    bytes.extend_from_slice(&record.bond_tag);
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.push(status);
    bytes.extend_from_slice(&terminal_height.to_be_bytes());
    bytes.extend_from_slice(&address_len.to_be_bytes());
    bytes.extend_from_slice(&record.address);
    Ok(bytes)
}

pub fn record_hash(record: &NameRecord) -> Result<[u8; 32], RecordEncodingError> {
    let bytes = canonical_record_bytes(record)?;
    crypto::hash("CoppiceRecordV1", &bytes).map_err(RecordEncodingError::Hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/records.json")).unwrap()
    }

    fn fixture_record(id: &str, status: &str) -> NameRecord {
        let (sequence, address, name_status) = match (id, status) {
            ("active", "Active") => (
                0,
                b"u1synthetic-conformance-address".to_vec(),
                NameStatus::Active,
            ),
            ("released", "Released") => (
                1,
                b"u1synthetic-new-address".to_vec(),
                NameStatus::Released {
                    terminal_height: 200,
                },
            ),
            ("bond-spent", "BondSpent") => (
                2,
                b"u1synthetic-new-address".to_vec(),
                NameStatus::BondSpent {
                    terminal_height: 205,
                },
            ),
            _ => panic!("unknown record fixture {id}/{status}"),
        };

        NameRecord {
            owner_pk: core::array::from_fn(|index| index as u8),
            bond_tag: [0x42; 32],
            sequence,
            address,
            status: name_status,
        }
    }

    #[test]
    fn records_json_vectors_match() {
        let fixture = fixture();
        for vector in fixture["vectors"].as_array().unwrap() {
            let id = vector["id"].as_str().unwrap();
            let status = vector["status"].as_str().unwrap();
            let record = fixture_record(id, status);
            let expected_bytes = hex::decode(vector["record_bytes_hex"].as_str().unwrap()).unwrap();
            let expected_hash: [u8; 32] = hex::decode(vector["record_hash_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();

            assert_eq!(
                canonical_record_bytes(&record).unwrap(),
                expected_bytes,
                "{id} bytes"
            );
            assert_eq!(record_hash(&record).unwrap(), expected_hash, "{id} hash");
        }
    }

    #[test]
    fn record_encoding_rejects_invalid_terminal_heights_and_lengths() {
        let released = NameRecord {
            owner_pk: [0; 32],
            bond_tag: [0; 32],
            sequence: 0,
            address: Vec::new(),
            status: NameStatus::Released { terminal_height: 0 },
        };
        assert_eq!(
            canonical_record_bytes(&released),
            Err(RecordEncodingError::InvalidTerminalHeight)
        );

        let oversized = NameRecord {
            owner_pk: [0; 32],
            bond_tag: [0; 32],
            sequence: 0,
            address: vec![0; usize::from(u16::MAX) + 1],
            status: NameStatus::Active,
        };
        assert_eq!(
            canonical_record_bytes(&oversized),
            Err(RecordEncodingError::AddressTooLong)
        );
    }
}
