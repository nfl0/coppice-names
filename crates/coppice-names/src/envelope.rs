use crate::constants;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Commit {
        commitment: [u8; 32],
    },
    Reveal {
        name: String,
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
        bond_anchor_height: u32,
        bond_anchor: [u8; 32],
        bond_proof: Vec<u8>,
        address: Vec<u8>,
        secret: [u8; 32],
    },
    Update {
        name: String,
        sequence: u64,
        address: Vec<u8>,
        signature: Vec<u8>,
    },
    Release {
        name: String,
        sequence: u64,
        signature: Vec<u8>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Length,
    Name,
    Trailing,
}

/// The wallet/frontend presentation suffix for a canonical Coppice name.
///
/// This is deliberately not part of the protocol name grammar or any
/// serialized Coppice value. Callers that accept user-facing names should
/// strip it with `normalize_name` before entering protocol state.
pub const PRESENTATION_SUFFIX: &str = ".zec";

pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= constants::MAX_NAME_LEN
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Removes the optional presentation suffix without otherwise changing the
/// supplied bytes.
pub fn strip_presentation_suffix(name: &str) -> &str {
    name.strip_suffix(PRESENTATION_SUFFIX).unwrap_or(name)
}

/// Converts a wallet/frontend name into the canonical bare protocol label.
///
/// Coppice v1 performs no case folding or Unicode normalization. The only
/// presentation conversion is removal of one terminal `.zec` suffix before
/// applying the existing canonical-name rules.
pub fn normalize_name(name: &str) -> Result<String, Error> {
    let canonical = strip_presentation_suffix(name);
    if valid_name(canonical) {
        Ok(canonical.to_owned())
    } else {
        Err(Error::Name)
    }
}

/// Formats a canonical bare name for wallet/frontend presentation.
pub fn display_name(canonical_name: &str) -> String {
    format!("{canonical_name}{PRESENTATION_SUFFIX}")
}

fn put_len(out: &mut Vec<u8>, n: usize) -> Result<(), Error> {
    let n = u16::try_from(n).map_err(|_| Error::Length)?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

fn put_name(out: &mut Vec<u8>, name: &str) -> Result<(), Error> {
    let canonical = normalize_name(name)?;
    put_len(out, canonical.len())?;
    out.extend_from_slice(canonical.as_bytes());
    Ok(())
}

fn take<'a>(p: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    if p.len() < n {
        return Err(Error::Malformed);
    }
    let (a, b) = p.split_at(n);
    *p = b;
    Ok(a)
}
fn take_len_limited(p: &mut &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let n = u16::from_be_bytes(take(p, 2)?.try_into().map_err(|_| Error::Malformed)?) as usize;
    if n > limit {
        return Err(Error::Length);
    }
    Ok(take(p, n)?.to_vec())
}
pub fn encode_operation(op: &Operation) -> Result<Vec<u8>, Error> {
    let mut o = Vec::new();
    match op {
        Operation::Commit { commitment } => {
            o.push(1);
            o.extend_from_slice(commitment);
        }
        Operation::Reveal {
            name,
            owner_pk,
            bond_tag,
            bond_anchor_height,
            bond_anchor,
            bond_proof,
            address,
            secret,
        } => {
            if address.len() > constants::MAX_ADDRESS_LEN
                || bond_proof.len() > constants::MAX_BOND_PROOF_LEN
            {
                return Err(Error::Length);
            }
            o.push(2);
            put_name(&mut o, name)?;
            o.extend_from_slice(owner_pk);
            o.extend_from_slice(bond_tag);
            o.extend_from_slice(&bond_anchor_height.to_be_bytes());
            o.extend_from_slice(bond_anchor);
            o.extend_from_slice(secret);
            put_len(&mut o, bond_proof.len())?;
            o.extend_from_slice(bond_proof);
            put_len(&mut o, address.len())?;
            o.extend_from_slice(address)
        }
        Operation::Update {
            name,
            sequence,
            address,
            signature,
        } => {
            if address.len() > constants::MAX_ADDRESS_LEN {
                return Err(Error::Length);
            }
            o.push(3);
            put_name(&mut o, name)?;
            o.extend_from_slice(&sequence.to_be_bytes());
            put_len(&mut o, address.len())?;
            o.extend_from_slice(address);
            if signature.len() != 64 {
                return Err(Error::Malformed);
            }
            o.extend_from_slice(signature)
        }
        Operation::Release {
            name,
            sequence,
            signature,
        } => {
            if signature.len() != 64 {
                return Err(Error::Malformed);
            }
            o.push(4);
            put_name(&mut o, name)?;
            o.extend_from_slice(&sequence.to_be_bytes());
            o.extend_from_slice(signature)
        }
    }
    if o.len() > coppice_core::carrier::MAX_CPV1_PAYLOAD_LEN {
        return Err(Error::Length);
    }
    Ok(o)
}
pub fn decode_operation(mut p: &[u8]) -> Result<Operation, Error> {
    if p.len() > coppice_core::carrier::MAX_CPV1_PAYLOAD_LEN {
        return Err(Error::Length);
    }
    let ty = *take(&mut p, 1)?.first().ok_or(Error::Malformed)?;
    let op = match ty {
        1 => Operation::Commit {
            commitment: take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?,
        },
        2 => {
            let name = take_name(&mut p)?;
            let k: [u8; 32] = take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?;
            Operation::Reveal {
                name,
                owner_pk: k,
                bond_tag: take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?,
                bond_anchor_height: u32::from_be_bytes(
                    take(&mut p, 4)?.try_into().map_err(|_| Error::Malformed)?,
                ),
                bond_anchor: take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?,
                secret: take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?,
                bond_proof: take_len_limited(&mut p, constants::MAX_BOND_PROOF_LEN)?,
                address: take_len_limited(&mut p, constants::MAX_ADDRESS_LEN)?,
            }
        }
        3 => {
            let name = take_name(&mut p)?;
            let s = u64::from_be_bytes(take(&mut p, 8)?.try_into().map_err(|_| Error::Malformed)?);
            let address = take_len_limited(&mut p, constants::MAX_ADDRESS_LEN)?;
            let signature = take(&mut p, 64)?.to_vec();
            Operation::Update {
                name,
                sequence: s,
                address,
                signature,
            }
        }
        4 => {
            let name = take_name(&mut p)?;
            let s = u64::from_be_bytes(take(&mut p, 8)?.try_into().map_err(|_| Error::Malformed)?);
            let signature = take(&mut p, 64)?.to_vec();
            Operation::Release {
                name,
                sequence: s,
                signature,
            }
        }
        _ => return Err(Error::Malformed),
    };
    if !p.is_empty() {
        return Err(Error::Trailing);
    }
    Ok(op)
}
fn take_name(p: &mut &[u8]) -> Result<String, Error> {
    let name =
        String::from_utf8(take_len_limited(p, constants::MAX_NAME_LEN).map_err(|_| Error::Name)?)
            .map_err(|_| Error::Name)?;
    if !valid_name(&name) {
        return Err(Error::Name);
    }
    Ok(name)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operation_wire_round_trip() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let x = Operation::Reveal {
            name: "alice".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor_height: 0,
            bond_anchor: [2; 32],
            bond_proof: vec![3; 17],
            address: b"UA_A".to_vec(),
            secret: [9; 32],
        };
        let p = encode_operation(&x).unwrap();
        assert_eq!(decode_operation(&p).unwrap(), x)
    }
    #[test]
    fn bad_name() {
        assert!(!valid_name("-a"));
        assert!(!valid_name("A"));
        assert!(!valid_name("alice.zec"));
        assert!(valid_name("a-9"));
    }

    #[test]
    fn presentation_suffix_is_removed_before_protocol_validation_and_encoding() {
        assert_eq!(normalize_name("alice").unwrap(), "alice");
        assert_eq!(normalize_name("alice.zec").unwrap(), "alice");
        assert_eq!(display_name("alice"), "alice.zec");
        assert!(normalize_name("alice.zec.zec").is_err());
        assert!(normalize_name("ALICE.zec").is_err());
        assert!(normalize_name(".zec").is_err());

        let maximum = "a".repeat(constants::MAX_NAME_LEN);
        assert_eq!(normalize_name(&format!("{maximum}.zec")).unwrap(), maximum);

        let bare = Operation::Update {
            name: "alice".to_owned(),
            sequence: 1,
            address: b"UA".to_vec(),
            signature: vec![0; 64],
        };
        let presented = Operation::Update {
            name: "alice.zec".to_owned(),
            sequence: 1,
            address: b"UA".to_vec(),
            signature: vec![0; 64],
        };
        assert_eq!(
            encode_operation(&presented).unwrap(),
            encode_operation(&bare).unwrap()
        );
        assert_eq!(
            decode_operation(&encode_operation(&presented).unwrap()).unwrap(),
            bare
        );
    }
    #[test]
    fn operation_decoder_is_strict() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let op = Operation::Reveal {
            name: "alice".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor_height: 0,
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: b"UA".to_vec(),
            secret: [9; 32],
        };
        let mut p = encode_operation(&op).unwrap();
        p.push(0);
        assert_eq!(decode_operation(&p), Err(Error::Trailing));
        let mut truncated = encode_operation(&op).unwrap();
        truncated.pop();
        assert_eq!(decode_operation(&truncated), Err(Error::Malformed));
        assert_eq!(decode_operation(&[0xff]), Err(Error::Malformed));
        let update = Operation::Update {
            name: "alice".into(),
            sequence: 1,
            address: b"UA".to_vec(),
            signature: vec![0; 63],
        };
        assert_eq!(encode_operation(&update), Err(Error::Malformed));
    }

    #[test]
    fn operation_field_limits_are_checked_before_variable_field_copying() {
        let mut oversized_name = vec![2, 0, 64];
        oversized_name.extend_from_slice(&[b'a'; 64]);
        assert_eq!(decode_operation(&oversized_name), Err(Error::Name));

        let mut oversized_reveal_proof = vec![2, 0, 1, b'a'];
        oversized_reveal_proof.extend_from_slice(&[0; 32 + 32 + 4 + 32 + 32]);
        oversized_reveal_proof.extend_from_slice(&(8193u16).to_be_bytes());
        assert_eq!(
            decode_operation(&oversized_reveal_proof),
            Err(Error::Length)
        );

        let mut oversized_reveal_address = vec![2, 0, 1, b'a'];
        oversized_reveal_address.extend_from_slice(&[0; 32 + 32 + 4 + 32 + 32]);
        oversized_reveal_address.extend_from_slice(&0u16.to_be_bytes());
        oversized_reveal_address.extend_from_slice(&(513u16).to_be_bytes());
        assert_eq!(
            decode_operation(&oversized_reveal_address),
            Err(Error::Length)
        );

        let mut oversized_update_address = vec![3, 0, 1, b'a'];
        oversized_update_address.extend_from_slice(&[0; 8]);
        oversized_update_address.extend_from_slice(&(513u16).to_be_bytes());
        assert_eq!(
            decode_operation(&oversized_update_address),
            Err(Error::Length)
        );

        let mut oversized_operation = vec![0; coppice_core::carrier::MAX_CPV1_PAYLOAD_LEN + 1];
        oversized_operation[0] = 1;
        assert_eq!(decode_operation(&oversized_operation), Err(Error::Length));

        let reveal = Operation::Reveal {
            name: "a".repeat(constants::MAX_NAME_LEN),
            owner_pk: [0; 32],
            bond_tag: [0; 32],
            bond_anchor_height: 0,
            bond_anchor: [0; 32],
            bond_proof: vec![0; constants::MAX_BOND_PROOF_LEN],
            address: vec![0; constants::MAX_ADDRESS_LEN],
            secret: [0; 32],
        };
        assert_eq!(encode_operation(&reveal).unwrap().len(), 8_906);

        let mut oversized = reveal.clone();
        if let Operation::Reveal { bond_proof, .. } = &mut oversized {
            bond_proof.push(0);
        }
        assert_eq!(encode_operation(&oversized), Err(Error::Length));
        let mut oversized = reveal;
        if let Operation::Reveal { address, .. } = &mut oversized {
            address.push(0);
        }
        assert_eq!(encode_operation(&oversized), Err(Error::Length));
    }

    #[test]
    fn maximum_reveal_payload_uses_eighteen_v1_frames() {
        let operation = Operation::Reveal {
            name: "a".repeat(constants::MAX_NAME_LEN),
            owner_pk: [0; 32],
            bond_tag: [0; 32],
            bond_anchor_height: 0,
            bond_anchor: [0; 32],
            bond_proof: vec![0; constants::MAX_BOND_PROOF_LEN],
            address: vec![0; constants::MAX_ADDRESS_LEN],
            secret: [0; 32],
        };
        let payload = encode_operation(&operation).unwrap();
        assert_eq!(payload.len(), 8_906);
        let frames = coppice_core::transport::encode_frames([0; 32], &payload).unwrap();
        assert_eq!(frames.len(), 18);
        assert!(frames.len() <= usize::from(constants::MAX_FRAMES));
    }

    fn fixed32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn operation_wire_vectors_match_v1_oracles() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/operations.json")).unwrap();
        let expected_bytes = |id: &str| {
            let vector = fixture["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|vector| vector["id"].as_str() == Some(id))
                .unwrap();
            hex::decode(vector["expected_hex"].as_str().unwrap()).unwrap()
        };
        let cases = vec![
            (
                "commit",
                Operation::Commit {
                    commitment: fixed32(
                        "bb65ec89bc5e298442f519808acea4a91dedeea427357894686399334d76ee80",
                    ),
                },
            ),
            (
                "reveal",
                Operation::Reveal {
                    name: "alice".into(),
                    owner_pk: fixed32(
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    ),
                    bond_tag: [0x42; 32],
                    bond_anchor_height: 123,
                    bond_anchor: [0x11; 32],
                    bond_proof: (0..16).collect(),
                    address: b"u1synthetic-conformance-address".to_vec(),
                    secret: [0xa5; 32],
                },
            ),
            (
                "update",
                Operation::Update {
                    name: "alice".into(),
                    sequence: 1,
                    address: b"u1synthetic-new-address".to_vec(),
                    signature: vec![0x77; 64],
                },
            ),
            (
                "release",
                Operation::Release {
                    name: "alice".into(),
                    sequence: 2,
                    signature: vec![0x77; 64],
                },
            ),
        ];

        for (id, operation) in cases {
            let expected = expected_bytes(id);
            let encoded = encode_operation(&operation).unwrap();
            assert_eq!(encoded, expected, "{id} encoding");

            let decoded = decode_operation(&expected)
                .unwrap_or_else(|error| panic!("{id} decoding failed: {error:?}"));
            assert_eq!(decoded, operation, "{id} decoding");
            assert_eq!(
                encode_operation(&decoded).unwrap(),
                expected,
                "{id} canonical"
            );
        }
    }

    #[test]
    fn obsolete_transfer_tag_is_rejected() {
        assert_eq!(decode_operation(&[6]), Err(Error::Malformed));
    }
}
