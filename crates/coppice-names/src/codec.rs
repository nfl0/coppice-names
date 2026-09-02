//! Exact manual wire codec for Coppice Names.

use crate::protocol::{CanonicalUa, CommitRef, Commitment, FieldElement, Name, Network, StateRef};

const MAGIC: [u8; 4] = *b"CNV2";
const REVISION: u8 = 1;
const COMMIT_TAG: u8 = 0;
const REVEAL_TAG: u8 = 1;
const REFRESH_TAG: u8 = 2;

/// Largest deployment-frozen REVEAL proof compatible with maximum inputs.
pub const MAX_REVEAL_PROOF_BYTES: usize = 14_883;
/// Largest deployment-frozen REFRESH proof compatible with maximum inputs.
pub const MAX_REFRESH_PROOF_BYTES: usize = 14_879;

/// Fixed proof lengths selected by one deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecParameters {
    pub reveal_proof_bytes: usize,
    pub refresh_proof_bytes: usize,
}

impl CodecParameters {
    pub fn validate(self) -> Result<Self, CodecError> {
        if self.reveal_proof_bytes > MAX_REVEAL_PROOF_BYTES
            || self.refresh_proof_bytes > MAX_REFRESH_PROOF_BYTES
        {
            return Err(CodecError::TooLarge);
        }
        Ok(self)
    }
}

/// One canonical Names operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Commit {
        commitment: Commitment,
    },
    Reveal {
        name: Name,
        commit: CommitRef,
        ua: CanonicalUa,
        action_index: u32,
        successor_future_nf: FieldElement,
        proof: Vec<u8>,
    },
    Refresh {
        name: Name,
        predecessor: StateRef,
        ua: CanonicalUa,
        action_index: u32,
        successor_future_nf: FieldElement,
        proof: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    WrongVersion,
    InvalidTag,
    Truncated,
    TrailingBytes,
    InvalidName,
    InvalidUa,
    InvalidField,
    InvalidProofLength,
    TooLarge,
}

pub fn encode(operation: &Operation, parameters: CodecParameters) -> Result<Vec<u8>, CodecError> {
    parameters.validate()?;
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(REVISION);
    match operation {
        Operation::Commit { commitment } => {
            out.push(COMMIT_TAG);
            out.extend_from_slice(&commitment.to_bytes());
        }
        Operation::Reveal {
            name,
            commit,
            ua,
            action_index,
            successor_future_nf,
            proof,
        } => {
            if proof.len() != parameters.reveal_proof_bytes {
                return Err(CodecError::InvalidProofLength);
            }
            out.push(REVEAL_TAG);
            encode_name(&mut out, name);
            out.extend_from_slice(&commit.height.to_be_bytes());
            out.extend_from_slice(&commit.tx_index.to_be_bytes());
            out.extend_from_slice(&commit.txid);
            encode_ua(&mut out, ua)?;
            out.extend_from_slice(&action_index.to_be_bytes());
            out.extend_from_slice(&successor_future_nf.to_bytes());
            out.extend_from_slice(proof);
        }
        Operation::Refresh {
            name,
            predecessor,
            ua,
            action_index,
            successor_future_nf,
            proof,
        } => {
            if proof.len() != parameters.refresh_proof_bytes {
                return Err(CodecError::InvalidProofLength);
            }
            out.push(REFRESH_TAG);
            encode_name(&mut out, name);
            out.extend_from_slice(&predecessor.height.to_be_bytes());
            out.extend_from_slice(&predecessor.tx_index.to_be_bytes());
            out.extend_from_slice(&predecessor.txid);
            out.extend_from_slice(&predecessor.action_index.to_be_bytes());
            encode_ua(&mut out, ua)?;
            out.extend_from_slice(&action_index.to_be_bytes());
            out.extend_from_slice(&successor_future_nf.to_bytes());
            out.extend_from_slice(proof);
        }
    }
    if out.len() > coppice::carrier::MAX_CPV1_PAYLOAD_LEN {
        return Err(CodecError::TooLarge);
    }
    Ok(out)
}

pub fn decode(
    bytes: &[u8],
    network: Network,
    parameters: CodecParameters,
) -> Result<Operation, CodecError> {
    parameters.validate()?;
    let mut input = Decoder::new(bytes);
    if input.take::<4>()? != MAGIC || input.u8()? != REVISION {
        return Err(CodecError::WrongVersion);
    }
    let operation = match input.u8()? {
        COMMIT_TAG => Operation::Commit {
            commitment: Commitment::from_bytes(input.take::<32>()?)
                .map_err(|_| CodecError::InvalidField)?,
        },
        REVEAL_TAG => {
            let name = input.name()?;
            let commit = CommitRef {
                height: input.u32()?,
                tx_index: input.u32()?,
                txid: input.take::<32>()?,
            };
            let ua = input.ua(network)?;
            let action_index = input.u32()?;
            let successor_future_nf = FieldElement::from_bytes(input.take::<32>()?)
                .map_err(|_| CodecError::InvalidField)?;
            let proof = input.proof(parameters.reveal_proof_bytes)?;
            Operation::Reveal {
                name,
                commit,
                ua,
                action_index,
                successor_future_nf,
                proof,
            }
        }
        REFRESH_TAG => {
            let name = input.name()?;
            let predecessor = StateRef {
                height: input.u32()?,
                tx_index: input.u32()?,
                txid: input.take::<32>()?,
                action_index: input.u32()?,
            };
            let ua = input.ua(network)?;
            let action_index = input.u32()?;
            let successor_future_nf = FieldElement::from_bytes(input.take::<32>()?)
                .map_err(|_| CodecError::InvalidField)?;
            let proof = input.proof(parameters.refresh_proof_bytes)?;
            Operation::Refresh {
                name,
                predecessor,
                ua,
                action_index,
                successor_future_nf,
                proof,
            }
        }
        _ => return Err(CodecError::InvalidTag),
    };
    if !input.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(operation)
}

fn encode_name(out: &mut Vec<u8>, name: &Name) {
    out.push(u8::try_from(name.as_bytes().len()).expect("name length is bounded"));
    out.extend_from_slice(name.as_bytes());
}

fn encode_ua(out: &mut Vec<u8>, ua: &CanonicalUa) -> Result<(), CodecError> {
    let length = u16::try_from(ua.as_bytes().len()).map_err(|_| CodecError::InvalidUa)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(ua.as_bytes());
    Ok(())
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining.len() < length {
            return Err(CodecError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.bytes(N)?.try_into().map_err(|_| CodecError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn name(&mut self) -> Result<Name, CodecError> {
        let length = usize::from(self.u8()?);
        let value =
            core::str::from_utf8(self.bytes(length)?).map_err(|_| CodecError::InvalidName)?;
        Name::parse(value).map_err(|_| CodecError::InvalidName)
    }

    fn ua(&mut self, network: Network) -> Result<CanonicalUa, CodecError> {
        let length = usize::from(self.u16()?);
        let value = core::str::from_utf8(self.bytes(length)?).map_err(|_| CodecError::InvalidUa)?;
        CanonicalUa::parse(network, value).map_err(|_| CodecError::InvalidUa)
    }

    fn proof(&mut self, length: usize) -> Result<Vec<u8>, CodecError> {
        if self.remaining.len() < length {
            return Err(CodecError::InvalidProofLength);
        }
        Ok(self.bytes(length)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::group::ff::PrimeField;

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    fn parameters() -> CodecParameters {
        CodecParameters {
            reveal_proof_bytes: 64,
            refresh_proof_bytes: 96,
        }
    }

    fn field(value: u64) -> FieldElement {
        FieldElement::from_bytes(pasta_curves::pallas::Base::from(value).to_repr()).unwrap()
    }

    fn operations() -> [Operation; 3] {
        let name = Name::parse("alice").unwrap();
        let ua = CanonicalUa::parse(Network::Regtest, UA).unwrap();
        [
            Operation::Commit {
                commitment: Commitment::from_bytes(pasta_curves::pallas::Base::from(1).to_repr())
                    .unwrap(),
            },
            Operation::Reveal {
                name: name.clone(),
                commit: CommitRef {
                    height: 100,
                    tx_index: 2,
                    txid: [3; 32],
                },
                ua: ua.clone(),
                action_index: 4,
                successor_future_nf: field(5),
                proof: vec![6; 64],
            },
            Operation::Refresh {
                name,
                predecessor: StateRef {
                    height: 200,
                    tx_index: 7,
                    txid: [8; 32],
                    action_index: 9,
                },
                ua,
                action_index: 10,
                successor_future_nf: field(11),
                proof: vec![12; 96],
            },
        ]
    }

    #[test]
    fn exact_layouts_round_trip_and_have_reviewed_sizes() {
        let [commit, reveal, refresh] = operations();
        let commit_bytes = encode(&commit, parameters()).unwrap();
        let reveal_bytes = encode(&reveal, parameters()).unwrap();
        let refresh_bytes = encode(&refresh, parameters()).unwrap();
        assert_eq!(commit_bytes.len(), 38);
        assert_eq!(reveal_bytes.len(), 85 + 5 + UA.len() + 64);
        assert_eq!(refresh_bytes.len(), 89 + 5 + UA.len() + 96);
        for (operation, bytes) in [
            (commit, commit_bytes),
            (reveal, reveal_bytes),
            (refresh, refresh_bytes),
        ] {
            assert_eq!(
                decode(&bytes, Network::Regtest, parameters()),
                Ok(operation)
            );
        }
    }

    #[test]
    fn every_truncation_and_trailing_byte_is_rejected() {
        for operation in operations() {
            let bytes = encode(&operation, parameters()).unwrap();
            for length in 0..bytes.len() {
                assert!(decode(&bytes[..length], Network::Regtest, parameters()).is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert_eq!(
                decode(&trailing, Network::Regtest, parameters()),
                Err(CodecError::TrailingBytes)
            );
        }
    }

    #[test]
    fn wrong_network_fields_and_proof_lengths_are_rejected() {
        let [commit, reveal, _] = operations();
        let reveal_bytes = encode(&reveal, parameters()).unwrap();
        assert_eq!(
            decode(&reveal_bytes, Network::Main, parameters()),
            Err(CodecError::InvalidUa)
        );
        let mut zero_commit = encode(&commit, parameters()).unwrap();
        zero_commit[6..].fill(0);
        assert_eq!(
            decode(&zero_commit, Network::Regtest, parameters()),
            Err(CodecError::InvalidField)
        );
        let bad_parameters = CodecParameters {
            reveal_proof_bytes: 63,
            ..parameters()
        };
        assert_eq!(
            encode(&reveal, bad_parameters),
            Err(CodecError::InvalidProofLength)
        );
    }
}
