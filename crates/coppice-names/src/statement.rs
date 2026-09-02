//! Native construction of the sole public digest for each Names proof.

use crate::protocol::{
    BOND_ZATOSHIS, CanonicalUa, CommitRef, Commitment, FieldElement, NameId, StateRef, wide_field,
};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{group::ff::PrimeField, pallas};

const OWNER_DOMAIN: u64 = 0x4e32_4f57_4e45_5221;
const COMMIT_DOMAIN: u64 = 0x4e32_434f_4d4d_4954;
const REVEAL_DOMAIN: u64 = 0x4e32_5245_5645_414c;
const REFRESH_DOMAIN: u64 = 0x4e32_5245_4652_5348;

/// Typed public facts bound into a REVEAL proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevealStatement {
    pub deployment_id: [u8; 32],
    pub name_id: NameId,
    pub inclusion_epoch: u32,
    pub commitment: Commitment,
    pub commit_ref: CommitRef,
    pub ua: CanonicalUa,
    pub action_index: u32,
    pub action_nullifier: FieldElement,
    pub action_commitment: FieldElement,
    pub successor_future_nf: FieldElement,
}

/// Typed public facts bound into a REFRESH proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshStatement {
    pub deployment_id: [u8; 32],
    pub name_id: NameId,
    pub predecessor_ref: StateRef,
    pub predecessor_commitment: FieldElement,
    pub predecessor_future_nf: FieldElement,
    pub predecessor_epoch: u32,
    pub inclusion_epoch: u32,
    pub ua: CanonicalUa,
    pub action_index: u32,
    pub action_nullifier: FieldElement,
    pub action_commitment: FieldElement,
    pub successor_future_nf: FieldElement,
}

impl RevealStatement {
    pub(crate) fn fields(&self) -> [pallas::Base; 12] {
        [
            deployment_field(self.deployment_id),
            pallas::Base::from(1),
            self.name_id.field(),
            pallas::Base::from(u64::from(self.inclusion_epoch)),
            self.commitment.field(),
            commit_ref_field(self.commit_ref),
            ua_field(&self.ua),
            pallas::Base::from(u64::from(self.action_index)),
            self.action_nullifier.field(),
            self.action_commitment.field(),
            self.successor_future_nf.field(),
            pallas::Base::from(BOND_ZATOSHIS),
        ]
    }

    /// Returns the one public field exposed by the REVEAL circuit.
    pub fn digest(&self) -> [u8; 32] {
        fold(REVEAL_DOMAIN, self.fields()).to_repr()
    }
}

impl RefreshStatement {
    pub(crate) fn fields(&self) -> [pallas::Base; 14] {
        [
            deployment_field(self.deployment_id),
            pallas::Base::from(2),
            self.name_id.field(),
            state_ref_field(self.predecessor_ref),
            self.predecessor_commitment.field(),
            self.predecessor_future_nf.field(),
            pallas::Base::from(u64::from(self.predecessor_epoch)),
            pallas::Base::from(u64::from(self.inclusion_epoch)),
            ua_field(&self.ua),
            pallas::Base::from(u64::from(self.action_index)),
            self.action_nullifier.field(),
            self.action_commitment.field(),
            self.successor_future_nf.field(),
            pallas::Base::from(BOND_ZATOSHIS),
        ]
    }

    /// Returns the one public field exposed by the REFRESH circuit.
    pub fn digest(&self) -> [u8; 32] {
        fold(REFRESH_DOMAIN, self.fields()).to_repr()
    }
}

/// Native owner commitment used by a wallet/prover witness builder.
pub fn owner_commitment(ak_x: FieldElement, nk: FieldElement, ivk: FieldElement) -> [u8; 32] {
    fold(OWNER_DOMAIN, [ak_x.field(), nk.field(), ivk.field()]).to_repr()
}

/// Native COMMIT opening used by a wallet/prover witness builder.
pub fn registration_commitment(
    deployment_id: [u8; 32],
    name_id: NameId,
    epoch: u32,
    owner_commit: FieldElement,
    secret: FieldElement,
) -> [u8; 32] {
    fold(
        COMMIT_DOMAIN,
        [
            deployment_field(deployment_id),
            name_id.field(),
            pallas::Base::from(u64::from(epoch)),
            owner_commit.field(),
            secret.field(),
        ],
    )
    .to_repr()
}

pub fn deployment_field(deployment_id: [u8; 32]) -> pallas::Base {
    bytes_field(b"CoppiceN2DplF", &deployment_id)
}

pub fn ua_field(ua: &CanonicalUa) -> pallas::Base {
    bytes_field(b"CoppiceN2UA", ua.as_bytes())
}

pub fn commit_ref_field(reference: CommitRef) -> pallas::Base {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&reference.height.to_be_bytes());
    bytes.extend_from_slice(&reference.tx_index.to_be_bytes());
    bytes.extend_from_slice(&reference.txid);
    bytes_field(b"CoppiceN2CRef", &bytes)
}

pub fn state_ref_field(reference: StateRef) -> pallas::Base {
    let mut bytes = Vec::with_capacity(44);
    bytes.extend_from_slice(&reference.height.to_be_bytes());
    bytes.extend_from_slice(&reference.tx_index.to_be_bytes());
    bytes.extend_from_slice(&reference.txid);
    bytes.extend_from_slice(&reference.action_index.to_be_bytes());
    bytes_field(b"CoppiceN2SRef", &bytes)
}

fn bytes_field(personalization: &[u8], bytes: &[u8]) -> pallas::Base {
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("protocol values are bounded")
            .to_be_bytes(),
    );
    framed.extend_from_slice(bytes);
    wide_field(personalization, &framed)
}

fn fold<const N: usize>(domain: u64, fields: [pallas::Base; N]) -> pallas::Base {
    fields
        .into_iter()
        .fold(pallas::Base::from(domain), poseidon_pair)
}

fn poseidon_pair(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([left, right])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CanonicalUa, Network};

    const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

    fn field(value: u64) -> FieldElement {
        FieldElement::from_bytes(pallas::Base::from(value).to_repr()).unwrap()
    }

    #[test]
    fn prevector_byte_fields_match_independent_implementation() {
        let deployment =
            hex::decode("0f0a82a82d6645b74a7ae2fc86722440c8f1395993e5b3efdf566a8815ab1d5c")
                .unwrap()
                .try_into()
                .unwrap();
        let ua = CanonicalUa::parse(Network::Regtest, UA).unwrap();
        assert_eq!(
            hex::encode(deployment_field(deployment).to_repr()),
            "dd42708898443b3bee93d3073252afcc482fcb4d0c032b49b7ffb9cc0db14a21"
        );
        assert_eq!(
            hex::encode(ua_field(&ua).to_repr()),
            "eff2994be2432adde0b900152d3b97bec5ba925fe4e67f71f6140c02e541ec16"
        );
        assert_eq!(
            hex::encode(
                commit_ref_field(CommitRef {
                    height: 100_440,
                    tx_index: 0,
                    txid: [0x55; 32]
                })
                .to_repr()
            ),
            "ce56ad1276e8f0568428217cb74569f93832d634cc2e99ed2f720e5c55360f2b"
        );
        assert_eq!(
            hex::encode(
                state_ref_field(StateRef {
                    height: 100_496,
                    tx_index: 0,
                    txid: [0x66; 32],
                    action_index: 3
                })
                .to_repr()
            ),
            "c7de3e0a75100b8b666fed998184677b70a36d3928a3c82d171b933f1cc0ac36"
        );
    }

    #[test]
    fn prevector_statement_folds_match_independent_implementation() {
        let deployment_id =
            hex::decode("0f0a82a82d6645b74a7ae2fc86722440c8f1395993e5b3efdf566a8815ab1d5c")
                .unwrap()
                .try_into()
                .unwrap();
        let name_id = NameId::from_bytes(
            hex::decode("b646f07d05366fb8127c706843da84c62e42eec3ba2e66af0188c20d0093710a")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let ua = CanonicalUa::parse(Network::Regtest, UA).unwrap();
        let commitment = Commitment::from_bytes(
            hex::decode("9b7da66fb21688339ec39e1ff43be22088c630d5cb4c0910529578b68184d921")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let reveal = RevealStatement {
            deployment_id,
            name_id,
            inclusion_epoch: 17,
            commitment,
            commit_ref: CommitRef {
                height: 100_440,
                tx_index: 0,
                txid: [0x55; 32],
            },
            ua: ua.clone(),
            action_index: 3,
            action_nullifier: field(6),
            action_commitment: field(7),
            successor_future_nf: field(8),
        };
        assert_eq!(
            hex::encode(reveal.digest()),
            "ea686599f0f5c37d19c091ca22ba7416cd81fccca6c3a677897a7305ac35252d"
        );

        let refresh = RefreshStatement {
            deployment_id,
            name_id,
            predecessor_ref: StateRef {
                height: 100_496,
                tx_index: 0,
                txid: [0x66; 32],
                action_index: 3,
            },
            predecessor_commitment: field(9),
            predecessor_future_nf: field(10),
            predecessor_epoch: 16,
            inclusion_epoch: 17,
            ua,
            action_index: 3,
            action_nullifier: field(10),
            action_commitment: field(11),
            successor_future_nf: field(12),
        };
        assert_eq!(
            hex::encode(refresh.digest()),
            "274484a7f15cb2dc1790f859ef0ffe893eaaa7690ca31584b33a13430b902329"
        );
    }
}
