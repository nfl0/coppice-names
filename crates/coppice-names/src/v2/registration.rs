//! Experimental v2 COMMIT/REVEAL registration and retained v1 bond evidence.

use super::state::{
    MAX_RECORD_BYTES, NameId, OwnerKey, ProducerPosition, StateRef, hash_bytes, name_id,
    record_digest_field,
};
use crate::{
    bond::{V1BondPublicInputs, V1BondVerifier},
    config::DeploymentParameters,
};
use pasta_curves::group::ff::PrimeField;
use serde::{Deserialize, Serialize};

/// Experimental v2 registration commitment version byte.
pub const V2_REGISTRATION_VERSION: u8 = 2;

/// Errors from v2 registration-intent encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    /// The name is not a canonical v1-compatible bare label.
    InvalidName,
    /// The owner is not a canonical non-identity Ironwood `ak` key.
    InvalidOwner,
    /// The committed record exceeds the v2 bound.
    RecordTooLarge,
}

/// The private semantic payload committed by COMMIT and disclosed by REVEAL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationIntent {
    /// Canonical bare name (the `.zec` presentation suffix is not retained).
    pub name: String,
    /// Canonical Ironwood `ak`/RedPallas SpendAuth validating key bytes.
    pub owner_pk: OwnerKey,
    /// Bond identity retained from the v1 registration flow.
    pub bond_tag: [u8; 32],
    /// Canonical destination/record data.
    pub record: Vec<u8>,
    /// Fresh hidden COMMIT preimage.
    pub secret: [u8; 32],
}

impl RegistrationIntent {
    /// Validates and returns the canonical name identifier.
    pub fn name_id(&self) -> Result<NameId, RegistrationError> {
        let canonical = crate::envelope::normalize_name(&self.name)
            .map_err(|_| RegistrationError::InvalidName)?;
        if canonical != self.name {
            return Err(RegistrationError::InvalidName);
        }
        super::state::owner_key_field(self.owner_pk)
            .map_err(|_| RegistrationError::InvalidOwner)?;
        if self.record.len() > MAX_RECORD_BYTES {
            return Err(RegistrationError::RecordTooLarge);
        }
        name_id(&canonical).map_err(|_| RegistrationError::InvalidName)
    }

    /// Computes the hidden v2 COMMIT value.
    pub fn commitment(&self) -> Result<[u8; 32], RegistrationError> {
        let name_id = self.name_id()?;
        let record_digest = record_digest_field(&self.record).to_repr();
        let record_len =
            u32::try_from(self.record.len()).map_err(|_| RegistrationError::RecordTooLarge)?;
        let mut preimage = Vec::with_capacity(1 + 32 + 32 + 32 + 32 + 4 + 32);
        preimage.push(V2_REGISTRATION_VERSION);
        preimage.extend_from_slice(&name_id);
        preimage.extend_from_slice(&self.owner_pk);
        preimage.extend_from_slice(&self.bond_tag);
        preimage.extend_from_slice(&record_digest);
        preimage.extend_from_slice(&record_len.to_be_bytes());
        preimage.extend_from_slice(&self.secret);
        Ok(hash_bytes("CoppiceN2Com", &preimage))
    }
}

/// The exact pending COMMIT position referenced by REVEAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitRef {
    /// The canonical transaction containing COMMIT.
    pub position: ProducerPosition,
    /// Exact carrier-message index of the accepted COMMIT in that transaction.
    pub operation_index: u32,
    /// The commitment payload.
    pub commitment: [u8; 32],
}

impl CommitRef {
    /// Constructs a commitment reference.
    pub const fn new(
        position: ProducerPosition,
        operation_index: u32,
        commitment: [u8; 32],
    ) -> Self {
        Self {
            position,
            operation_index,
            commitment,
        }
    }
}

/// Public v1 BondProof evidence carried by an experimental v2 REVEAL.
///
/// This is only an adapter envelope. The verifier identity and circuit remain
/// the unchanged v1 `CoppiceBondV1` relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondEvidence {
    /// The v1 Orchard proof bytes.
    pub proof: Vec<u8>,
    /// The v1 note anchor encoding.
    pub anchor: [u8; 32],
    /// The v1 bond tag.
    pub bond_tag: [u8; 32],
    /// The note position proven by v1.
    pub position: u32,
    /// The minimum permitted note position.
    pub position_floor: u32,
}

/// The narrow dependency the v2 state machine needs for retained BondProof.
pub trait BondProofVerifier {
    /// Verifies v1 BondProof without changing its verifier identity or statement.
    fn verify(&self, intent: &RegistrationIntent, evidence: &BondEvidence) -> bool;
}

/// Adapter that verifies the unchanged v1 BondProof relation for a v2 REVEAL.
pub struct FrozenV1BondProofVerifier {
    deployment: DeploymentParameters,
    verifier: V1BondVerifier,
}

impl FrozenV1BondProofVerifier {
    /// Builds an adapter with the frozen v1 verifier and deployment context.
    pub fn new(deployment: DeploymentParameters) -> Result<Self, crate::bond::V1BondVerifierError> {
        Ok(Self {
            deployment,
            verifier: V1BondVerifier::new()?,
        })
    }
}

impl BondProofVerifier for FrozenV1BondProofVerifier {
    fn verify(&self, intent: &RegistrationIntent, evidence: &BondEvidence) -> bool {
        if intent.name_id().is_err()
            || evidence.bond_tag != intent.bond_tag
            || evidence.position < evidence.position_floor
        {
            return false;
        }
        let Ok(canonical_record) =
            crate::reveal::canonical_v1_address(&intent.record, &self.deployment)
        else {
            return false;
        };
        let Ok(inputs) = V1BondPublicInputs::from_runtime_facts(
            &self.deployment,
            evidence.anchor,
            evidence.position_floor,
            &intent.name,
            &canonical_record,
            intent.owner_pk,
            intent.bond_tag,
        ) else {
            return false;
        };
        self.verifier.verify_v1_bond_proof(&evidence.proof, &inputs)
    }
}

/// Optional pointer to the previous terminal lineage when a name is reused.
///
/// A first registration has `None`; a reclaiming REVEAL must carry the exact
/// prior terminal state reference so a fresh resolver can authenticate the
/// claimability boundary without replaying unrelated names.
pub type ReplacementRef = Option<StateRef>;
