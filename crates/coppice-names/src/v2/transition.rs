//! Public v2 transition statements and the Orchard proof-verifier adapter.

use super::{
    operation::{IronwoodActionRef, OperationKind},
    state::{
        NameId, NameState, OwnerKey, StateError, canonical_field, name_id_field, owner_key_field,
        record_digest_field,
    },
};
use orchard::circuit::state_note_binding::{
    self as orchard_state_note, GenesisPublicInputs, GenesisVerifier, TransitionPublicInputs,
    TransitionVerifier,
};
use pasta_curves::{group::ff::PrimeField, pallas};

/// Errors while constructing canonical proof public inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementError {
    /// A state value failed representation validation.
    InvalidState(StateError),
    /// The predecessor and successor carry different names.
    NameMismatch,
    /// The owner changes, which is outside this milestone.
    OwnerMismatch,
    /// A statement field is not a canonical Pallas encoding.
    InvalidField,
}

impl From<StateError> for StatementError {
    fn from(error: StateError) -> Self {
        Self::InvalidState(error)
    }
}

/// The public statement authenticated by one non-genesis transition proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionStatement {
    /// Canonical v2 name identifier.
    pub name_id: NameId,
    /// Canonical Ironwood `ak`/RedPallas owner key.
    pub owner_pk: OwnerKey,
    /// Current state-note commitment.
    pub predecessor_commitment: [u8; 32],
    /// Nullifier at the exact predecessor action.
    pub predecessor_nullifier: [u8; 32],
    /// Successor state-note commitment.
    pub successor_commitment: [u8; 32],
    /// UPDATE, RENEW, or RELEASE.
    pub operation: OperationKind,
    /// Predecessor canonical u64 sequence.
    pub predecessor_sequence: u64,
    /// Successor canonical u64 sequence.
    pub successor_sequence: u64,
    /// Predecessor record digest field encoding.
    pub predecessor_record_digest: [u8; 32],
    /// Successor record digest field encoding.
    pub successor_record_digest: [u8; 32],
    /// Predecessor exclusive lease expiry.
    pub predecessor_lease_expiry: u32,
    /// Successor exclusive lease expiry.
    pub successor_lease_expiry: u32,
    /// Predecessor state status code.
    pub predecessor_status: u8,
    /// Successor state status code.
    pub successor_status: u8,
    /// Predecessor terminal height, zero while active.
    pub predecessor_terminal_height: u32,
    /// Successor terminal height, zero while active.
    pub successor_terminal_height: u32,
    /// Canonical block height of this operation.
    pub operation_height: u32,
    /// Digest of the exact predecessor producer position.
    pub predecessor_state_digest: [u8; 32],
    /// Digest of the exact successor state.
    pub successor_state_digest: [u8; 32],
    /// Digest of the predecessor [`StateRef`].
    pub predecessor_ref_digest: [u8; 32],
}

impl TransitionStatement {
    /// Builds a statement from two authenticated state values and one action.
    pub fn from_states(
        predecessor: &NameState,
        successor: &NameState,
        action: IronwoodActionRef,
        operation: OperationKind,
        operation_height: u32,
    ) -> Result<Self, StatementError> {
        predecessor.data.validate()?;
        successor.data.validate()?;
        if predecessor.data.name_id != successor.data.name_id {
            return Err(StatementError::NameMismatch);
        }
        if predecessor.data.owner_pk != successor.data.owner_pk {
            return Err(StatementError::OwnerMismatch);
        }
        if predecessor.state_ref.commitment != predecessor.commitment
            || successor.state_ref.commitment != successor.commitment
        {
            return Err(StatementError::InvalidField);
        }
        let predecessor_digest =
            super::state::state_digest(&predecessor.data, predecessor.commitment);
        let successor_digest = super::state::state_digest(&successor.data, successor.commitment);
        if predecessor.state_digest != predecessor_digest
            || successor.state_digest != successor_digest
        {
            return Err(StatementError::InvalidField);
        }
        Ok(Self {
            name_id: predecessor.data.name_id,
            owner_pk: predecessor.data.owner_pk,
            predecessor_commitment: predecessor.commitment,
            predecessor_nullifier: action.nullifier,
            successor_commitment: successor.commitment,
            operation,
            predecessor_sequence: predecessor.data.sequence,
            successor_sequence: successor.data.sequence,
            predecessor_record_digest: record_digest_field(&predecessor.data.record).to_repr(),
            successor_record_digest: record_digest_field(&successor.data.record).to_repr(),
            predecessor_lease_expiry: predecessor.data.lease_expiry,
            successor_lease_expiry: successor.data.lease_expiry,
            predecessor_status: predecessor.data.status.code(),
            successor_status: successor.data.status.code(),
            predecessor_terminal_height: predecessor.data.terminal_height,
            successor_terminal_height: successor.data.terminal_height,
            operation_height,
            predecessor_state_digest: predecessor_digest,
            successor_state_digest: successor_digest,
            predecessor_ref_digest: predecessor.state_ref.digest(),
        })
    }

    /// Converts this statement to the fixed Orchard public-input order.
    pub fn orchard_inputs(&self) -> Result<TransitionPublicInputs, StatementError> {
        let owner = owner_key_field(self.owner_pk).map_err(StatementError::InvalidState)?;
        let predecessor_commitment =
            canonical_field(self.predecessor_commitment).map_err(StatementError::InvalidState)?;
        let predecessor_nullifier =
            canonical_field(self.predecessor_nullifier).map_err(StatementError::InvalidState)?;
        let successor_commitment =
            canonical_field(self.successor_commitment).map_err(StatementError::InvalidState)?;
        let predecessor_record = canonical_field(self.predecessor_record_digest)
            .map_err(StatementError::InvalidState)?;
        let successor_record =
            canonical_field(self.successor_record_digest).map_err(StatementError::InvalidState)?;
        let predecessor_digest =
            canonical_field(self.predecessor_state_digest).map_err(StatementError::InvalidState)?;
        let successor_digest =
            canonical_field(self.successor_state_digest).map_err(StatementError::InvalidState)?;
        let predecessor_ref =
            canonical_field(self.predecessor_ref_digest).map_err(StatementError::InvalidState)?;
        let operation = pallas::Base::from(u64::from(self.operation.code()));
        let operation_height = pallas::Base::from(u64::from(self.operation_height));
        let binding = poseidon_pair(
            poseidon_pair(
                poseidon_pair(predecessor_digest, predecessor_ref),
                operation,
            ),
            operation_height,
        );
        Ok(TransitionPublicInputs::from_fields([
            name_id_field(self.name_id),
            owner,
            predecessor_commitment,
            predecessor_nullifier,
            successor_commitment,
            operation,
            pallas::Base::from(self.predecessor_sequence),
            pallas::Base::from(self.successor_sequence),
            predecessor_record,
            successor_record,
            pallas::Base::from(u64::from(self.predecessor_lease_expiry)),
            pallas::Base::from(u64::from(self.successor_lease_expiry)),
            pallas::Base::from(u64::from(self.predecessor_status)),
            pallas::Base::from(u64::from(self.successor_status)),
            pallas::Base::from(u64::from(self.predecessor_terminal_height)),
            pallas::Base::from(u64::from(self.successor_terminal_height)),
            operation_height,
            predecessor_digest,
            successor_digest,
            predecessor_ref,
            binding,
        ]))
    }
}

/// The public statement authenticated by a REVEAL genesis proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisStatement {
    /// Canonical v2 name identifier.
    pub name_id: NameId,
    /// Canonical Ironwood `ak`/RedPallas owner key.
    pub owner_pk: OwnerKey,
    /// Initial state-note commitment.
    pub commitment: [u8; 32],
    /// Initial sequence, normally zero.
    pub sequence: u64,
    /// Initial record digest field encoding.
    pub record_digest: [u8; 32],
    /// Initial exclusive lease expiry.
    pub lease_expiry: u32,
    /// Initial state status code.
    pub status: u8,
    /// Initial terminal height, normally zero.
    pub terminal_height: u32,
    /// State digest committed by the genesis proof.
    pub state_digest: [u8; 32],
}

impl GenesisStatement {
    /// Builds a genesis statement from the initial state and its output action.
    pub fn from_state(
        state: &NameState,
        action: IronwoodActionRef,
    ) -> Result<Self, StatementError> {
        if state.commitment != action.commitment {
            return Err(StatementError::InvalidField);
        }
        state.data.validate()?;
        let state_digest = super::state::state_digest(&state.data, state.commitment);
        if state.state_digest != state_digest {
            return Err(StatementError::InvalidField);
        }
        Ok(Self {
            name_id: state.data.name_id,
            owner_pk: state.data.owner_pk,
            commitment: state.commitment,
            sequence: state.data.sequence,
            record_digest: record_digest_field(&state.data.record).to_repr(),
            lease_expiry: state.data.lease_expiry,
            status: state.data.status.code(),
            terminal_height: state.data.terminal_height,
            state_digest,
        })
    }

    /// Converts this statement to the fixed Orchard public-input order.
    pub fn orchard_inputs(&self) -> Result<GenesisPublicInputs, StatementError> {
        let owner = owner_key_field(self.owner_pk).map_err(StatementError::InvalidState)?;
        let commitment = canonical_field(self.commitment).map_err(StatementError::InvalidState)?;
        let record = canonical_field(self.record_digest).map_err(StatementError::InvalidState)?;
        let state_digest =
            canonical_field(self.state_digest).map_err(StatementError::InvalidState)?;
        Ok(GenesisPublicInputs::from_fields([
            name_id_field(self.name_id),
            owner,
            commitment,
            pallas::Base::from(self.sequence),
            record,
            pallas::Base::from(u64::from(self.lease_expiry)),
            pallas::Base::from(u64::from(self.status)),
            pallas::Base::from(u64::from(self.terminal_height)),
            state_digest,
        ]))
    }
}

fn poseidon_pair(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    halo2_gadgets::poseidon::primitives::Hash::<
        _,
        halo2_gadgets::poseidon::primitives::P128Pow5T3,
        halo2_gadgets::poseidon::primitives::ConstantLength<2>,
        3,
        2,
    >::init()
    .hash([left, right])
}

/// The narrow proof dependency consumed by the v2 state machine and resolver.
pub trait V2StateProofVerifier {
    /// Verifies a REVEAL genesis proof.
    fn verify_genesis(&self, statement: &GenesisStatement, proof: &[u8]) -> bool;
    /// Verifies an UPDATE, RENEW, or RELEASE proof.
    fn verify_transition(&self, statement: &TransitionStatement, proof: &[u8]) -> bool;
}

/// Adapter over the feature-gated experimental Orchard verifiers.
pub struct OrchardV2ProofVerifier {
    transition: TransitionVerifier,
    genesis: GenesisVerifier,
}

impl OrchardV2ProofVerifier {
    /// Generates experimental proving/verifying keys and keeps only verifiers.
    pub fn new() -> Self {
        let (_, transition, _, genesis) = orchard_state_note::keygen();
        Self {
            transition,
            genesis,
        }
    }

    /// Builds the adapter from already-generated experimental verifiers.
    pub const fn from_parts(transition: TransitionVerifier, genesis: GenesisVerifier) -> Self {
        Self {
            transition,
            genesis,
        }
    }
}

impl Default for OrchardV2ProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl V2StateProofVerifier for OrchardV2ProofVerifier {
    fn verify_genesis(&self, statement: &GenesisStatement, proof: &[u8]) -> bool {
        statement
            .orchard_inputs()
            .ok()
            .and_then(|inputs| {
                orchard_state_note::verify_genesis(&self.genesis, proof, &inputs).ok()
            })
            .is_some()
    }

    fn verify_transition(&self, statement: &TransitionStatement, proof: &[u8]) -> bool {
        statement
            .orchard_inputs()
            .ok()
            .and_then(|inputs| {
                orchard_state_note::verify_transition(&self.transition, proof, &inputs).ok()
            })
            .is_some()
    }
}
