//! Replay-independent host validation for canonical v1 REVEAL operations.

use crate::{
    bond::{V1BindingError, V1BondPublicInputs, V1BondVerifier, V1BondVerifierError},
    config::{DeploymentEncodingError, DeploymentParameters},
    envelope::{self, Operation},
    owner, pending,
    record::NameStatus,
    registration,
    state::{CoppiceState, PrevalidatedReveal, PrevalidatedRevealPath},
};
use zcash_address::unified::{Address, Encoding};

pub use crate::constants::{MAX_ADDRESS_LEN, MAX_BOND_PROOF_LEN};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedIronwoodCheckpoint {
    pub height: u32,
    pub root: [u8; 32],
    pub tree_size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevealValidationError {
    UnsupportedOperation,
    InvalidName,
    InvalidOwnerKey,
    InvalidAddress,
    WrongAddressNetwork,
    NonCanonicalAddress,
    AddressTooLong,
    DeploymentEncoding(DeploymentEncodingError),
    CommitmentNotPending,
    CommitmentNotMature,
    CommitmentExpired,
    NameNotClaimable,
    CommitPredatesClaimability,
    BondAlreadySpent,
    BondAlreadyInUse,
    InvalidAnchorHeight,
    AnchorCheckpointMismatch,
    FreshnessCheckpointMismatch,
    InvalidPublicInput,
    ProofTooLarge,
    InvalidProof,
    VerifierIdentityMismatch,
    ArithmeticOverflow,
}

impl From<V1BondVerifierError> for RevealValidationError {
    fn from(error: V1BondVerifierError) -> Self {
        match error {
            V1BondVerifierError::VerifierIdentityMismatch => Self::VerifierIdentityMismatch,
            V1BondVerifierError::KeyConstruction => Self::InvalidProof,
        }
    }
}

/// Validates and returns the canonical v1 Unified Address bytes for a deployment.
///
/// This is shared with wallet adapters so they can validate pending local
/// registration metadata using the same address rule as REVEAL validation.
pub fn canonical_v1_address(
    bytes: &[u8],
    deployment: &DeploymentParameters,
) -> Result<Vec<u8>, RevealValidationError> {
    if bytes.len() > MAX_ADDRESS_LEN {
        return Err(RevealValidationError::AddressTooLong);
    }
    if !bytes.is_ascii() {
        return Err(RevealValidationError::InvalidAddress);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| RevealValidationError::InvalidAddress)?;
    let (network, address) =
        Address::decode(text).map_err(|_| RevealValidationError::InvalidAddress)?;
    if network != deployment.address_network {
        return Err(RevealValidationError::WrongAddressNetwork);
    }
    let canonical = address.encode(&network).into_bytes();
    if canonical != bytes {
        return Err(RevealValidationError::NonCanonicalAddress);
    }
    Ok(canonical)
}

struct ValidatedBeforeProof<'a> {
    reveal: PrevalidatedReveal,
    public_inputs: V1BondPublicInputs,
    proof: &'a [u8],
}

fn validate_before_proof<'a>(
    state: &CoppiceState,
    deployment: &DeploymentParameters,
    reveal_height: u32,
    anchor_checkpoint: AuthenticatedIronwoodCheckpoint,
    floor_checkpoint: AuthenticatedIronwoodCheckpoint,
    operation: &'a Operation,
) -> Result<ValidatedBeforeProof<'a>, RevealValidationError> {
    let Operation::Reveal {
        name,
        owner_pk,
        bond_tag,
        bond_anchor_height,
        bond_anchor,
        bond_proof,
        address,
        secret,
    } = operation
    else {
        return Err(RevealValidationError::UnsupportedOperation);
    };

    if !envelope::valid_name(name) {
        return Err(RevealValidationError::InvalidName);
    }
    owner::parse_v1_owner_key(*owner_pk).map_err(|_| RevealValidationError::InvalidOwnerKey)?;
    let address = canonical_v1_address(address, deployment)?;
    if bond_proof.len() > MAX_BOND_PROOF_LEN {
        return Err(RevealValidationError::ProofTooLarge);
    }

    let commitment = registration::registration_commitment(
        deployment, name, *owner_pk, *bond_tag, &address, *secret,
    )
    .map_err(RevealValidationError::DeploymentEncoding)?;
    let committed_at = state
        .pending
        .get(&commitment)
        .copied()
        .ok_or(RevealValidationError::CommitmentNotPending)?;
    let timing_valid = pending::reveal_is_valid(
        committed_at.block_height,
        reveal_height,
        deployment.commit_ttl_blocks,
    )
    .map_err(|_| RevealValidationError::ArithmeticOverflow)?;
    if !timing_valid {
        if reveal_height <= committed_at.block_height {
            return Err(RevealValidationError::CommitmentNotMature);
        }
        return Err(RevealValidationError::CommitmentExpired);
    }
    if reveal_height < deployment.activation_height {
        return Err(RevealValidationError::NameNotClaimable);
    }

    let path = match state.names.get(name) {
        None => PrevalidatedRevealPath::NewName,
        Some(record) if record.status == NameStatus::Active => {
            return Err(RevealValidationError::NameNotClaimable);
        }
        Some(record) => {
            let terminal_height = match record.status {
                NameStatus::Released { terminal_height }
                | NameStatus::BondSpent { terminal_height } => terminal_height,
                NameStatus::Active => unreachable!("handled above"),
            };
            let claimable_from = terminal_height
                .checked_add(deployment.reuse_delay_blocks)
                .ok_or(RevealValidationError::ArithmeticOverflow)?;
            if reveal_height < claimable_from {
                return Err(RevealValidationError::NameNotClaimable);
            }
            if committed_at.block_height < claimable_from {
                return Err(RevealValidationError::CommitPredatesClaimability);
            }
            PrevalidatedRevealPath::TerminalReplacement
        }
    };

    if state.recent_spent.contains_key(bond_tag) {
        return Err(RevealValidationError::BondAlreadySpent);
    }
    if state.active_bond_index().contains_key(bond_tag) {
        return Err(RevealValidationError::BondAlreadyInUse);
    }
    if *bond_anchor_height < committed_at.block_height || *bond_anchor_height >= reveal_height {
        return Err(RevealValidationError::InvalidAnchorHeight);
    }
    if anchor_checkpoint.height != *bond_anchor_height || anchor_checkpoint.root != *bond_anchor {
        return Err(RevealValidationError::AnchorCheckpointMismatch);
    }

    let activation_checkpoint_height = deployment
        .activation_height
        .checked_sub(1)
        .ok_or(RevealValidationError::ArithmeticOverflow)?;
    let floor_height = activation_checkpoint_height.max(
        committed_at
            .block_height
            .saturating_sub(deployment.bond_note_max_age_blocks),
    );
    if floor_checkpoint.height != floor_height {
        return Err(RevealValidationError::FreshnessCheckpointMismatch);
    }
    let public_inputs = V1BondPublicInputs::from_runtime_facts(
        deployment,
        anchor_checkpoint.root,
        floor_checkpoint.tree_size,
        name,
        &address,
        *owner_pk,
        *bond_tag,
    )
    .map_err(|error| match error {
        V1BindingError::Deployment(error) => RevealValidationError::DeploymentEncoding(error),
        _ => RevealValidationError::InvalidPublicInput,
    })?;

    Ok(ValidatedBeforeProof {
        reveal: PrevalidatedReveal {
            name: name.clone(),
            owner_pk: *owner_pk,
            bond_tag: *bond_tag,
            address,
            commitment,
            path,
        },
        public_inputs,
        proof: bond_proof,
    })
}

pub fn validate_v1_reveal(
    state: &CoppiceState,
    deployment: &DeploymentParameters,
    reveal_height: u32,
    anchor_checkpoint: AuthenticatedIronwoodCheckpoint,
    floor_checkpoint: AuthenticatedIronwoodCheckpoint,
    verifier: &V1BondVerifier,
    operation: &Operation,
) -> Result<PrevalidatedReveal, RevealValidationError> {
    let validated = validate_before_proof(
        state,
        deployment,
        reveal_height,
        anchor_checkpoint,
        floor_checkpoint,
        operation,
    )?;
    if !verifier.verify_v1_bond_proof(validated.proof, &validated.public_inputs) {
        return Err(RevealValidationError::InvalidProof);
    }
    Ok(validated.reveal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Rendezvous,
        owner::{OwnerSigningKey, owner_key_bytes},
        pending::ChainPosition,
        record::NameRecord,
    };
    use std::collections::BTreeMap;
    use zcash_address::unified::{self, Encoding};
    use zcash_protocol::consensus::NetworkType;

    fn deployment() -> DeploymentParameters {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let input = &fixture["input"];
        DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: NetworkType::Regtest,
            activation_height: input["activation_height"].as_u64().unwrap() as u32,
            minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
            commit_ttl_blocks: input["commit_ttl_blocks"].as_u64().unwrap() as u32,
            reuse_delay_blocks: input["reuse_delay_blocks"].as_u64().unwrap() as u32,
            bond_note_max_age_blocks: input["bond_note_max_age_blocks"].as_u64().unwrap() as u32,
            rendezvous: Rendezvous {
                orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            },
        }
    }

    fn canonical_ua(network: NetworkType) -> Vec<u8> {
        let deployment = deployment();
        unified::Address::try_from_items(vec![unified::Receiver::Orchard(
            deployment.rendezvous.orchard_receiver,
        )])
        .unwrap()
        .encode(&network)
        .into_bytes()
    }

    fn owner_pk() -> [u8; 32] {
        let key = OwnerSigningKey::try_from([1; 32]).unwrap();
        owner_key_bytes(&(&key).into())
    }

    fn operation() -> Operation {
        Operation::Reveal {
            name: "alice".to_owned(),
            owner_pk: owner_pk(),
            bond_tag: [1; 32],
            bond_anchor_height: 100,
            bond_anchor: [2; 32],
            bond_proof: vec![0; 32],
            address: canonical_ua(NetworkType::Regtest),
            secret: [3; 32],
        }
    }

    fn state_with_commit(operation: &Operation, commit_height: u32) -> CoppiceState {
        let deployment = deployment();
        let Operation::Reveal {
            name,
            owner_pk,
            bond_tag,
            address,
            secret,
            ..
        } = operation
        else {
            panic!()
        };
        let commitment = registration::registration_commitment(
            &deployment,
            name,
            *owner_pk,
            *bond_tag,
            address,
            *secret,
        )
        .unwrap();
        let mut state = CoppiceState::default();
        state.pending.insert(
            commitment,
            ChainPosition {
                block_height: commit_height,
                tx_index: 0,
            },
        );
        state
    }

    fn checkpoints(
        anchor_height: u32,
        anchor_root: [u8; 32],
        floor_height: u32,
    ) -> (
        AuthenticatedIronwoodCheckpoint,
        AuthenticatedIronwoodCheckpoint,
    ) {
        (
            AuthenticatedIronwoodCheckpoint {
                height: anchor_height,
                root: anchor_root,
                tree_size: 50,
            },
            AuthenticatedIronwoodCheckpoint {
                height: floor_height,
                root: [9; 32],
                tree_size: 10,
            },
        )
    }

    fn preproof(
        state: &CoppiceState,
        operation: &Operation,
        reveal_height: u32,
        anchor: AuthenticatedIronwoodCheckpoint,
        floor: AuthenticatedIronwoodCheckpoint,
    ) -> Result<PrevalidatedReveal, RevealValidationError> {
        validate_before_proof(
            state,
            &deployment(),
            reveal_height,
            anchor,
            floor,
            operation,
        )
        .map(|validated| validated.reveal)
    }

    #[test]
    fn rejects_shape_name_owner_and_address_failures() {
        let state = CoppiceState::default();
        let (anchor, floor) = checkpoints(100, [2; 32], 9);
        assert_eq!(
            preproof(
                &state,
                &Operation::Commit {
                    commitment: [0; 32]
                },
                101,
                anchor,
                floor
            ),
            Err(RevealValidationError::UnsupportedOperation)
        );

        let mut invalid_name = operation();
        if let Operation::Reveal { name, .. } = &mut invalid_name {
            *name = "Alice".to_owned();
        }
        assert_eq!(
            preproof(&state, &invalid_name, 101, anchor, floor),
            Err(RevealValidationError::InvalidName)
        );

        let mut invalid_owner = operation();
        if let Operation::Reveal { owner_pk, .. } = &mut invalid_owner {
            *owner_pk = [0xff; 32];
        }
        assert_eq!(
            preproof(&state, &invalid_owner, 101, anchor, floor),
            Err(RevealValidationError::InvalidOwnerKey)
        );

        let mut identity_owner = operation();
        if let Operation::Reveal { owner_pk, .. } = &mut identity_owner {
            *owner_pk = [0; 32];
        }
        assert_eq!(
            preproof(&state, &identity_owner, 101, anchor, floor),
            Err(RevealValidationError::InvalidOwnerKey)
        );

        let mut malformed = operation();
        if let Operation::Reveal { address, .. } = &mut malformed {
            *address = b"not-a-ua".to_vec();
        }
        assert_eq!(
            preproof(&state, &malformed, 101, anchor, floor),
            Err(RevealValidationError::InvalidAddress)
        );

        let mut wrong_network = operation();
        if let Operation::Reveal { address, .. } = &mut wrong_network {
            *address = canonical_ua(NetworkType::Main);
        }
        assert_eq!(
            preproof(&state, &wrong_network, 101, anchor, floor),
            Err(RevealValidationError::WrongAddressNetwork)
        );

        let mut oversized = operation();
        if let Operation::Reveal { address, .. } = &mut oversized {
            *address = vec![b'a'; MAX_ADDRESS_LEN + 1];
        }
        assert_eq!(
            preproof(&state, &oversized, 101, anchor, floor),
            Err(RevealValidationError::AddressTooLong)
        );

        let mut uppercase = operation();
        if let Operation::Reveal { address, .. } = &mut uppercase {
            address.make_ascii_uppercase();
        }
        assert!(matches!(
            preproof(&state, &uppercase, 101, anchor, floor),
            Err(RevealValidationError::InvalidAddress | RevealValidationError::NonCanonicalAddress)
        ));
    }

    #[test]
    fn commitment_timing_boundaries_are_exact() {
        let operation = operation();
        let missing = CoppiceState::default();
        let (anchor, floor) = checkpoints(100, [2; 32], 9);
        assert_eq!(
            preproof(&missing, &operation, 101, anchor, floor),
            Err(RevealValidationError::CommitmentNotPending)
        );

        let state = state_with_commit(&operation, 100);
        assert_eq!(
            preproof(&state, &operation, 100, anchor, floor),
            Err(RevealValidationError::CommitmentNotMature)
        );
        assert!(preproof(&state, &operation, 101, anchor, floor).is_ok());

        let mut deadline_operation = operation.clone();
        if let Operation::Reveal {
            bond_anchor_height, ..
        } = &mut deadline_operation
        {
            *bond_anchor_height = 119;
        }
        let (deadline_anchor, floor) = checkpoints(119, [2; 32], 9);
        assert!(preproof(&state, &deadline_operation, 120, deadline_anchor, floor).is_ok());
        assert_eq!(
            preproof(&state, &deadline_operation, 121, deadline_anchor, floor),
            Err(RevealValidationError::CommitmentExpired)
        );

        let mut pre_activation = operation.clone();
        if let Operation::Reveal {
            bond_anchor_height, ..
        } = &mut pre_activation
        {
            *bond_anchor_height = 8;
        }
        let pre_activation_state = state_with_commit(&pre_activation, 8);
        let (pre_activation_anchor, pre_activation_floor) = checkpoints(8, [2; 32], 9);
        assert_eq!(
            preproof(
                &pre_activation_state,
                &pre_activation,
                9,
                pre_activation_anchor,
                pre_activation_floor,
            ),
            Err(RevealValidationError::NameNotClaimable)
        );
    }

    #[test]
    fn claimability_and_bond_state_checks_are_exact() {
        let operation = operation();
        let (anchor, floor) = checkpoints(100, [2; 32], 9);
        let mut active = state_with_commit(&operation, 100);
        active.names.insert(
            "alice".to_owned(),
            NameRecord {
                owner_pk: owner_pk(),
                bond_tag: [8; 32],
                sequence: 0,
                address: canonical_ua(NetworkType::Regtest),
                status: NameStatus::Active,
            },
        );
        assert_eq!(
            preproof(&active, &operation, 101, anchor, floor),
            Err(RevealValidationError::NameNotClaimable)
        );

        let terminal_record = |terminal_height| NameRecord {
            owner_pk: owner_pk(),
            bond_tag: [8; 32],
            sequence: 1,
            address: canonical_ua(NetworkType::Regtest),
            status: NameStatus::Released { terminal_height },
        };
        let mut cooling_operation = operation.clone();
        if let Operation::Reveal {
            bond_anchor_height, ..
        } = &mut cooling_operation
        {
            *bond_anchor_height = 98;
        }
        let mut cooling = state_with_commit(&cooling_operation, 98);
        cooling
            .names
            .insert("alice".to_owned(), terminal_record(90));
        let (cooling_anchor, floor) = checkpoints(98, [2; 32], 9);
        assert_eq!(
            preproof(&cooling, &cooling_operation, 99, cooling_anchor, floor),
            Err(RevealValidationError::NameNotClaimable)
        );

        let mut predated = state_with_commit(&operation, 99);
        predated
            .names
            .insert("alice".to_owned(), terminal_record(90));
        assert_eq!(
            preproof(&predated, &operation, 100, anchor, floor),
            Err(RevealValidationError::CommitPredatesClaimability)
        );

        let mut boundary = state_with_commit(&operation, 100);
        boundary
            .names
            .insert("alice".to_owned(), terminal_record(90));
        assert_eq!(
            preproof(&boundary, &operation, 101, anchor, floor)
                .unwrap()
                .path,
            PrevalidatedRevealPath::TerminalReplacement
        );

        let mut spent = state_with_commit(&operation, 100);
        spent.recent_spent.insert([1; 32], 50);
        assert_eq!(
            preproof(&spent, &operation, 101, anchor, floor),
            Err(RevealValidationError::BondAlreadySpent)
        );

        let mut names = BTreeMap::new();
        names.insert(
            "bob".to_owned(),
            NameRecord {
                owner_pk: owner_pk(),
                bond_tag: [1; 32],
                sequence: 0,
                address: canonical_ua(NetworkType::Regtest),
                status: NameStatus::Active,
            },
        );
        let pending = state_with_commit(&operation, 100).pending;
        let collision = CoppiceState::from_authoritative_parts(
            names,
            pending,
            crate::recent_spent::RecentSpent::new(),
        )
        .unwrap();
        assert_eq!(
            preproof(&collision, &operation, 101, anchor, floor),
            Err(RevealValidationError::BondAlreadyInUse)
        );
    }

    #[test]
    fn anchor_and_freshness_checkpoints_are_authenticated() {
        let operation = operation();
        let state = state_with_commit(&operation, 100);
        let (anchor, floor) = checkpoints(100, [2; 32], 9);

        let mut below = operation.clone();
        if let Operation::Reveal {
            bond_anchor_height, ..
        } = &mut below
        {
            *bond_anchor_height = 99;
        }
        assert_eq!(
            preproof(&state, &below, 101, anchor, floor),
            Err(RevealValidationError::InvalidAnchorHeight)
        );
        let mut at_reveal = operation.clone();
        if let Operation::Reveal {
            bond_anchor_height, ..
        } = &mut at_reveal
        {
            *bond_anchor_height = 101;
        }
        let (at_reveal_anchor, _) = checkpoints(101, [2; 32], 9);
        assert_eq!(
            preproof(&state, &at_reveal, 101, at_reveal_anchor, floor),
            Err(RevealValidationError::InvalidAnchorHeight)
        );

        let wrong_height = AuthenticatedIronwoodCheckpoint {
            height: 99,
            ..anchor
        };
        assert_eq!(
            preproof(&state, &operation, 101, wrong_height, floor),
            Err(RevealValidationError::AnchorCheckpointMismatch)
        );
        let wrong_root = AuthenticatedIronwoodCheckpoint {
            root: [4; 32],
            ..anchor
        };
        assert_eq!(
            preproof(&state, &operation, 101, wrong_root, floor),
            Err(RevealValidationError::AnchorCheckpointMismatch)
        );
        let wrong_floor = AuthenticatedIronwoodCheckpoint {
            height: 10,
            ..floor
        };
        assert_eq!(
            preproof(&state, &operation, 101, anchor, wrong_floor),
            Err(RevealValidationError::FreshnessCheckpointMismatch)
        );
    }

    #[test]
    fn proof_rejection_is_clean_and_state_is_unchanged() {
        let operation = operation();
        let state = state_with_commit(&operation, 100);
        let before = state.clone();
        let (anchor, floor) = checkpoints(100, [2; 32], 9);
        let verifier = V1BondVerifier::new().unwrap();
        assert_eq!(
            validate_v1_reveal(
                &state,
                &deployment(),
                101,
                anchor,
                floor,
                &verifier,
                &operation,
            ),
            Err(RevealValidationError::InvalidProof)
        );
        assert_eq!(state, before);

        let mut oversized = operation;
        if let Operation::Reveal { bond_proof, .. } = &mut oversized {
            *bond_proof = vec![0; MAX_BOND_PROOF_LEN + 1];
        }
        assert_eq!(
            preproof(&state, &oversized, 101, anchor, floor),
            Err(RevealValidationError::ProofTooLarge)
        );
    }
}
