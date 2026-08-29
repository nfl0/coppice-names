use super::super::{
    operation::{CanonicalTransaction, IronwoodActionRef},
    registration::RegistrationIntent,
    resolver::{FreshResolver, ResolveError},
    schedule,
    state::ProducerPosition,
};
use super::*;
use orchard::circuit::state_note_binding::spend_auth_owner_key_bytes;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use pasta_curves::{group::ff::PrimeField, pallas};
use std::collections::BTreeMap;

struct AcceptingProofs;

impl V1StateProofVerifier for AcceptingProofs {
    fn verify_genesis(&self, statement: &GenesisStatement, _: &[u8]) -> bool {
        statement.name_id == statement.intent_name_id
            && statement.owner_pk == statement.intent_owner_pk
            && statement.record_digest == statement.intent_record_digest
            && statement.sequence == 0
            && statement.status == StateStatus::Active.code()
            && statement.terminal_height == 0
            && statement.scheduled
            && statement
                .operation_height
                .checked_add(statement.lease_duration_blocks)
                == Some(statement.lease_expiry)
    }

    fn verify_transition(&self, statement: &TransitionStatement, _: &[u8]) -> bool {
        let common = statement.name_id == statement.successor_name_id
            && statement.owner_pk == statement.successor_owner_pk
            && statement.predecessor_nullifier == statement.predecessor_future_nullifier
            && statement.predecessor_status == StateStatus::Active.code()
            && statement.predecessor_terminal_height == 0
            && statement.operation_height < statement.predecessor_lease_expiry
            && statement.predecessor_sequence.checked_add(1) == Some(statement.successor_sequence);
        common
            && match statement.operation {
                OperationKind::Update => {
                    statement.successor_record_digest != statement.predecessor_record_digest
                        && statement.successor_lease_expiry == statement.predecessor_lease_expiry
                        && statement.successor_status == StateStatus::Active.code()
                        && statement.successor_terminal_height == 0
                }
                OperationKind::Renew => {
                    statement.successor_record_digest == statement.predecessor_record_digest
                        && statement.scheduled
                        && statement
                            .operation_height
                            .checked_add(statement.lease_duration_blocks)
                            == Some(statement.successor_lease_expiry)
                        && statement.successor_lease_expiry > statement.predecessor_lease_expiry
                        && statement.successor_status == StateStatus::Active.code()
                        && statement.successor_terminal_height == 0
                }
                OperationKind::Release => {
                    statement.successor_record_digest == statement.predecessor_record_digest
                        && statement.successor_lease_expiry == statement.predecessor_lease_expiry
                        && statement.successor_status == StateStatus::Released.code()
                        && statement.successor_terminal_height == statement.operation_height
                }
            }
    }
}

fn owner(seed: u8) -> [u8; 32] {
    let key = SpendingKey::from_bytes([seed; 32]).unwrap();
    let ask = SpendAuthorizingKey::from(&key);
    spend_auth_owner_key_bytes(&ask)
}

fn intent(seed: u8, name: &str, record: &[u8]) -> RegistrationIntent {
    RegistrationIntent {
        name: name.to_owned(),
        owner_pk: owner(seed),
        record: record.to_vec(),
        secret: [seed.wrapping_add(0x80); 32],
    }
}

fn field(value: u64) -> [u8; 32] {
    pallas::Base::from(value).to_repr()
}

fn transaction(
    tx_index: u32,
    txid: u8,
    actions: Vec<IronwoodActionRef>,
    operations: Vec<V1Operation>,
) -> CanonicalTransaction {
    CanonicalTransaction {
        tx_index,
        txid: [txid; 32],
        actions,
        operations,
    }
}

fn append(
    machine: &mut V1StateMachine,
    source: &mut BTreeMap<u32, CanonicalBlock>,
    mut transactions: Vec<CanonicalTransaction>,
) -> Result<AppliedBlock, ApplyError> {
    // Ordinary fixtures model the required same-action predecessor spend
    // only when both the exact current reference and successor commitment
    // are coherent. Adversarial stale/cross-action fixtures retain their
    // deliberately mismatched action facts.
    for transaction in &mut transactions {
        for operation in &transaction.operations {
            let Some((_, predecessor, state, commitment, _, action_index, _)) =
                transition_parts(operation)
            else {
                continue;
            };
            if machine
                .head(state.name_id)
                .is_some_and(|head| head.state_ref == *predecessor)
                && transaction.actions.iter().any(|action| {
                    action.action_index == action_index && action.commitment == *commitment
                })
                && let Some(action) = transaction
                    .actions
                    .iter_mut()
                    .find(|action| action.action_index == action_index)
            {
                action.nullifier = predecessor.nullifier;
            }
        }
    }
    let tip = machine.tip();
    let block = CanonicalBlock {
        height: tip.height + 1,
        block_hash: [tip.height as u8 + 1; 32],
        prev_block_hash: tip.block_hash,
        transactions,
    };
    let applied = machine.apply_block(&block, &AcceptingProofs)?;
    source.insert(block.height, block);
    Ok(applied)
}

fn assert_rejected(applied: &AppliedBlock, expected: ApplyError) {
    let actual = applied
        .operations
        .last()
        .map(|operation| operation.result.clone());
    assert_eq!(actual, Some(AppliedOperationResult::Rejected(expected)));
}

fn assert_fresh_matches_replay(
    machine: &V1StateMachine,
    source: &BTreeMap<u32, CanonicalBlock>,
    name: &str,
) {
    let name_id = super::super::state::name_id(name).unwrap();
    let fresh = FreshResolver::new(machine.params())
        .unwrap()
        .resolve(name, source, &AcceptingProofs)
        .unwrap();
    assert_eq!(
        fresh.status,
        machine.resolution_at(name_id, machine.tip().height)
    );
    assert_eq!(
        fresh.state.as_ref().map(|state| state.state_ref),
        machine.head(name_id).map(|state| state.state_ref)
    );
}

#[test]
fn activation_parent_bootstrap_accepts_first_block_and_preserves_continuity() {
    let params = V1Parameters::testing();
    let activation_parent = [0xa5; 32];
    let activation_hash = [0xb6; 32];
    let next_hash = [0xc7; 32];
    let mut machine = V1StateMachine::from_activation_parent(params, activation_parent).unwrap();

    let activation = CanonicalBlock {
        height: params.activation_height,
        block_hash: activation_hash,
        prev_block_hash: activation_parent,
        transactions: Vec::new(),
    };
    let applied = machine.apply_block(&activation, &AcceptingProofs).unwrap();
    assert_eq!(applied.tip, activation.tip());

    let next = CanonicalBlock {
        height: params.activation_height + 1,
        block_hash: next_hash,
        prev_block_hash: activation_hash,
        transactions: Vec::new(),
    };
    let applied = machine.apply_block(&next, &AcceptingProofs).unwrap();
    assert_eq!(applied.tip, next.tip());
    assert_eq!(machine.tip(), next.tip());
}

#[test]
fn activation_parent_bootstrap_rejects_wrong_first_predecessor() {
    let params = V1Parameters::testing();
    let activation_parent = [0xa5; 32];
    let mut machine = V1StateMachine::from_activation_parent(params, activation_parent).unwrap();
    let activation = CanonicalBlock {
        height: params.activation_height,
        block_hash: [0xb6; 32],
        prev_block_hash: [0xc7; 32],
        transactions: Vec::new(),
    };

    assert_eq!(
        machine.apply_block(&activation, &AcceptingProofs),
        Err(ApplyError::PredecessorMismatch)
    );
    assert_eq!(machine.tip().height, params.activation_height - 1);
    assert_eq!(machine.tip().block_hash, activation_parent);
}

#[test]
fn application_rejection_is_local_to_one_canonical_message() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let alice = intent(31, "alice-reject", b"record");
    let carol = intent(32, "carol-accept", b"record");
    let alice_commitment = alice.commitment().unwrap();
    let carol_commitment = carol.commitment().unwrap();
    let block = CanonicalBlock {
        height: params.activation_height,
        block_hash: [1; 32],
        prev_block_hash: [0; 32],
        transactions: vec![transaction(
            0,
            1,
            Vec::new(),
            vec![
                V1Operation::Commit {
                    commitment: alice_commitment,
                },
                // Bob's duplicate is invalid Names data, not a reason to
                // reject the host-selected canonical block.
                V1Operation::Commit {
                    commitment: alice_commitment,
                },
                V1Operation::Commit {
                    commitment: carol_commitment,
                },
            ],
        )],
    };
    let applied = machine.apply_block(&block, &AcceptingProofs).unwrap();
    assert!(matches!(
        applied.operations.as_slice(),
        [
            AppliedOperation {
                result: AppliedOperationResult::Accepted(None),
                ..
            },
            AppliedOperation {
                result: AppliedOperationResult::Rejected(ApplyError::DuplicateCommitment),
                ..
            },
            AppliedOperation {
                result: AppliedOperationResult::Accepted(None),
                ..
            },
        ]
    ));
    assert!(machine.pending(alice_commitment).is_some());
    assert!(machine.pending(carol_commitment).is_some());
}

#[test]
fn invalid_scheduled_candidate_does_not_mask_later_valid_anchor() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(33, "anchor-skip", b"record");
    let commit_ref = commit(&mut machine, &mut source, &alice, 0, 33);
    let name_id = alice.name_id().unwrap();
    let reveal_height =
        schedule::next_anchor_height(name_id, commit_ref.position.height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let state = StateData {
        name_id,
        owner_pk: alice.owner_pk,
        sequence: 0,
        record: alice.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let mut bogus_intent = alice.clone();
    bogus_intent.secret[0] ^= 1;
    let result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            34,
            vec![
                IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(3300),
                    commitment: field(3301),
                },
                IronwoodActionRef {
                    action_index: 1,
                    nullifier: field(3302),
                    commitment: field(3303),
                },
            ],
            vec![
                reveal_operation(&bogus_intent, commit_ref, state.clone(), field(3301), None),
                {
                    let mut valid = reveal_operation(&alice, commit_ref, state, field(3303), None);
                    if let V1Operation::Reveal { action_index, .. } = &mut valid {
                        *action_index = 1;
                    }
                    valid
                },
            ],
        )],
    )
    .unwrap();
    assert!(matches!(
        result.operations.as_slice(),
        [
            AppliedOperation {
                result: AppliedOperationResult::Rejected(ApplyError::CommitmentMismatch),
                ..
            },
            AppliedOperation {
                result: AppliedOperationResult::Accepted(Some((name, AppliedOperationKind::Reveal))),
                ..
            },
        ] if *name == name_id
    ));
    assert_fresh_matches_replay(&machine, &source, "anchor-skip");
}

#[test]
fn invalid_first_action_claim_structurally_reserves_the_action() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(35, "action-reservation", b"record");
    let commit_ref = commit(&mut machine, &mut source, &alice, 0, 37);
    let name_id = alice.name_id().unwrap();
    let reveal_height =
        schedule::next_anchor_height(name_id, commit_ref.position.height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let state = StateData {
        name_id,
        owner_pk: alice.owner_pk,
        sequence: 0,
        record: alice.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let mut invalid = alice.clone();
    invalid.secret[0] ^= 1;
    let result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            38,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(3500),
                commitment: field(3501),
            }],
            vec![
                reveal_operation(&invalid, commit_ref, state.clone(), field(3501), None),
                reveal_operation(&alice, commit_ref, state, field(3501), None),
            ],
        )],
    )
    .unwrap();
    assert!(matches!(
        result.operations.as_slice(),
        [
            AppliedOperation {
                result: AppliedOperationResult::Rejected(ApplyError::CommitmentMismatch),
                ..
            },
            AppliedOperation {
                result: AppliedOperationResult::Rejected(ApplyError::ActionAlreadyClaimed),
                ..
            },
        ]
    ));
    assert!(machine.head(name_id).is_none());
    assert_fresh_matches_replay(&machine, &source, "action-reservation");
}

#[test]
fn structural_action_claims_cover_reveal_and_transition_reordering() {
    let params = V1Parameters::testing();
    let alice = intent(37, "claim-family", b"record");
    let name_id = alice.name_id().unwrap();
    let commitment = field(3701);
    let nullifier = field(3702);
    let state = StateData {
        name_id,
        owner_pk: alice.owner_pk,
        sequence: 0,
        record: alice.record.clone(),
        lease_expiry: params.lease_duration_blocks + 1,
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let predecessor = StateRef::new(
        ProducerPosition::new(1, 0, [1; 32]),
        0,
        0,
        commitment,
        nullifier,
    );
    let commit = CommitRef::new(
        ProducerPosition::new(1, 0, [2; 32]),
        0,
        alice.commitment().unwrap(),
    );
    let reveal = reveal_operation(&alice, commit, state.clone(), commitment, None);
    let update = transition_operation(
        OperationKind::Update,
        predecessor,
        StateData {
            sequence: 1,
            record: b"updated".to_vec(),
            ..state.clone()
        },
        commitment,
        0,
    );
    let renew = transition_operation(
        OperationKind::Renew,
        predecessor,
        StateData {
            sequence: 1,
            lease_expiry: state.lease_expiry + params.lease_duration_blocks,
            ..state
        },
        commitment,
        0,
    );
    for operations in [
        vec![reveal.clone(), update.clone()],
        vec![update.clone(), reveal],
        vec![update, renew],
    ] {
        let transaction = transaction(
            0,
            43,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier,
                commitment,
            }],
            operations,
        );
        assert!(transaction.is_first_action_claim(0));
        assert!(!transaction.is_first_action_claim(1));
    }
}

#[test]
fn ordinary_spend_abandons_current_state_without_a_names_transition() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(36, "ordinary-spend", b"record");
    let (_, state0, _) = register(&mut machine, &mut source, &alice, 39);
    let name_id = alice.name_id().unwrap();
    let spend_height = machine.tip().height + 1;
    let invalid_successor = state_after(
        &state0,
        &state0.data.record,
        1,
        state0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let unmatched = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            41,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: state0.state_ref.nullifier,
                commitment: field(3601),
            }],
            vec![transition_operation(
                OperationKind::Update,
                state0.state_ref,
                invalid_successor,
                field(3601),
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&unmatched, ApplyError::InvalidStateProof);
    assert_eq!(
        machine.head(name_id).unwrap().abandoned_height,
        Some(spend_height)
    );
    assert_eq!(
        machine.resolution_at(name_id, spend_height),
        ResolutionStatus::Abandoned
    );

    let successor = state_after(
        &state0,
        b"should-not-apply",
        1,
        state0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let rejected = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            42,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: state0.state_ref.nullifier,
                commitment: field(3602),
            }],
            vec![transition_operation(
                OperationKind::Update,
                state0.state_ref,
                successor,
                field(3602),
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&rejected, ApplyError::StalePredecessor);
    assert_fresh_matches_replay(&machine, &source, "ordinary-spend");
    advance_to(
        &mut machine,
        &mut source,
        spend_height + params.reuse_delay_blocks,
    );
    assert_eq!(
        machine.resolution_at(name_id, machine.tip().height),
        ResolutionStatus::Expired
    );
    assert_fresh_matches_replay(&machine, &source, "ordinary-spend");
}

#[test]
fn transition_requires_action_nullifier_to_match_authenticated_head() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(38, "nf-binding", b"record");
    let (_, current, _) = register(&mut machine, &mut source, &alice, 45);
    let commitment = field(3_801);
    let successor = state_after(
        &current,
        b"changed",
        1,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let tip = machine.tip();
    let block = CanonicalBlock {
        height: tip.height + 1,
        block_hash: [0x38; 32],
        prev_block_hash: tip.block_hash,
        transactions: vec![transaction(
            0,
            46,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(3_802),
                commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                current.state_ref,
                successor,
                commitment,
                0,
            )],
        )],
    };
    let applied = machine.apply_block(&block, &AcceptingProofs).unwrap();
    assert_rejected(&applied, ApplyError::ActionNullifierMismatch);
    assert_eq!(
        machine.head(alice.name_id().unwrap()).unwrap().state_ref,
        current.state_ref
    );
    assert!(
        machine
            .head(alice.name_id().unwrap())
            .unwrap()
            .abandoned_height
            .is_none()
    );
    source.insert(block.height, block);
    assert_fresh_matches_replay(&machine, &source, "nf-binding");
}

#[test]
fn fresh_resolution_matches_replay_across_adversarial_spends() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(39, "parity", b"record");
    let (_, current, _) = register(&mut machine, &mut source, &alice, 45);
    let name_id = alice.name_id().unwrap();

    // A canonical spend of the accepted head note with an invalid Names
    // successor abandons the head in replay and fresh resolution alike.
    let tip = machine.tip();
    let invalid_successor = state_after(
        &current,
        b"record",
        1,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let commitment = field(4_401);
    let invalid_successor_block = CanonicalBlock {
        height: tip.height + 1,
        block_hash: [0x51; 32],
        prev_block_hash: tip.block_hash,
        transactions: vec![transaction(
            0,
            46,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: current.state_ref.nullifier,
                commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                current.state_ref,
                invalid_successor,
                commitment,
                0,
            )],
        )],
    };
    let applied = machine
        .apply_block(&invalid_successor_block, &AcceptingProofs)
        .unwrap();
    assert_rejected(&applied, ApplyError::InvalidStateProof);
    let abandoned = machine.head(name_id).unwrap().clone();
    assert_eq!(
        abandoned.abandoned_height,
        Some(invalid_successor_block.height)
    );
    source.insert(invalid_successor_block.height, invalid_successor_block);
    assert_fresh_matches_replay(&machine, &source, "parity");
    assert_eq!(
        machine.resolution_at(name_id, machine.tip().height),
        ResolutionStatus::Abandoned
    );

    // A later transition from the abandoned head is stale in both views,
    // and the abandoned head is not silently restored.
    let tip = machine.tip();
    let stale_successor = state_after(
        &abandoned,
        b"changed",
        1,
        abandoned.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let stale_commitment = field(4_402);
    let stale_block = CanonicalBlock {
        height: tip.height + 1,
        block_hash: [0x52; 32],
        prev_block_hash: tip.block_hash,
        transactions: vec![transaction(
            0,
            47,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: abandoned.state_ref.nullifier,
                commitment: stale_commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                abandoned.state_ref,
                stale_successor,
                stale_commitment,
                0,
            )],
        )],
    };
    let applied = machine.apply_block(&stale_block, &AcceptingProofs).unwrap();
    assert_rejected(&applied, ApplyError::StalePredecessor);
    source.insert(stale_block.height, stale_block);
    assert_fresh_matches_replay(&machine, &source, "parity");
    assert_eq!(
        machine.resolution_at(name_id, machine.tip().height),
        ResolutionStatus::Abandoned
    );

    // Once the reuse delay passes, both views resolve the name expired.
    let claimable = params
        .head_claimable_from(&abandoned.data, abandoned.abandoned_height)
        .unwrap();
    advance_to(&mut machine, &mut source, claimable);
    assert_eq!(
        machine.resolution_at(name_id, machine.tip().height),
        ResolutionStatus::Expired
    );
    assert_fresh_matches_replay(&machine, &source, "parity");
}

#[test]
fn unauthenticated_predecessor_claims_are_skipped_without_poisoning_resolution() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(43, "claim-skip", b"record");
    let (_, current, _) = register(&mut machine, &mut source, &alice, 43);
    let name_id = alice.name_id().unwrap();

    // An UPDATE whose predecessor claim points inside canonical history
    // but not at an accepted Names producer is unaccepted in replay and
    // skipped by fresh resolution; it must not poison the name. The same
    // block also carries a claim pointing beyond the canonical tip.
    let tip = machine.tip();
    let forged_successor = state_after(
        &current,
        b"changed",
        1,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let forged_commitment = field(4_601);
    let forged_claim = StateRef::new(
        ProducerPosition::new(current.state_ref.producer_height, 0, [0xff; 32]),
        0,
        0,
        forged_commitment,
        field(4_602),
    );
    let beyond_tip_claim = StateRef::new(
        ProducerPosition::new(tip.height + 50, 0, [0xfe; 32]),
        0,
        0,
        forged_commitment,
        field(4_602),
    );
    let forged_block = CanonicalBlock {
        height: tip.height + 1,
        block_hash: [0x61; 32],
        prev_block_hash: tip.block_hash,
        transactions: vec![
            transaction(
                0,
                45,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: forged_claim.nullifier,
                    commitment: forged_commitment,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    forged_claim,
                    forged_successor.clone(),
                    forged_commitment,
                    0,
                )],
            ),
            transaction(
                1,
                46,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: beyond_tip_claim.nullifier,
                    commitment: forged_commitment,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    beyond_tip_claim,
                    forged_successor,
                    forged_commitment,
                    0,
                )],
            ),
        ],
    };
    let applied = machine
        .apply_block(&forged_block, &AcceptingProofs)
        .unwrap();
    assert!(matches!(
        applied.operations.as_slice(),
        [
            AppliedOperation {
                result: AppliedOperationResult::Rejected(ApplyError::StalePredecessor),
                ..
            },
            AppliedOperation {
                result: AppliedOperationResult::Rejected(ApplyError::StalePredecessor),
                ..
            },
        ]
    ));
    source.insert(forged_block.height, forged_block);
    assert_fresh_matches_replay(&machine, &source, "claim-skip");

    // The accepted head still updates normally afterwards.
    let successor = state_after(
        &current,
        b"changed",
        1,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let commitment = field(4_603);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            46,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: current.state_ref.nullifier,
                commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                current.state_ref,
                successor,
                commitment,
                0,
            )],
        )],
    )
    .unwrap();
    assert_fresh_matches_replay(&machine, &source, "claim-skip");

    // A reclaiming REVEAL with an equally forged replacement predecessor
    // fails on the same authenticate_accepted_state_ref boundary in fresh
    // resolution and is rejected in replay: skipped, never fatal, and the
    // accepted head is untouched.
    let bob = intent(46, "claim-skip", b"bob-record");
    let bob_commit = commit(&mut machine, &mut source, &bob, 0, 47);
    let reveal_height =
        schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let bob_commitment = field(4_604);
    let bob_state = StateData {
        name_id,
        owner_pk: bob.owner_pk,
        sequence: 0,
        record: bob.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let hostile_reveal_block = CanonicalBlock {
        height: reveal_height,
        block_hash: [0x62; 32],
        prev_block_hash: machine.tip().block_hash,
        transactions: vec![transaction(
            0,
            48,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(4_605),
                commitment: bob_commitment,
            }],
            vec![reveal_operation(
                &bob,
                bob_commit,
                bob_state,
                bob_commitment,
                Some(forged_claim),
            )],
        )],
    };
    let applied = machine
        .apply_block(&hostile_reveal_block, &AcceptingProofs)
        .unwrap();
    assert_rejected(&applied, ApplyError::NameUnavailable);
    source.insert(hostile_reveal_block.height, hostile_reveal_block);
    assert_fresh_matches_replay(&machine, &source, "claim-skip");
}

#[test]
fn structural_source_failure_while_authenticating_predecessor_remains_fatal() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    // Register late enough that the COMMIT carrier's pending-scan window
    // stays above activation history, so the only path from the claimed
    // producer down to the activation-era block is the recursive lineage
    // replay inside authenticate_accepted_state_ref.
    advance_to(&mut machine, &mut source, 19);
    let alice = intent(47, "fatal-source", b"record");
    let (reveal_height, current, _) = register(&mut machine, &mut source, &alice, 49);
    let name_id = alice.name_id().unwrap();

    // Update from the accepted head, then extend the tip so that the
    // activation-era history lies below the fresh window and the fallback
    // reset window alike. Only the recursive lineage replay inside
    // authenticate_accepted_state_ref still reaches it.
    let update_height = reveal_height + params.max_anchor_age().unwrap() + 1;
    advance_to(&mut machine, &mut source, update_height - 1);
    let successor = state_after(
        &current,
        b"changed",
        1,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let commitment = field(4_701);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            50,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: current.state_ref.nullifier,
                commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                current.state_ref,
                successor,
                commitment,
                0,
            )],
        )],
    )
    .unwrap();
    let tip_height = reveal_height + 30;
    advance_to(&mut machine, &mut source, tip_height);

    // Control: with complete history the bounded replay bootstraps from
    // the authenticated claim and matches replay exactly.
    assert_fresh_matches_replay(&machine, &source, "fatal-source");

    // Removing one canonical block below every window sweep breaks the
    // recursive authentication of the claimed predecessor. That is
    // source/history corruption: it must surface as the fatal lineage
    // error, never as a normal Missing/Abandoned resolution outcome, and
    // it must not be downgraded to an unaccepted operation.
    let gap_height = params.activation_height;
    let gap_block = source.remove(&gap_height).unwrap();
    assert_eq!(
        FreshResolver::new(params)
            .unwrap()
            .resolve("fatal-source", &source, &AcceptingProofs,),
        Err(ResolveError::InvalidLineage)
    );

    // Restoring the canonical source restores normal resolution.
    source.insert(gap_height, gap_block);
    assert_fresh_matches_replay(&machine, &source, "fatal-source");
    assert_eq!(machine.head(name_id).unwrap().data.sequence, 1);
}

#[test]
fn forged_commit_references_are_skipped_without_poisoning_resolution() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(48, "commit-claim-skip", b"alice-record");
    let (_, current, _) = register(&mut machine, &mut source, &alice, 51);
    let name_id = alice.name_id().unwrap();

    let bob = intent(49, "commit-claim-skip", b"bob-record");
    let accepted_commit = commit(&mut machine, &mut source, &bob, 0, 52);
    let duplicate_height = machine.tip().height + 1;
    let duplicate_position = ProducerPosition::new(duplicate_height, 0, [53; 32]);
    let duplicate = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            53,
            Vec::new(),
            vec![V1Operation::Commit {
                commitment: accepted_commit.commitment,
            }],
        )],
    )
    .unwrap();
    assert_rejected(&duplicate, ApplyError::DuplicateCommitment);
    let rejected_duplicate = CommitRef::new(duplicate_position, 0, accepted_commit.commitment);

    let reveal_height =
        schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let replacement_state = StateData {
        name_id,
        owner_pk: bob.owner_pk,
        sequence: 0,
        record: bob.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };

    let mut beyond_tip = accepted_commit;
    beyond_tip.position.height = reveal_height + 50;
    let mut wrong_txid = accepted_commit;
    wrong_txid.position.txid = [0xfe; 32];
    let mut wrong_tx_index = accepted_commit;
    wrong_tx_index.position.tx_index += 1;
    let mut wrong_operation_index = accepted_commit;
    wrong_operation_index.operation_index += 1;
    let forged = [
        beyond_tip,
        wrong_txid,
        wrong_tx_index,
        wrong_operation_index,
        rejected_duplicate,
    ];
    let transactions = forged
        .into_iter()
        .enumerate()
        .map(|(index, commit)| {
            let action_commitment = field(4_800 + index as u64);
            transaction(
                index as u32,
                54 + index as u8,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(4_900 + index as u64),
                    commitment: action_commitment,
                }],
                vec![reveal_operation(
                    &bob,
                    commit,
                    replacement_state.clone(),
                    action_commitment,
                    None,
                )],
            )
        })
        .collect();
    let hostile_block = CanonicalBlock {
        height: reveal_height,
        block_hash: [0x63; 32],
        prev_block_hash: machine.tip().block_hash,
        transactions,
    };
    let applied = machine
        .apply_block(&hostile_block, &AcceptingProofs)
        .unwrap();
    assert!(applied.operations.iter().all(|operation| matches!(
        operation.result,
        AppliedOperationResult::Rejected(
            ApplyError::CommitmentMismatch | ApplyError::UnknownCommitment
        )
    )));
    source.insert(hostile_block.height, hostile_block);

    assert_eq!(machine.head(name_id).unwrap().state_ref, current.state_ref);
    assert_fresh_matches_replay(&machine, &source, "commit-claim-skip");

    // Resolution continues through a later valid operation on the real
    // accepted head; none of the forged references poison the name.
    let successor = state_after(
        &current,
        b"alice-updated",
        1,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let successor_commitment = field(4_950);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            59,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: current.state_ref.nullifier,
                commitment: successor_commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                current.state_ref,
                successor,
                successor_commitment,
                0,
            )],
        )],
    )
    .unwrap();
    assert_fresh_matches_replay(&machine, &source, "commit-claim-skip");
    assert_eq!(machine.head(name_id).unwrap().data.sequence, 1);
}

#[test]
fn structural_commit_history_failures_remain_fatal() {
    let params = V1Parameters {
        activation_height: 1,
        epoch_size: 2,
        commit_ttl_blocks: 8,
        refresh_deadline_blocks: 3,
        lease_duration_blocks: 12,
        grace_period_blocks: 3,
        reuse_delay_blocks: 4,
        max_record_bytes: super::super::state::MAX_RECORD_BYTES,
        minimum_bond_zatoshis: 1,
    };
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    advance_to(&mut machine, &mut source, 9);
    let alice = intent(50, "commit-source", b"record");
    let (reveal_height, _, accepted_commit) = register(&mut machine, &mut source, &alice, 60);
    let fresh_lower = reveal_height - params.max_anchor_age().unwrap();
    let commit_lower = accepted_commit
        .position
        .height
        .saturating_sub(params.commit_ttl_blocks)
        .max(params.activation_height);
    let corrupted_height = commit_lower + 1;
    assert!(corrupted_height < fresh_lower);
    assert!(corrupted_height < accepted_commit.position.height);
    assert_fresh_matches_replay(&machine, &source, "commit-source");

    // A missing block genuinely required to reconstruct the accepted
    // COMMIT's pending window is fatal, even though it lies below the
    // ordinary fresh-name sweep.
    let original = source.remove(&corrupted_height).unwrap();
    assert_eq!(
        FreshResolver::new(params)
            .unwrap()
            .resolve("commit-source", &source, &AcceptingProofs),
        Err(ResolveError::InvalidLineage)
    );
    source.insert(corrupted_height, original.clone());

    // Malformed canonical transaction shape in that same required range
    // is also source corruption, not an unauthenticated COMMIT claim.
    let malformed = source.get_mut(&corrupted_height).unwrap();
    malformed.transactions = vec![
        transaction(0, 61, Vec::new(), Vec::new()),
        transaction(0, 62, Vec::new(), Vec::new()),
    ];
    assert_eq!(
        FreshResolver::new(params)
            .unwrap()
            .resolve("commit-source", &source, &AcceptingProofs),
        Err(ResolveError::InvalidLineage)
    );
    source.insert(corrupted_height, original);

    // Internal linkage across the contiguous authentication range is
    // equally structural and remains fatal.
    source
        .get_mut(&(corrupted_height + 1))
        .unwrap()
        .prev_block_hash = [0xfd; 32];
    assert_eq!(
        FreshResolver::new(params)
            .unwrap()
            .resolve("commit-source", &source, &AcceptingProofs),
        Err(ResolveError::InvalidLineage)
    );
}

#[test]
fn reveal_action_claim_failures_are_nonfatal() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(51, "reveal-action-claim", b"record");
    let commit = commit(&mut machine, &mut source, &alice, 0, 63);
    let name_id = alice.name_id().unwrap();
    let reveal_height =
        schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let state = StateData {
        name_id,
        owner_pk: alice.owner_pk,
        sequence: 0,
        record: alice.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let declared_commitment = field(5_001);
    let malformed_reveal = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            64,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(5_002),
                commitment: field(5_003),
            }],
            vec![reveal_operation(
                &alice,
                commit,
                state,
                declared_commitment,
                None,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&malformed_reveal, ApplyError::ActionCommitmentMismatch);
    assert_fresh_matches_replay(&machine, &source, "reveal-action-claim");
}

#[test]
fn future_predecessor_claim_cannot_bootstrap_bounded_replay() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(52, "future-predecessor", b"record-0");
    let (reveal_height, current, _) = register(&mut machine, &mut source, &alice, 65);
    let name_id = alice.name_id().unwrap();

    // Put a proof-shaped hostile RENEW beyond the fresh window of the real
    // anchor. Its claimed predecessor is an UPDATE that will not be
    // produced until the following block.
    let hostile_height = schedule::next_anchor_height(
        name_id,
        reveal_height + params.max_anchor_age().unwrap() + 1,
        params,
    )
    .unwrap();
    assert!(hostile_height < current.data.lease_expiry);
    advance_to(&mut machine, &mut source, hostile_height - 1);
    let future_height = hostile_height + 1;
    let future_commitment = field(5_101);
    let future_ref = StateRef::new(
        ProducerPosition::new(future_height, 0, [67; 32]),
        0,
        0,
        future_commitment,
        future_commitment,
    );
    let future_state = state_after(
        &current,
        b"record-1",
        1,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let hostile_state = StateData {
        name_id,
        owner_pk: current.data.owner_pk,
        sequence: 2,
        record: future_state.record.clone(),
        lease_expiry: params.lease_expiry(hostile_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let hostile_commitment = field(5_102);
    let hostile_block = CanonicalBlock {
        height: hostile_height,
        block_hash: [0x64; 32],
        prev_block_hash: machine.tip().block_hash,
        transactions: vec![transaction(
            0,
            66,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: future_ref.nullifier,
                commitment: hostile_commitment,
            }],
            vec![transition_operation(
                OperationKind::Renew,
                future_ref,
                hostile_state,
                hostile_commitment,
                0,
            )],
        )],
    };
    let applied = machine
        .apply_block(&hostile_block, &AcceptingProofs)
        .unwrap();
    assert_rejected(&applied, ApplyError::StalePredecessor);
    source.insert(hostile_block.height, hostile_block);

    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            67,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: current.state_ref.nullifier,
                commitment: future_commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                current.state_ref,
                future_state,
                future_commitment,
                0,
            )],
        )],
    )
    .unwrap();
    assert_eq!(machine.tip().height, future_height);
    assert_fresh_matches_replay(&machine, &source, "future-predecessor");
    assert_eq!(machine.head(name_id).unwrap().data.sequence, 1);
}

#[test]
fn last_grace_spend_cannot_extend_reset_claimability() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(37, "grace-spend", b"record");
    let (anchor, state, _) = register(&mut machine, &mut source, &alice, 43);
    let name_id = alice.name_id().unwrap();
    let ordinary_claimable = state.data.lease_expiry + params.grace_period_blocks;
    assert_eq!(ordinary_claimable, anchor + params.reset_horizon().unwrap());

    let last_grace_height = ordinary_claimable - 1;
    advance_to(&mut machine, &mut source, last_grace_height - 1);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            44,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: state.state_ref.nullifier,
                commitment: field(3701),
            }],
            Vec::new(),
        )],
    )
    .unwrap();
    assert_eq!(
        machine.resolution_at(name_id, last_grace_height),
        ResolutionStatus::Abandoned
    );
    assert_fresh_matches_replay(&machine, &source, "grace-spend");

    advance_to(&mut machine, &mut source, ordinary_claimable);
    assert_eq!(
        machine.resolution_at(name_id, ordinary_claimable),
        ResolutionStatus::Expired
    );
    assert_fresh_matches_replay(&machine, &source, "grace-spend");
}

#[test]
fn reveal_cannot_reference_a_rejected_duplicate_commit_message() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(34, "duplicate-commit", b"record");
    let commitment = alice.commitment().unwrap();
    let commit_position = ProducerPosition::new(1, 0, [35; 32]);
    let rejected_duplicate = CommitRef::new(commit_position, 1, commitment);
    let commits = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            35,
            Vec::new(),
            vec![
                V1Operation::Commit { commitment },
                V1Operation::Commit { commitment },
            ],
        )],
    )
    .unwrap();
    assert_rejected(&commits, ApplyError::DuplicateCommitment);
    let name_id = alice.name_id().unwrap();
    let reveal_height = schedule::next_anchor_height(name_id, 2, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let state = StateData {
        name_id,
        owner_pk: alice.owner_pk,
        sequence: 0,
        record: alice.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let reveal = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            36,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(3400),
                commitment: field(3401),
            }],
            vec![reveal_operation(
                &alice,
                rejected_duplicate,
                state,
                field(3401),
                None,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&reveal, ApplyError::CommitmentMismatch);
    assert_fresh_matches_replay(&machine, &source, "duplicate-commit");
}

#[test]
fn fresh_resolution_rejects_cryptographically_valid_shadow_reveal_lineage() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let original = intent(40, "shadow", b"old-record");
    let (_, state0, _) = register(&mut machine, &mut source, &original, 40);
    let release_height = machine.tip().height + 1;
    let released = state_after(
        &state0,
        b"old-record",
        1,
        state0.data.lease_expiry,
        StateStatus::Released,
        release_height,
    );
    let release_commitment = field(4001);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            41,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(4002),
                commitment: release_commitment,
            }],
            vec![transition_operation(
                OperationKind::Release,
                state0.state_ref,
                released,
                release_commitment,
                0,
            )],
        )],
    )
    .unwrap();
    let terminal = machine.head(original.name_id().unwrap()).unwrap().clone();
    let claimable = release_height + params.reuse_delay_blocks;
    advance_to(&mut machine, &mut source, claimable);

    let bob = intent(41, "shadow", b"bob-record");
    let charlie = intent(42, "shadow", b"charlie-record");
    let commit_height = machine.tip().height + 1;
    let bob_commit = CommitRef::new(
        ProducerPosition::new(commit_height, 0, [42; 32]),
        0,
        bob.commitment().unwrap(),
    );
    let charlie_commit = CommitRef::new(
        ProducerPosition::new(commit_height, 1, [43; 32]),
        0,
        charlie.commitment().unwrap(),
    );
    append(
        &mut machine,
        &mut source,
        vec![
            transaction(
                0,
                42,
                Vec::new(),
                vec![V1Operation::Commit {
                    commitment: bob_commit.commitment,
                }],
            ),
            transaction(
                1,
                43,
                Vec::new(),
                vec![V1Operation::Commit {
                    commitment: charlie_commit.commitment,
                }],
            ),
        ],
    )
    .unwrap();
    let name_id = bob.name_id().unwrap();
    let reveal_height = schedule::next_anchor_height(name_id, commit_height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let bob_commitment = field(4003);
    let charlie_commitment = field(4004);
    let bob_state = StateData {
        name_id,
        owner_pk: bob.owner_pk,
        sequence: 0,
        record: bob.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let charlie_state = StateData {
        name_id,
        owner_pk: charlie.owner_pk,
        sequence: 0,
        record: charlie.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let reveals = append(
        &mut machine,
        &mut source,
        vec![
            transaction(
                0,
                44,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(4005),
                    commitment: bob_commitment,
                }],
                vec![reveal_operation(
                    &bob,
                    bob_commit,
                    bob_state,
                    bob_commitment,
                    Some(terminal.state_ref),
                )],
            ),
            transaction(
                1,
                45,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(4006),
                    commitment: charlie_commitment,
                }],
                vec![reveal_operation(
                    &charlie,
                    charlie_commit,
                    charlie_state.clone(),
                    charlie_commitment,
                    Some(terminal.state_ref),
                )],
            ),
        ],
    )
    .unwrap();
    assert!(matches!(
        reveals.operations.as_slice(),
        [
            AppliedOperation {
                result: AppliedOperationResult::Accepted(Some((_, AppliedOperationKind::Reveal))),
                ..
            },
            AppliedOperation {
                result: AppliedOperationResult::Rejected(ApplyError::NameUnavailable),
                ..
            },
        ]
    ));
    let bob_head = machine.head(name_id).unwrap().clone();
    let shadow0 = NameState::new(
        charlie_state,
        charlie_commitment,
        StateRef::new(
            ProducerPosition::new(reveal_height, 1, [45; 32]),
            0,
            0,
            charlie_commitment,
            charlie_commitment,
        ),
    )
    .unwrap();
    let shadow_update_state = state_after(
        &shadow0,
        b"charlie-update",
        1,
        shadow0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let shadow_update_commitment = field(4007);
    let shadow_update_height = machine.tip().height + 1;
    let update = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            46,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(4008),
                commitment: shadow_update_commitment,
            }],
            vec![transition_operation(
                OperationKind::Update,
                shadow0.state_ref,
                shadow_update_state.clone(),
                shadow_update_commitment,
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&update, ApplyError::StalePredecessor);

    let renew_height =
        schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, renew_height - 1);
    let shadow_update = NameState::new(
        shadow_update_state,
        shadow_update_commitment,
        StateRef::new(
            ProducerPosition::new(shadow_update_height, 0, [46; 32]),
            0,
            0,
            shadow_update_commitment,
            shadow_update_commitment,
        ),
    )
    .unwrap();
    let shadow_renew = state_after(
        &shadow_update,
        b"charlie-update",
        2,
        params.lease_expiry(renew_height).unwrap(),
        StateStatus::Active,
        0,
    );
    let renew = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            47,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(4009),
                commitment: field(4010),
            }],
            vec![transition_operation(
                OperationKind::Renew,
                shadow_update.state_ref,
                shadow_renew,
                field(4010),
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&renew, ApplyError::StalePredecessor);
    assert_eq!(machine.head(name_id).unwrap().state_ref, bob_head.state_ref);

    // Bob's accepted anchor is now beyond the reset horizon, while the
    // rejected Charlie renewal is recent. It must not block a
    // no-predecessor reset registration.
    let reset_commit_height = reveal_height + params.reset_horizon().unwrap();
    advance_to(&mut machine, &mut source, reset_commit_height - 1);
    let dana = intent(43, "shadow", b"dana-record");
    let dana_commit = commit(&mut machine, &mut source, &dana, 0, 48);
    assert_eq!(dana_commit.position.height, reset_commit_height);
    let dana_reveal_height =
        schedule::next_anchor_height(name_id, reset_commit_height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, dana_reveal_height - 1);
    let dana_state = StateData {
        name_id,
        owner_pk: dana.owner_pk,
        sequence: 0,
        record: dana.record.clone(),
        lease_expiry: params.lease_expiry(dana_reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let reset = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            49,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(4011),
                commitment: field(4012),
            }],
            vec![reveal_operation(
                &dana,
                dana_commit,
                dana_state,
                field(4012),
                None,
            )],
        )],
    )
    .unwrap();
    assert!(matches!(
        reset.operations.last(),
        Some(AppliedOperation {
            result: AppliedOperationResult::Accepted(Some((name, AppliedOperationKind::Reveal))),
            ..
        }) if *name == name_id
    ));
    assert_fresh_matches_replay(&machine, &source, "shadow");
}

fn advance_to(
    machine: &mut V1StateMachine,
    source: &mut BTreeMap<u32, CanonicalBlock>,
    height: u32,
) {
    while machine.tip().height < height {
        append(machine, source, Vec::new()).unwrap();
    }
}

fn commit(
    machine: &mut V1StateMachine,
    source: &mut BTreeMap<u32, CanonicalBlock>,
    intent: &RegistrationIntent,
    tx_index: u32,
    txid: u8,
) -> CommitRef {
    let commitment = intent.commitment().unwrap();
    let height = machine.tip().height + 1;
    let position = ProducerPosition::new(height, tx_index, [txid; 32]);
    append(
        machine,
        source,
        vec![transaction(
            tx_index,
            txid,
            Vec::new(),
            vec![V1Operation::Commit { commitment }],
        )],
    )
    .unwrap();
    CommitRef::new(position, 0, commitment)
}

fn reveal_operation(
    intent: &RegistrationIntent,
    commit: CommitRef,
    state: StateData,
    commitment: [u8; 32],
    replacement_predecessor: Option<StateRef>,
) -> V1Operation {
    V1Operation::Reveal {
        intent: Box::new(intent.clone()),
        commit,
        replacement_predecessor,
        state,
        state_commitment: commitment,
        state_nullifier: commitment,
        action_index: 0,
        proof: vec![1],
    }
}

fn register(
    machine: &mut V1StateMachine,
    source: &mut BTreeMap<u32, CanonicalBlock>,
    intent: &RegistrationIntent,
    txid: u8,
) -> (u32, NameState, CommitRef) {
    let params = machine.params();
    let commit = commit(machine, source, intent, 0, txid);
    let name_id = intent.name_id().unwrap();
    let reveal_height =
        schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
    advance_to(machine, source, reveal_height - 1);
    let commitment = field(u64::from(txid) + 100);
    let state = StateData {
        name_id,
        owner_pk: intent.owner_pk,
        sequence: 0,
        record: intent.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let op = reveal_operation(intent, commit, state, commitment, None);
    let action = IronwoodActionRef {
        action_index: 0,
        nullifier: field(u64::from(txid) + 200),
        commitment,
    };
    append(
        machine,
        source,
        vec![transaction(0, txid.wrapping_add(1), vec![action], vec![op])],
    )
    .unwrap();
    (
        reveal_height,
        machine.head(name_id).unwrap().clone(),
        commit,
    )
}

fn state_after(
    previous: &NameState,
    record: &[u8],
    sequence: u64,
    lease_expiry: u32,
    status: StateStatus,
    terminal_height: u32,
) -> StateData {
    StateData {
        name_id: previous.data.name_id,
        owner_pk: previous.data.owner_pk,
        sequence,
        record: record.to_vec(),
        lease_expiry,
        status,
        terminal_height,
    }
}

fn transition_operation(
    kind: OperationKind,
    predecessor: StateRef,
    state: StateData,
    commitment: [u8; 32],
    action_index: u32,
) -> V1Operation {
    match kind {
        OperationKind::Update => V1Operation::Update {
            predecessor,
            state,
            state_commitment: commitment,
            state_nullifier: commitment,
            action_index,
            proof: vec![1],
        },
        OperationKind::Renew => V1Operation::Renew {
            predecessor,
            state,
            state_commitment: commitment,
            state_nullifier: commitment,
            action_index,
            proof: vec![1],
        },
        OperationKind::Release => V1Operation::Release {
            predecessor,
            state,
            state_commitment: commitment,
            state_nullifier: commitment,
            action_index,
            proof: vec![1],
        },
    }
}

#[test]
fn vertical_slice_registers_updates_renews_and_releases_one_name() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(1, "alice", b"record-0");
    let (reveal_height, state0, _) = register(&mut machine, &mut source, &alice, 10);
    let name_id = alice.name_id().unwrap();

    let state1 = state_after(
        &state0,
        b"record-1",
        1,
        state0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let cm1 = field(301);
    let update1 = transition_operation(OperationKind::Update, state0.state_ref, state1, cm1, 0);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            30,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(401),
                commitment: cm1,
            }],
            vec![update1],
        )],
    )
    .unwrap();
    let state1 = machine.head(name_id).unwrap().clone();

    let state2 = state_after(
        &state1,
        b"record-2",
        2,
        state1.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let cm2 = field(302);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            31,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(402),
                commitment: cm2,
            }],
            vec![transition_operation(
                OperationKind::Update,
                state1.state_ref,
                state2,
                cm2,
                0,
            )],
        )],
    )
    .unwrap();
    let state2 = machine.head(name_id).unwrap().clone();

    let renew_height =
        schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
    assert!(renew_height < state2.data.lease_expiry);
    advance_to(&mut machine, &mut source, renew_height - 1);
    let state3 = state_after(
        &state2,
        b"record-2",
        3,
        params.lease_expiry(renew_height).unwrap(),
        StateStatus::Active,
        0,
    );
    let cm3 = field(303);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            32,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(403),
                commitment: cm3,
            }],
            vec![transition_operation(
                OperationKind::Renew,
                state2.state_ref,
                state3,
                cm3,
                0,
            )],
        )],
    )
    .unwrap();
    let state3 = machine.head(name_id).unwrap().clone();
    assert_eq!(state3.data.record, b"record-2");
    assert!(state3.data.lease_expiry > state2.data.lease_expiry);

    let update_height = renew_height + 1;
    advance_to(&mut machine, &mut source, update_height - 1);
    let state4 = state_after(
        &state3,
        b"record-3",
        4,
        state3.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let cm4 = field(304);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            33,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(404),
                commitment: cm4,
            }],
            vec![transition_operation(
                OperationKind::Update,
                state3.state_ref,
                state4,
                cm4,
                0,
            )],
        )],
    )
    .unwrap();
    let state4 = machine.head(name_id).unwrap().clone();
    assert_eq!(state4.data.lease_expiry, state3.data.lease_expiry);

    let release_height = update_height + 1;
    let state5 = state_after(
        &state4,
        b"record-3",
        5,
        state4.data.lease_expiry,
        StateStatus::Released,
        release_height,
    );
    let cm5 = field(305);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            34,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(405),
                commitment: cm5,
            }],
            vec![transition_operation(
                OperationKind::Release,
                state4.state_ref,
                state5,
                cm5,
                0,
            )],
        )],
    )
    .unwrap();
    assert_eq!(
        machine.resolution_at(name_id, machine.tip().height),
        ResolutionStatus::Released
    );
    let resolved = FreshResolver::new(params)
        .unwrap()
        .resolve("alice", &source, &AcceptingProofs)
        .unwrap();
    assert_eq!(resolved.status, ResolutionStatus::Released);
    assert_eq!(resolved.state.unwrap().data.sequence, 5);
    assert!(resolved.stats.candidate_block_probes >= 1);
    assert!(resolved.stats.tail_blocks_scanned >= 2);
    assert!(resolved.stats.predecessor_chain_steps >= 5);
    assert_fresh_matches_replay(&machine, &source, "alice");

    let before_first_renew = source
        .iter()
        .filter(|(height, _)| **height <= reveal_height)
        .map(|(height, block)| (*height, block.clone()))
        .collect::<BTreeMap<_, _>>();
    let first_lookup = FreshResolver::new(params)
        .unwrap()
        .resolve("alice", &before_first_renew, &AcceptingProofs)
        .unwrap();
    assert_eq!(first_lookup.status, ResolutionStatus::Active);
    assert_eq!(first_lookup.state.unwrap().data.sequence, 0);

    let mut no_anchor = source.clone();
    for block in no_anchor.values_mut() {
        for transaction in &mut block.transactions {
            transaction.operations.retain(|operation| {
                !matches!(
                    operation,
                    V1Operation::Reveal { .. } | V1Operation::Renew { .. }
                )
            });
        }
    }
    // A source whose lineage was stripped resolves to the same outcome
    // replay would produce: no accepted producer, hence no state head.
    // Unaccepted lineage claims are skipped, never hard errors.
    let missing = FreshResolver::new(params)
        .unwrap()
        .resolve("alice", &no_anchor, &AcceptingProofs)
        .unwrap();
    assert_eq!(missing.status, ResolutionStatus::Missing);
    assert!(missing.state.is_none());
    assert!(missing.anchor.is_none());

    let mut reorged_anchor = source.clone();
    reorged_anchor
        .get_mut(&renew_height)
        .unwrap()
        .transactions
        .clear();
    reorged_anchor.get_mut(&renew_height).unwrap().block_hash = [0xee; 32];
    assert_eq!(
        FreshResolver::new(params)
            .unwrap()
            .resolve("alice", &reorged_anchor, &AcceptingProofs),
        Err(ResolveError::InvalidLineage)
    );

    let mut reorged_predecessor = source.clone();
    reorged_predecessor
        .get_mut(&reveal_height)
        .unwrap()
        .transactions
        .clear();
    reorged_predecessor
        .get_mut(&reveal_height)
        .unwrap()
        .block_hash = [0xdd; 32];
    assert_eq!(
        FreshResolver::new(params).unwrap().resolve(
            "alice",
            &reorged_predecessor,
            &AcceptingProofs
        ),
        Err(ResolveError::InvalidLineage)
    );
    assert!(reveal_height < machine.tip().height);
}

#[test]
fn missed_renewal_and_release_have_non_payable_boundaries() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(10, "lease", b"record");
    let (_, state0, _) = register(&mut machine, &mut source, &alice, 90);
    let name_id = alice.name_id().unwrap();
    let expiry = state0.data.lease_expiry;

    let renewal_height =
        schedule::next_anchor_height(name_id, machine.tip().height + 1, params).unwrap();
    advance_to(&mut machine, &mut source, renewal_height - 1);
    let invalid_renewal = state_after(&state0, b"record", 1, expiry + 1, StateStatus::Active, 0);
    let invalid_renewal_result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            89,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(1099),
                commitment: field(1100),
            }],
            vec![transition_operation(
                OperationKind::Renew,
                state0.state_ref,
                invalid_renewal,
                field(1100),
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&invalid_renewal_result, ApplyError::InvalidStateProof);
    assert_eq!(
        machine.resolution_at(name_id, renewal_height),
        ResolutionStatus::Abandoned
    );

    advance_to(&mut machine, &mut source, expiry);
    assert_eq!(
        machine.resolution_at(name_id, expiry),
        ResolutionStatus::Expired
    );
    assert_eq!(
        machine.resolution_at(name_id, expiry + params.grace_period_blocks - 1),
        ResolutionStatus::Expired
    );
    advance_to(
        &mut machine,
        &mut source,
        expiry + params.grace_period_blocks,
    );
    assert_eq!(
        machine.resolution_at(name_id, machine.tip().height),
        ResolutionStatus::Expired
    );
    let stale_lookup = FreshResolver::new(params)
        .unwrap()
        .resolve("lease", &source, &AcceptingProofs)
        .unwrap();
    assert_eq!(stale_lookup.status, ResolutionStatus::Expired);
    assert!(stale_lookup.state.is_some());
    assert_fresh_matches_replay(&machine, &source, "lease");

    let update = state_after(
        &state0,
        b"should-fail",
        1,
        state0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let update_result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            91,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(1101),
                commitment: field(1102),
            }],
            vec![transition_operation(
                OperationKind::Update,
                state0.state_ref,
                update,
                field(1102),
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&update_result, ApplyError::StalePredecessor);

    let mut release_machine = V1StateMachine::new(params).unwrap();
    let mut release_source = BTreeMap::new();
    let release_intent = intent(11, "release-lease", b"record");
    let (_, release_state, _) = register(
        &mut release_machine,
        &mut release_source,
        &release_intent,
        92,
    );
    let terminal_height = release_machine.tip().height + 1;
    let terminal = state_after(
        &release_state,
        b"record",
        1,
        release_state.data.lease_expiry,
        StateStatus::Released,
        terminal_height,
    );
    let terminal_commitment = field(1103);
    append(
        &mut release_machine,
        &mut release_source,
        vec![transaction(
            0,
            93,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(1104),
                commitment: terminal_commitment,
            }],
            vec![transition_operation(
                OperationKind::Release,
                release_state.state_ref,
                terminal,
                terminal_commitment,
                0,
            )],
        )],
    )
    .unwrap();
    let release_name = release_intent.name_id().unwrap();
    assert_eq!(
        release_machine.resolution_at(release_name, terminal_height),
        ResolutionStatus::Released
    );
    let release_claimable = terminal_height + params.reuse_delay_blocks;
    assert_eq!(
        release_machine.resolution_at(release_name, release_claimable - 1),
        ResolutionStatus::Released
    );
    assert_eq!(
        release_machine.resolution_at(release_name, release_claimable),
        ResolutionStatus::Expired
    );
}

#[test]
fn registration_preserves_two_stage_maturity_slot_and_reclaim_boundaries() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(2, "alice", b"record");
    let commitment = alice.commitment().unwrap();
    let same_block_position = ProducerPosition::new(1, 0, [9; 32]);
    let same_block_state = StateData {
        name_id: alice.name_id().unwrap(),
        owner_pk: alice.owner_pk,
        sequence: 0,
        record: alice.record.clone(),
        lease_expiry: params.lease_expiry(1).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let same_block = reveal_operation(
        &alice,
        CommitRef::new(same_block_position, 0, commitment),
        same_block_state,
        field(500),
        None,
    );
    let same_block_result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            9,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(501),
                commitment: field(500),
            }],
            vec![V1Operation::Commit { commitment }, same_block],
        )],
    )
    .unwrap();
    assert_rejected(&same_block_result, ApplyError::SameBlockCommitReveal);

    let commit_ref = commit(&mut machine, &mut source, &alice, 0, 10);
    let name_id = alice.name_id().unwrap();
    let reveal_height = schedule::next_anchor_height(name_id, 2, params).unwrap();
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let mut wrong_intent = alice.clone();
    wrong_intent.secret[0] ^= 1;
    let state = StateData {
        name_id,
        owner_pk: wrong_intent.owner_pk,
        sequence: 0,
        record: wrong_intent.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let wrong_result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            11,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(502),
                commitment: field(501),
            }],
            vec![reveal_operation(
                &wrong_intent,
                commit_ref,
                state,
                field(501),
                None,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&wrong_result, ApplyError::CommitmentMismatch);

    let mut outside_machine = V1StateMachine::new(params).unwrap();
    let mut outside_source = BTreeMap::new();
    let outside_intent = intent(3, "outside", b"record");
    let outside_commit = commit(
        &mut outside_machine,
        &mut outside_source,
        &outside_intent,
        0,
        20,
    );
    let outside_name = outside_intent.name_id().unwrap();
    let outside_height = (2..=16)
        .find(|height| !schedule::is_anchor_height(outside_name, *height, params))
        .unwrap();
    advance_to(
        &mut outside_machine,
        &mut outside_source,
        outside_height - 1,
    );
    let outside_state = StateData {
        name_id: outside_name,
        owner_pk: outside_intent.owner_pk,
        sequence: 0,
        record: outside_intent.record.clone(),
        lease_expiry: params.lease_expiry(outside_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let outside_result = append(
        &mut outside_machine,
        &mut outside_source,
        vec![transaction(
            0,
            21,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(601),
                commitment: field(600),
            }],
            vec![reveal_operation(
                &outside_intent,
                outside_commit,
                outside_state,
                field(600),
                None,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&outside_result, ApplyError::InvalidStateProof);

    let mut unavailable_machine = V1StateMachine::new(params).unwrap();
    let mut unavailable_source = BTreeMap::new();
    let unavailable_intent = intent(12, "unavailable", b"record");
    let (_, unavailable_head, _) = register(
        &mut unavailable_machine,
        &mut unavailable_source,
        &unavailable_intent,
        22,
    );
    let unavailable_name = unavailable_intent.name_id().unwrap();
    let unavailable_claimable = params
        .claimable_from(
            unavailable_head.data.status,
            unavailable_head.data.lease_expiry,
            unavailable_head.data.terminal_height,
        )
        .unwrap();
    let replacement_commit_height = schedule::next_anchor_height(
        unavailable_name,
        unavailable_machine.tip().height + 1,
        params,
    )
    .unwrap();
    let unavailable_replacement = intent(13, "unavailable", b"new-record");
    advance_to(
        &mut unavailable_machine,
        &mut unavailable_source,
        replacement_commit_height - 1,
    );
    let unavailable_commit = commit(
        &mut unavailable_machine,
        &mut unavailable_source,
        &unavailable_replacement,
        0,
        23,
    );
    assert_eq!(
        unavailable_commit.position.height,
        replacement_commit_height
    );
    let unavailable_reveal_height =
        schedule::next_anchor_height(unavailable_name, replacement_commit_height + 1, params)
            .unwrap();
    assert!(unavailable_reveal_height < unavailable_claimable);
    advance_to(
        &mut unavailable_machine,
        &mut unavailable_source,
        unavailable_reveal_height - 1,
    );
    let unavailable_state = StateData {
        name_id: unavailable_name,
        owner_pk: unavailable_replacement.owner_pk,
        sequence: 0,
        record: unavailable_replacement.record.clone(),
        lease_expiry: params.lease_expiry(unavailable_reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let unavailable_result = append(
        &mut unavailable_machine,
        &mut unavailable_source,
        vec![transaction(
            0,
            24,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(650),
                commitment: field(651),
            }],
            vec![reveal_operation(
                &unavailable_replacement,
                unavailable_commit,
                unavailable_state,
                field(651),
                Some(unavailable_head.state_ref),
            )],
        )],
    )
    .unwrap();
    assert_rejected(&unavailable_result, ApplyError::NameUnavailable);

    let mut expiry_machine = V1StateMachine::new(params).unwrap();
    let mut expiry_source = BTreeMap::new();
    let expiry_intent = intent(4, "expired", b"record");
    let expiry_commit = commit(
        &mut expiry_machine,
        &mut expiry_source,
        &expiry_intent,
        0,
        30,
    );
    advance_to(&mut expiry_machine, &mut expiry_source, 16);
    assert!(expiry_machine.pending(expiry_commit.commitment).is_none());
    let expiry_name = expiry_intent.name_id().unwrap();
    let expiry_reveal = schedule::next_anchor_height(expiry_name, 17, params).unwrap();
    advance_to(&mut expiry_machine, &mut expiry_source, expiry_reveal - 1);
    let expiry_state = StateData {
        name_id: expiry_name,
        owner_pk: expiry_intent.owner_pk,
        sequence: 0,
        record: expiry_intent.record.clone(),
        lease_expiry: params.lease_expiry(expiry_reveal).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let expiry_result = append(
        &mut expiry_machine,
        &mut expiry_source,
        vec![transaction(
            0,
            31,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(701),
                commitment: field(700),
            }],
            vec![reveal_operation(
                &expiry_intent,
                expiry_commit,
                expiry_state,
                field(700),
                None,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&expiry_result, ApplyError::UnknownCommitment);

    let mut reclaim_machine = V1StateMachine::new(params).unwrap();
    let mut reclaim_source = BTreeMap::new();
    let reclaim_intent = intent(5, "reclaim", b"record");
    let (_, old_state, _) = register(
        &mut reclaim_machine,
        &mut reclaim_source,
        &reclaim_intent,
        40,
    );
    let claimable = params
        .claimable_from(
            old_state.data.status,
            old_state.data.lease_expiry,
            old_state.data.terminal_height,
        )
        .unwrap();
    advance_to(&mut reclaim_machine, &mut reclaim_source, claimable - 2);
    let replacement = intent(6, "reclaim", b"new-record");
    let replacement_commit = commit(
        &mut reclaim_machine,
        &mut reclaim_source,
        &replacement,
        0,
        41,
    );
    let replacement_name = replacement.name_id().unwrap();
    let replacement_height =
        schedule::next_anchor_height(replacement_name, claimable, params).unwrap();
    advance_to(
        &mut reclaim_machine,
        &mut reclaim_source,
        replacement_height - 1,
    );
    let replacement_state = StateData {
        name_id: replacement_name,
        owner_pk: replacement.owner_pk,
        sequence: 0,
        record: replacement.record.clone(),
        lease_expiry: params.lease_expiry(replacement_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let reclaim_result = append(
        &mut reclaim_machine,
        &mut reclaim_source,
        vec![transaction(
            0,
            42,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(801),
                commitment: field(800),
            }],
            vec![reveal_operation(
                &replacement,
                replacement_commit,
                replacement_state,
                field(800),
                Some(old_state.state_ref),
            )],
        )],
    )
    .unwrap();
    assert_rejected(&reclaim_result, ApplyError::CommitPredatesClaimability);
}

#[test]
fn no_predecessor_replacement_is_rejected_before_claimability() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let original = intent(14, "early-reset", b"record");
    let (_, previous, _) = register(&mut machine, &mut source, &original, 60);
    let replacement = intent(15, "early-reset", b"replacement");
    let replacement_commit = commit(&mut machine, &mut source, &replacement, 0, 61);
    let name_id = replacement.name_id().unwrap();
    let claimable = params
        .claimable_from(
            previous.data.status,
            previous.data.lease_expiry,
            previous.data.terminal_height,
        )
        .unwrap();
    assert!(replacement_commit.position.height < claimable);
    let reveal_height =
        schedule::next_anchor_height(name_id, replacement_commit.position.height + 1, params)
            .unwrap();
    assert!(reveal_height < claimable);
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let state = StateData {
        name_id,
        owner_pk: replacement.owner_pk,
        sequence: 0,
        record: replacement.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            62,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(1401),
                commitment: field(1402),
            }],
            vec![reveal_operation(
                &replacement,
                replacement_commit,
                state,
                field(1402),
                None,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&result, ApplyError::NameUnavailable);
    assert_eq!(machine.head(name_id).unwrap().state_ref, previous.state_ref);
    assert_fresh_matches_replay(&machine, &source, "early-reset");
}

#[test]
fn no_predecessor_replacement_is_rejected_after_claimability_before_reset_boundary() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let original = intent(16, "bounded-reset", b"record");
    let (_, state0, _) = register(&mut machine, &mut source, &original, 63);
    let name_id = original.name_id().unwrap();
    let release_height = machine.tip().height + 1;
    let released = state_after(
        &state0,
        &state0.data.record,
        1,
        state0.data.lease_expiry,
        StateStatus::Released,
        release_height,
    );
    let release_commitment = field(1601);
    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            64,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(1602),
                commitment: release_commitment,
            }],
            vec![transition_operation(
                OperationKind::Release,
                state0.state_ref,
                released,
                release_commitment,
                0,
            )],
        )],
    )
    .unwrap();
    let previous = machine.head(name_id).unwrap().clone();
    let claimable = params
        .claimable_from(
            previous.data.status,
            previous.data.lease_expiry,
            previous.data.terminal_height,
        )
        .unwrap();
    let anchor = params
        .anchor_height(previous.data.lease_expiry)
        .expect("released state has an anchor");
    let reset_boundary = anchor
        .checked_add(params.reset_horizon().unwrap())
        .expect("reset boundary does not overflow");
    assert!(claimable < reset_boundary);

    advance_to(&mut machine, &mut source, claimable - 1);
    let replacement = intent(17, "bounded-reset", b"replacement");
    let replacement_commit = commit(&mut machine, &mut source, &replacement, 0, 65);
    let commit_height = replacement_commit.position.height;
    assert!(commit_height >= claimable);
    assert!(commit_height < reset_boundary);
    assert_eq!(commit_height, claimable);

    let reveal_height = schedule::next_anchor_height(
        name_id,
        commit_height
            .checked_add(1)
            .expect("maturity height overflow"),
        params,
    )
    .expect("replacement has a scheduled reveal slot");
    let commit_expiry = commit_height
        .checked_add(params.commit_ttl_blocks)
        .expect("commit expiry does not overflow");
    assert!(reveal_height > commit_height);
    assert!(reveal_height >= claimable);
    assert!(reveal_height <= commit_expiry);
    assert!(schedule::is_anchor_height(name_id, reveal_height, params));
    advance_to(&mut machine, &mut source, reveal_height - 1);
    let state = StateData {
        name_id,
        owner_pk: replacement.owner_pk,
        sequence: 0,
        record: replacement.record.clone(),
        lease_expiry: params.lease_expiry(reveal_height).unwrap(),
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            66,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(1603),
                commitment: field(1604),
            }],
            vec![reveal_operation(
                &replacement,
                replacement_commit,
                state,
                field(1604),
                None,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&result, ApplyError::InvalidReplacementReference);
    assert_eq!(machine.head(name_id).unwrap().state_ref, previous.state_ref);
    assert_fresh_matches_replay(&machine, &source, "bounded-reset");
}

#[test]
fn lineage_and_same_action_binding_reject_stale_and_cross_action_inputs() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(7, "alice", b"record");
    let (_, state0, _) = register(&mut machine, &mut source, &alice, 50);
    let name_id = alice.name_id().unwrap();
    let valid_state = state_after(
        &state0,
        b"changed",
        1,
        state0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let valid_cm = field(901);
    let mut wrong_predecessor = state0.state_ref;
    wrong_predecessor.producer_tx_index += 1;
    let stale_result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            51,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(902),
                commitment: valid_cm,
            }],
            vec![transition_operation(
                OperationKind::Update,
                wrong_predecessor,
                valid_state.clone(),
                valid_cm,
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&stale_result, ApplyError::StalePredecessor);

    let cross_action_result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            52,
            vec![
                IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(903),
                    commitment: field(904),
                },
                IronwoodActionRef {
                    action_index: 1,
                    nullifier: field(905),
                    commitment: valid_cm,
                },
            ],
            vec![transition_operation(
                OperationKind::Update,
                state0.state_ref,
                valid_state.clone(),
                valid_cm,
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&cross_action_result, ApplyError::ActionCommitmentMismatch);

    append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            53,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(906),
                commitment: valid_cm,
            }],
            vec![transition_operation(
                OperationKind::Update,
                state0.state_ref,
                valid_state,
                valid_cm,
                0,
            )],
        )],
    )
    .unwrap();
    let current = machine.head(name_id).unwrap().clone();
    let stale_state = state_after(
        &current,
        b"other",
        2,
        current.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let stale_again_result = append(
        &mut machine,
        &mut source,
        vec![transaction(
            0,
            54,
            vec![IronwoodActionRef {
                action_index: 0,
                nullifier: field(907),
                commitment: field(908),
            }],
            vec![transition_operation(
                OperationKind::Update,
                state0.state_ref,
                stale_state,
                field(908),
                0,
            )],
        )],
    )
    .unwrap();
    assert_rejected(&stale_again_result, ApplyError::StalePredecessor);
    assert_fresh_matches_replay(&machine, &source, "alice");
}

#[test]
fn unrelated_names_commute_and_schedule_gap_is_formally_bounded() {
    let params = V1Parameters::testing();
    let mut machine = V1StateMachine::new(params).unwrap();
    let mut source = BTreeMap::new();
    let alice = intent(8, "alice", b"alice");
    let bob = intent(9, "bob", b"bob");
    let (_, alice0, _) = register(&mut machine, &mut source, &alice, 60);
    let (_, bob0, _) = register(&mut machine, &mut source, &bob, 70);
    let alice1 = state_after(
        &alice0,
        b"alice-1",
        1,
        alice0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let bob1 = state_after(
        &bob0,
        b"bob-1",
        1,
        bob0.data.lease_expiry,
        StateStatus::Active,
        0,
    );
    let alice_cm = field(1001);
    let bob_cm = field(1002);
    let applied = append(
        &mut machine,
        &mut source,
        vec![
            transaction(
                0,
                80,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(1003),
                    commitment: alice_cm,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    alice0.state_ref,
                    alice1,
                    alice_cm,
                    0,
                )],
            ),
            transaction(
                1,
                81,
                vec![IronwoodActionRef {
                    action_index: 0,
                    nullifier: field(1004),
                    commitment: bob_cm,
                }],
                vec![transition_operation(
                    OperationKind::Update,
                    bob0.state_ref,
                    bob1,
                    bob_cm,
                    0,
                )],
            ),
        ],
    )
    .unwrap();
    assert_eq!(applied.operations.len(), 2);
    assert_eq!(
        machine
            .head(alice.name_id().unwrap())
            .unwrap()
            .data
            .sequence,
        1
    );
    assert_eq!(
        machine.head(bob.name_id().unwrap()).unwrap().data.sequence,
        1
    );

    let max_gap = params.max_anchor_gap().unwrap();
    for epoch in 0..128 {
        let left = schedule::slot_height(alice.name_id().unwrap(), epoch, params).unwrap();
        let right = schedule::slot_height(alice.name_id().unwrap(), epoch + 1, params).unwrap();
        assert!(right - left <= max_gap);
        assert!(right > left);
    }
    assert!(schedule::candidate_anchor_heights(alice.name_id().unwrap(), 100, params).len() <= 3);
}
