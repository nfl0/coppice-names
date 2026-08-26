//! Small, test-only experiment for per-name Ironwood state-note lineage.
//!
//! This does not change Names v1. It models only the proposed object relation:
//! one named state object is consumed and one successor object is created by a
//! canonical Ironwood action. The test-side model deliberately has no global
//! application-root precondition.
//!
//! The `core_actions` helper consumes the current app-facing Core effect
//! view: ordered parallel nullifier and commitment slices. That is enough to
//! model the public edge `(predecessor nullifier, successor commitment)`.
//! Those effects do not contain the spent note's predecessor commitment. The
//! model therefore keeps that relation as an explicit Names-side invariant so
//! the experiment makes the missing authenticated fact visible rather than
//! silently assuming that Core provides it.

use coppice::replay::{
    CoreCanonicalBlockInput, CoreCanonicalTransactionInput, CoreReplay,
    CoreReplayActivationCheckpoint, CoreReplayConfiguration, FullTransactionAcquisition,
    IronwoodFrontier,
};
use orchard::{note::Nullifier, tree::MerkleHashOrchard};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zcash_protocol::consensus::BranchId;

type Bytes32 = [u8; 32];

const ACTIVATION_HEIGHT: u32 = 10;
const ACTIVATION_BLOCK_HASH: Bytes32 = [0xa0; 32];

fn fixture_bytes(tag: u8) -> Bytes32 {
    [tag; 32]
}

/// Low little-endian field values are canonical Ironwood nullifier/commitment
/// encodings. The experiment intentionally uses deterministic fake effects;
/// it does not construct a proving transaction.
fn canonical_field_bytes(tag: u8) -> Bytes32 {
    let mut bytes = [0; 32];
    bytes[0] = tag;
    assert!(Option::<Nullifier>::from(Nullifier::from_bytes(&bytes)).is_some());
    assert!(Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes)).is_some());
    bytes
}

fn fixture_successor_nullifier(
    object_id: Bytes32,
    commitment: Bytes32,
    owner: Bytes32,
    sequence: u64,
) -> Bytes32 {
    // This gives the fixture a known future spend identity so AliceState1 can
    // be extended. It is test scaffolding, not a claim that a real public
    // note commitment determines its future nullifier.
    let mut hasher = Sha256::new();
    hasher.update(b"coppice-state-note-lineage-test/nullifier-v1");
    hasher.update(object_id);
    hasher.update(commitment);
    hasher.update(owner);
    hasher.update(sequence.to_be_bytes());

    // Keep the deterministic fixture in the low 128 bits so it is a
    // canonical Pallas base-field encoding accepted by CoreReplay.
    let digest = hasher.finalize();
    let mut result = [0; 32];
    result[..16].copy_from_slice(&digest[..16]);
    if result == [0; 32] {
        result[0] = 1;
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalPosition {
    height: u32,
    tx_index: u32,
    txid: Bytes32,
    action_index: u32,
}

/// The public current-Core effect shape used by this experiment.
///
/// `predecessor_nullifier` is the nullifier revealed by spending the old
/// note. `successor_commitment` is the new note commitment in the same
/// canonical action. There is intentionally no predecessor note commitment
/// field here: current Core effects do not expose one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CurrentCoreActionEffect {
    position: CanonicalPosition,
    predecessor_nullifier: Bytes32,
    successor_commitment: Bytes32,
}

/// Extracts the current typed Core effect view into per-action edges.
///
/// Core exposes the two compact effect sequences in canonical action order.
/// Zipping them is therefore sufficient for this experiment's public
/// nullifier-to-successor-commitment edge, while keeping the absence of an
/// authenticated input-note identity explicit.
fn core_actions(
    tx_index: u32,
    txid: Bytes32,
    pairs: &[(Bytes32, Bytes32)],
) -> Vec<CurrentCoreActionEffect> {
    let configuration = CoreReplayConfiguration::new(ACTIVATION_HEIGHT, 32).unwrap();
    let mut replay = CoreReplay::new(
        configuration,
        CoreReplayActivationCheckpoint {
            height: ACTIVATION_HEIGHT - 1,
            block_hash: ACTIVATION_BLOCK_HASH,
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    )
    .unwrap();

    let block = CoreCanonicalBlockInput {
        height: ACTIVATION_HEIGHT,
        block_hash: fixture_bytes(0xa1),
        prev_block_hash: ACTIVATION_BLOCK_HASH,
        branch_id: BranchId::Nu6_3,
        transactions: vec![CoreCanonicalTransactionInput {
            tx_index,
            txid,
            ironwood_nullifiers: pairs.iter().map(|(nullifier, _)| *nullifier).collect(),
            ironwood_commitments: pairs.iter().map(|(_, commitment)| *commitment).collect(),
            full_transaction_acquisition: FullTransactionAcquisition::None,
            full_transaction: None,
        }],
    };
    let context = replay.apply_block(&block).unwrap();
    let transaction = &context.transactions()[0];
    let effects = transaction.ironwood_effects();
    assert_eq!(effects.nullifiers().len(), effects.commitments().len());
    assert_eq!(effects.nullifiers().len(), pairs.len());

    effects
        .nullifiers()
        .iter()
        .zip(effects.commitments())
        .enumerate()
        .map(
            |(action_index, (predecessor_nullifier, successor_commitment))| {
                CurrentCoreActionEffect {
                    position: CanonicalPosition {
                        height: transaction.height(),
                        tx_index: transaction.tx_index(),
                        txid: transaction.txid(),
                        action_index: action_index as u32,
                    },
                    predecessor_nullifier: *predecessor_nullifier,
                    successor_commitment: *successor_commitment,
                }
            },
        )
        .collect()
}

fn core_action_at(
    tx_index: u32,
    txid_tag: u8,
    predecessor_nullifier: Bytes32,
    successor_commitment: Bytes32,
) -> CurrentCoreActionEffect {
    core_actions(
        tx_index,
        fixture_bytes(txid_tag),
        &[(predecessor_nullifier, successor_commitment)],
    )
    .into_iter()
    .next()
    .unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    UpdateValue(u8),
}

impl Operation {
    fn value(self) -> u8 {
        match self {
            Self::UpdateValue(value) => value,
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::UpdateValue(_) => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateObject {
    object_id: Bytes32,
    commitment: Bytes32,
    spend_nullifier: Bytes32,
    owner: Bytes32,
    sequence: u64,
    value: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateTransition {
    object_id: Bytes32,
    predecessor_commitment: Bytes32,
    predecessor_nullifier: Bytes32,
    successor_commitment: Bytes32,
    operation: Operation,
    owner: Bytes32,
    authorization: Bytes32,
}

fn authorization_digest(transition: &StateTransition) -> Bytes32 {
    // This is only a deterministic stand-in for the owner authorization that
    // would be checked by a real application operation.
    let mut hasher = Sha256::new();
    hasher.update(b"coppice-state-note-lineage-test/owner-auth-v1");
    hasher.update(transition.object_id);
    hasher.update(transition.predecessor_commitment);
    hasher.update(transition.predecessor_nullifier);
    hasher.update(transition.successor_commitment);
    hasher.update([transition.operation.tag(), transition.operation.value()]);
    hasher.update(transition.owner);
    hasher.finalize().into()
}

impl StateTransition {
    fn update(current: &StateObject, successor_commitment: Bytes32, value: u8) -> Self {
        let mut transition = Self {
            object_id: current.object_id,
            predecessor_commitment: current.commitment,
            predecessor_nullifier: current.spend_nullifier,
            successor_commitment,
            operation: Operation::UpdateValue(value),
            owner: current.owner,
            authorization: [0; 32],
        };
        transition.authorization = authorization_digest(&transition);
        transition
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NamedMutation {
    action: CurrentCoreActionEffect,
    transition: StateTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineageError {
    UnknownObject,
    PredecessorNotCurrent,
    PredecessorNullifierNotCurrent,
    ActionDoesNotMatchTransition,
    WrongOwner,
    InvalidAuthorization,
    InvalidSequence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NameLineage {
    current: BTreeMap<Bytes32, StateObject>,
    accepted_edges: Vec<(Bytes32, Bytes32, Bytes32)>,
}

impl NameLineage {
    fn new(objects: impl IntoIterator<Item = StateObject>) -> Self {
        Self {
            current: objects
                .into_iter()
                .map(|object| (object.object_id, object))
                .collect(),
            accepted_edges: Vec::new(),
        }
    }

    /// Applies a transition after the host-selected canonical action stream
    /// has been established. No global application root is an input.
    fn apply(
        &mut self,
        action: CurrentCoreActionEffect,
        transition: StateTransition,
    ) -> Result<(), LineageError> {
        if action.predecessor_nullifier != transition.predecessor_nullifier
            || action.successor_commitment != transition.successor_commitment
        {
            return Err(LineageError::ActionDoesNotMatchTransition);
        }

        let current = self
            .current
            .get(&transition.object_id)
            .copied()
            .ok_or(LineageError::UnknownObject)?;
        if transition.predecessor_commitment != current.commitment {
            return Err(LineageError::PredecessorNotCurrent);
        }
        if transition.predecessor_nullifier != current.spend_nullifier {
            return Err(LineageError::PredecessorNullifierNotCurrent);
        }
        if transition.owner != current.owner {
            return Err(LineageError::WrongOwner);
        }
        if transition.authorization != authorization_digest(&transition) {
            return Err(LineageError::InvalidAuthorization);
        }

        let next_sequence = current
            .sequence
            .checked_add(1)
            .ok_or(LineageError::InvalidSequence)?;
        let next = StateObject {
            object_id: current.object_id,
            commitment: transition.successor_commitment,
            spend_nullifier: fixture_successor_nullifier(
                current.object_id,
                transition.successor_commitment,
                current.owner,
                next_sequence,
            ),
            owner: current.owner,
            sequence: next_sequence,
            value: transition.operation.value(),
        };

        self.current.insert(current.object_id, next);
        self.accepted_edges.push((
            current.object_id,
            transition.predecessor_commitment,
            transition.successor_commitment,
        ));
        Ok(())
    }

    /// A deterministic audit root is derived from the per-name map only. It
    /// is deliberately not a transition precondition or a conflict lock.
    fn audit_root(&self) -> Bytes32 {
        let mut hasher = Sha256::new();
        hasher.update(b"coppice-state-note-lineage-test/audit-root-v1");
        for (object_id, object) in &self.current {
            hasher.update(object_id);
            hasher.update(object.commitment);
            hasher.update(object.spend_nullifier);
            hasher.update(object.owner);
            hasher.update(object.sequence.to_be_bytes());
            hasher.update([object.value]);
        }
        hasher.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanonicalOutcome {
    Applied,
    RejectedByZcashNullifier,
    RejectedByNames(LineageError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayResult {
    lineage: NameLineage,
    outcomes: Vec<CanonicalOutcome>,
}

/// Replays a host-selected canonical stream. The `spent_nullifiers` set is a
/// fixture for Zcash one-time-spend semantics, not a Names consensus layer:
/// the canonical stream decides which spend is present, and Names only sees
/// the surviving ordered action.
fn replay(
    objects: impl IntoIterator<Item = StateObject>,
    mutations: &[NamedMutation],
) -> ReplayResult {
    let mut lineage = NameLineage::new(objects);
    let mut spent_nullifiers = BTreeSet::new();
    let mut previous_position = None;
    let mut outcomes = Vec::with_capacity(mutations.len());

    for mutation in mutations {
        if let Some(previous) = previous_position {
            assert!(previous < mutation.action.position);
        }
        previous_position = Some(mutation.action.position);

        if !spent_nullifiers.insert(mutation.action.predecessor_nullifier) {
            outcomes.push(CanonicalOutcome::RejectedByZcashNullifier);
            continue;
        }
        outcomes.push(match lineage.apply(mutation.action, mutation.transition) {
            Ok(()) => CanonicalOutcome::Applied,
            Err(error) => CanonicalOutcome::RejectedByNames(error),
        });
    }

    ReplayResult { lineage, outcomes }
}

fn initial_object(
    object_tag: u8,
    commitment_tag: u8,
    nullifier_tag: u8,
    owner_tag: u8,
) -> StateObject {
    StateObject {
        object_id: fixture_bytes(object_tag),
        commitment: canonical_field_bytes(commitment_tag),
        spend_nullifier: canonical_field_bytes(nullifier_tag),
        owner: fixture_bytes(owner_tag),
        sequence: 0,
        value: 0,
    }
}

fn mutation(
    current: &StateObject,
    successor_commitment_tag: u8,
    value: u8,
    tx_index: u32,
    txid_tag: u8,
) -> NamedMutation {
    let transition = StateTransition::update(
        current,
        canonical_field_bytes(successor_commitment_tag),
        value,
    );
    let action = core_action_at(
        tx_index,
        txid_tag,
        transition.predecessor_nullifier,
        transition.successor_commitment,
    );
    NamedMutation { action, transition }
}

#[test]
fn current_core_effects_supply_ordered_nullifier_to_successor_edges() {
    let first = (canonical_field_bytes(1), canonical_field_bytes(2));
    let second = (canonical_field_bytes(3), canonical_field_bytes(4));
    let actions = core_actions(0, fixture_bytes(0x11), &[first, second]);

    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].predecessor_nullifier, first.0);
    assert_eq!(actions[0].successor_commitment, first.1);
    assert_eq!(actions[1].predecessor_nullifier, second.0);
    assert_eq!(actions[1].successor_commitment, second.1);
    assert_eq!(actions[0].position.action_index, 0);
    assert_eq!(actions[1].position.action_index, 1);
}

#[test]
fn unrelated_name_updates_commute_without_a_global_root_precondition() {
    let alice0 = initial_object(0xa1, 0x11, 0x21, 0x31);
    let bob0 = initial_object(0xb1, 0x12, 0x22, 0x32);

    let alice_then_bob = replay(
        [alice0, bob0],
        &[
            mutation(&alice0, 0x13, 1, 0, 0x41),
            mutation(&bob0, 0x14, 2, 1, 0x42),
        ],
    );
    let bob_then_alice = replay(
        [alice0, bob0],
        &[
            mutation(&bob0, 0x14, 2, 0, 0x52),
            mutation(&alice0, 0x13, 1, 1, 0x51),
        ],
    );

    assert_eq!(
        alice_then_bob.outcomes,
        vec![CanonicalOutcome::Applied, CanonicalOutcome::Applied]
    );
    assert_eq!(
        bob_then_alice.outcomes,
        vec![CanonicalOutcome::Applied, CanonicalOutcome::Applied]
    );
    assert_eq!(
        alice_then_bob.lineage.current,
        bob_then_alice.lineage.current
    );
    assert_eq!(
        alice_then_bob.lineage.audit_root(),
        bob_then_alice.lineage.audit_root()
    );
    assert_eq!(alice_then_bob.lineage.accepted_edges.len(), 2);
    assert_eq!(bob_then_alice.lineage.accepted_edges.len(), 2);
}

#[test]
fn same_name_competing_updates_share_a_predecessor_and_canonical_spend_wins() {
    let alice0 = initial_object(0xa1, 0x11, 0x21, 0x31);
    let update_a = mutation(&alice0, 0x13, 1, 0, 0x61);
    let update_b = mutation(&alice0, 0x15, 2, 1, 0x62);

    assert_eq!(
        update_a.transition.predecessor_commitment,
        update_b.transition.predecessor_commitment
    );
    assert_eq!(
        update_a.transition.predecessor_nullifier,
        update_b.transition.predecessor_nullifier
    );
    assert_eq!(
        update_a.action.predecessor_nullifier,
        update_b.action.predecessor_nullifier
    );
    assert_ne!(
        update_a.action.successor_commitment,
        update_b.action.successor_commitment
    );

    let a_first = replay([alice0], &[update_a, update_b]);
    assert_eq!(
        a_first.outcomes,
        vec![
            CanonicalOutcome::Applied,
            CanonicalOutcome::RejectedByZcashNullifier
        ]
    );
    assert_eq!(
        a_first.lineage.current[&alice0.object_id].commitment,
        update_a.action.successor_commitment
    );

    let b_first = replay(
        [alice0],
        &[
            mutation(&alice0, 0x15, 2, 0, 0x72),
            mutation(&alice0, 0x13, 1, 1, 0x71),
        ],
    );
    assert_eq!(
        b_first.outcomes,
        vec![
            CanonicalOutcome::Applied,
            CanonicalOutcome::RejectedByZcashNullifier
        ]
    );
    assert_eq!(
        b_first.lineage.current[&alice0.object_id].commitment,
        update_b.action.successor_commitment
    );
}

#[test]
fn accepted_mutations_form_alice_state_zero_one_two_and_consume_one_create_one() {
    let alice0 = initial_object(0xa1, 0x11, 0x21, 0x31);
    let update_1 = mutation(&alice0, 0x13, 1, 0, 0x81);
    let alice1 = StateObject {
        object_id: alice0.object_id,
        commitment: update_1.action.successor_commitment,
        spend_nullifier: fixture_successor_nullifier(
            alice0.object_id,
            update_1.action.successor_commitment,
            alice0.owner,
            1,
        ),
        owner: alice0.owner,
        sequence: 1,
        value: 1,
    };
    let update_2 = mutation(&alice1, 0x16, 2, 1, 0x82);

    let result = replay([alice0], &[update_1, update_2]);
    assert_eq!(
        result.outcomes,
        vec![CanonicalOutcome::Applied, CanonicalOutcome::Applied]
    );
    assert_eq!(result.lineage.accepted_edges.len(), 2);
    assert_eq!(
        result.lineage.accepted_edges[0],
        (alice0.object_id, alice0.commitment, alice1.commitment)
    );
    assert_eq!(
        result.lineage.accepted_edges[1],
        (
            alice0.object_id,
            alice1.commitment,
            update_2.action.successor_commitment
        )
    );
    assert_eq!(
        result.lineage.current[&alice0.object_id].commitment,
        update_2.action.successor_commitment
    );
    assert_eq!(result.lineage.current[&alice0.object_id].sequence, 2);
}

#[test]
fn stale_predecessor_is_rejected_after_the_current_object_is_consumed() {
    let alice0 = initial_object(0xa1, 0x11, 0x21, 0x31);
    let update_1 = mutation(&alice0, 0x13, 1, 0, 0x91);
    let accepted = replay([alice0], &[update_1]);
    assert_eq!(accepted.outcomes, vec![CanonicalOutcome::Applied]);

    let mut stale = StateTransition::update(&alice0, canonical_field_bytes(0x17), 3);
    // The operation remains owner-authorized; it is stale because it names
    // AliceState0 after AliceState1 is already current.
    stale.authorization = authorization_digest(&stale);
    let stale_action = core_action_at(
        0,
        0x92,
        stale.predecessor_nullifier,
        stale.successor_commitment,
    );
    let mut lineage = accepted.lineage;
    assert_eq!(
        lineage.apply(stale_action, stale),
        Err(LineageError::PredecessorNotCurrent)
    );
}

#[test]
fn current_effects_need_an_authenticated_input_note_identity_for_full_lineage_soundness() {
    let alice0 = initial_object(0xa1, 0x11, 0x21, 0x31);
    let successor_commitment = canonical_field_bytes(0x18);
    let transition = StateTransition::update(&alice0, successor_commitment, 4);
    let alternate_nullifier = canonical_field_bytes(0x19);
    let action = core_action_at(0, 0xa1, alternate_nullifier, successor_commitment);

    // The current effect boundary supplies this public edge, but the action
    // could have spent any note whose nullifier is alternate_nullifier.
    assert_eq!(action.predecessor_nullifier, alternate_nullifier);
    assert_eq!(action.successor_commitment, successor_commitment);

    // The transition names AliceState0 and is owner-authorized, but changes
    // only its declared predecessor nullifier to match the public action.
    // The model rejects it because its fixture state knows AliceState0's
    // expected nullifier. Current Core effects contain no authenticated field
    // that can establish this commitment-to-nullifier relation.
    let mut missing_binding = transition;
    missing_binding.predecessor_nullifier = alternate_nullifier;
    missing_binding.authorization = authorization_digest(&missing_binding);
    let mut lineage = NameLineage::new([alice0]);
    assert_eq!(
        lineage.apply(action, missing_binding),
        Err(LineageError::PredecessorNullifierNotCurrent)
    );
}
