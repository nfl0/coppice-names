//! Test-only experiment for deterministic temporal sharding of Names lookup.
//!
//! This is an analytical model, not a Names protocol implementation. It uses
//! only a synthetic canonical block history and counts ordinary block-body
//! inspections. No Coppice, Orchard, server, or production Names API is
//! changed by this file.
//!
//! The schedule is deliberately name-derived:
//!
//! ```text
//! epoch = floor(height / epoch_size)
//! offset = H(domain || name_id || epoch || slot_index) mod epoch_size
//! ```
//!
//! A resolver inspects only the schedule windows intersecting its bounded
//! lease range. Transitions in a fetched block are already in canonical action
//! order; the resolver never invents a second fork-choice rule.

use blake2b_simd::Params;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

const SLOT_DOMAIN: &[u8] = b"coppice.names.temporal-slot.v1";
const SLOT_PERSONALIZATION: &[u8] = b"CoppiceSlotV1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NameId([u8; 32]);

impl NameId {
    fn from_tag(tag: u8) -> Self {
        Self([tag; 32])
    }

    fn from_number(number: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&number.to_le_bytes());
        Self(bytes)
    }
}

/// A compact synthetic state identity. The `tag` distinguishes competing
/// successors that have the same version but different commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct StateId {
    name_id: NameId,
    version: u64,
    tag: u64,
}

fn state(name_id: NameId, version: u64) -> StateId {
    StateId {
        name_id,
        version,
        tag: 0,
    }
}

fn tagged_state(name_id: NameId, version: u64, tag: u64) -> StateId {
    StateId {
        name_id,
        version,
        tag,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Transition {
    name_id: NameId,
    predecessor: StateId,
    successor: StateId,
}

fn transition(name_id: NameId, predecessor_version: u64, successor_version: u64) -> Transition {
    Transition {
        name_id,
        predecessor: state(name_id, predecessor_version),
        successor: state(name_id, successor_version),
    }
}

fn transition_between(predecessor: StateId, successor: StateId) -> Transition {
    Transition {
        name_id: predecessor.name_id,
        predecessor,
        successor,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Block {
    height: u64,
    ironwood_action_count: u64,
    /// Canonical transaction/action order within this block.
    transitions: Vec<Transition>,
}

impl Block {
    fn empty(height: u64) -> Self {
        Self {
            height,
            ironwood_action_count: 0,
            transitions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalHistory {
    blocks: Vec<Block>,
}

impl CanonicalHistory {
    fn empty(tip: u64) -> Self {
        Self {
            blocks: (0..=tip).map(Block::empty).collect(),
        }
    }

    fn add_transition(&mut self, height: u64, value: Transition) {
        let block = self
            .blocks
            .get_mut(height as usize)
            .expect("synthetic history must cover the transition height");
        assert_eq!(block.height, height);
        block.ironwood_action_count += 1;
        block.transitions.push(value);
    }

    fn add_ironwood_actions(&mut self, height: u64, count: u64) {
        let block = self
            .blocks
            .get_mut(height as usize)
            .expect("synthetic history must cover the action height");
        assert_eq!(block.height, height);
        block.ironwood_action_count += count;
    }

    fn replace_block(&mut self, block: Block) {
        let height = block.height;
        let destination = self
            .blocks
            .get_mut(height as usize)
            .expect("synthetic reorg must replace an existing block");
        *destination = block;
    }

    fn block(&self, height: u64) -> &Block {
        let block = self
            .blocks
            .get(height as usize)
            .expect("resolver must stay within the synthetic tip");
        assert_eq!(block.height, height);
        block
    }

    /// Cumulative commitment-tree size after every block, including empty
    /// blocks. This is the only metadata used by the optional body skip.
    fn tree_sizes(&self) -> Vec<u64> {
        let mut size = 0;
        self.blocks
            .iter()
            .map(|block| {
                size += block.ironwood_action_count;
                size
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScheduleParams {
    epoch_size: u64,
    slot_width: u64,
    slots_per_epoch: u64,
}

impl ScheduleParams {
    fn validate(self) {
        assert!(self.epoch_size > 0);
        assert!(self.slot_width > 0);
        assert!(self.slots_per_epoch > 0);
    }
}

fn hash_slot_offset(name_id: NameId, epoch: u64, slot_index: u64, epoch_size: u64) -> u64 {
    assert!(epoch_size > 0);
    let mut input = Vec::with_capacity(SLOT_DOMAIN.len() + 32 + 16);
    input.extend_from_slice(SLOT_DOMAIN);
    input.extend_from_slice(&name_id.0);
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(&slot_index.to_le_bytes());

    let digest = Params::new()
        .hash_length(8)
        .personal(SLOT_PERSONALIZATION)
        .hash(&input);
    let mut bytes = [0; 8];
    bytes.copy_from_slice(digest.as_bytes());
    u64::from_le_bytes(bytes) % epoch_size
}

/// The single-slot form requested by the experiment.
fn candidate_slot(name_id: NameId, epoch: u64, epoch_size: u64) -> u64 {
    hash_slot_offset(name_id, epoch, 0, epoch_size)
}

/// Return the inclusive window for the first deterministic slot in an epoch.
/// A window is clipped at the epoch boundary, so it cannot silently grant a
/// publication height in the next epoch.
fn candidate_window(
    name_id: NameId,
    epoch: u64,
    epoch_size: u64,
    slot_width: u64,
) -> RangeInclusive<u64> {
    assert!(epoch_size > 0);
    assert!(slot_width > 0);
    let epoch_start = epoch
        .checked_mul(epoch_size)
        .expect("synthetic schedule height overflow");
    let epoch_end = epoch_start
        .checked_add(epoch_size - 1)
        .expect("synthetic schedule height overflow");
    let start = epoch_start
        .checked_add(candidate_slot(name_id, epoch, epoch_size))
        .expect("synthetic schedule height overflow");
    let end = start.saturating_add(slot_width - 1).min(epoch_end);
    start..=end
}

fn candidate_offsets(name_id: NameId, epoch: u64, params: ScheduleParams) -> Vec<u64> {
    params.validate();
    let target = params.slots_per_epoch.min(params.epoch_size);
    let mut offsets = BTreeSet::new();

    // Hash each slot index, then deterministically probe on an intra-name
    // collision. Thus k slots are distinct whenever k <= epoch_size while
    // remaining entirely name/epoch-derived.
    for slot_index in 0..target {
        let mut offset = hash_slot_offset(name_id, epoch, slot_index, params.epoch_size);
        while offsets.contains(&offset) {
            offset = (offset + 1) % params.epoch_size;
        }
        offsets.insert(offset);
    }
    offsets.into_iter().collect()
}

fn candidate_windows(
    name_id: NameId,
    epoch: u64,
    params: ScheduleParams,
) -> Vec<RangeInclusive<u64>> {
    params.validate();
    candidate_offsets(name_id, epoch, params)
        .into_iter()
        .map(|offset| {
            let epoch_start = epoch
                .checked_mul(params.epoch_size)
                .expect("synthetic schedule height overflow");
            let epoch_end = epoch_start
                .checked_add(params.epoch_size - 1)
                .expect("synthetic schedule height overflow");
            let start = epoch_start
                .checked_add(offset)
                .expect("synthetic schedule height overflow");
            let end = start.saturating_add(params.slot_width - 1).min(epoch_end);
            start..=end
        })
        .collect()
}

fn lease_range(tip: u64, lease_window: u64) -> RangeInclusive<u64> {
    assert!(lease_window > 0);
    let start = tip.saturating_sub(lease_window - 1);
    start..=tip
}

/// Return the exact block heights a fresh lookup is allowed to inspect.
fn candidate_heights(
    name_id: NameId,
    tip: u64,
    lease_window: u64,
    params: ScheduleParams,
) -> Vec<u64> {
    params.validate();
    let search = lease_range(tip, lease_window);
    let search_start = *search.start();
    let search_end = *search.end();
    let first_epoch = search_start / params.epoch_size;
    let last_epoch = search_end / params.epoch_size;
    let mut heights = BTreeSet::new();

    for epoch in first_epoch..=last_epoch {
        for window in candidate_windows(name_id, epoch, params) {
            let start = (*window.start()).max(search_start);
            let end = (*window.end()).min(search_end);
            if start <= end {
                heights.extend(start..=end);
            }
        }
    }
    heights.into_iter().collect()
}

/// Count candidate heights without allocating the full height list. This is
/// used only by the large analytical sweep; the resolver above still builds
/// and visits the exact allowed heights.
fn candidate_block_count(
    name_id: NameId,
    tip: u64,
    lease_window: u64,
    params: ScheduleParams,
) -> usize {
    params.validate();
    let search = lease_range(tip, lease_window);
    let search_start = *search.start();
    let search_end = *search.end();
    let first_epoch = search_start / params.epoch_size;
    let last_epoch = search_end / params.epoch_size;
    let mut count = 0u64;

    for epoch in first_epoch..=last_epoch {
        let mut previous_end: Option<u64> = None;
        for window in candidate_windows(name_id, epoch, params) {
            let start = (*window.start()).max(search_start);
            let end = (*window.end()).min(search_end);
            if start > end {
                continue;
            }
            match previous_end {
                Some(previous) if start <= previous.saturating_add(1) => {
                    if end > previous {
                        count += end - previous;
                        previous_end = Some(end);
                    }
                }
                _ => {
                    count += end - start + 1;
                    previous_end = Some(end);
                }
            }
        }
    }
    count as usize
}

fn candidate_block_count_from_offsets(
    tip: u64,
    lease_window: u64,
    params: ScheduleParams,
    offsets_by_epoch: &BTreeMap<u64, Vec<u64>>,
) -> usize {
    params.validate();
    let search = lease_range(tip, lease_window);
    let search_start = *search.start();
    let search_end = *search.end();
    let first_epoch = search_start / params.epoch_size;
    let last_epoch = search_end / params.epoch_size;
    let mut count = 0u64;

    for epoch in first_epoch..=last_epoch {
        let epoch_start = epoch
            .checked_mul(params.epoch_size)
            .expect("synthetic schedule height overflow");
        let epoch_end = epoch_start
            .checked_add(params.epoch_size - 1)
            .expect("synthetic schedule height overflow");
        let mut previous_end: Option<u64> = None;
        for &offset in offsets_by_epoch
            .get(&epoch)
            .expect("cached schedule must cover the lease epochs")
        {
            let start = epoch_start
                .checked_add(offset)
                .expect("synthetic schedule height overflow")
                .max(search_start);
            let end = epoch_start
                .checked_add(offset)
                .expect("synthetic schedule height overflow")
                .saturating_add(params.slot_width - 1)
                .min(epoch_end)
                .min(search_end);
            if start > end {
                continue;
            }
            match previous_end {
                Some(previous) if start <= previous.saturating_add(1) => {
                    if end > previous {
                        count += end - previous;
                        previous_end = Some(end);
                    }
                }
                _ => {
                    count += end - start + 1;
                    previous_end = Some(end);
                }
            }
        }
    }
    count as usize
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Resolution {
    latest: Option<Transition>,
    current: StateId,
    search_range: RangeInclusive<u64>,
    candidate_heights: Vec<u64>,
    blocks_fetched: usize,
    transitions_inspected: usize,
    accepted_transitions: usize,
}

/// Resolve a name by fetching only candidate schedule heights.
///
/// The state machine here is intentionally tiny: a valid transition must be
/// for the requested name, consume the current state identity, preserve the
/// name in the successor, and advance exactly one version. In production the
/// transition proof supplies these facts; this test does not recreate it.
fn resolve_latest(
    name_id: NameId,
    tip: u64,
    lease_window: u64,
    params: ScheduleParams,
    history: &CanonicalHistory,
) -> Resolution {
    let search_range = lease_range(tip, lease_window);
    let candidate_heights = candidate_heights(name_id, tip, lease_window, params);
    let mut current = state(name_id, 0);
    let mut latest = None;
    let mut blocks_fetched = 0;
    let mut transitions_inspected = 0;
    let mut accepted_transitions = 0;

    // `candidate_heights` is sorted by height. `block.transitions` is already
    // canonical action order. No other block or transaction is visited.
    for &height in &candidate_heights {
        let block = history.block(height);
        blocks_fetched += 1;
        for transition in &block.transitions {
            transitions_inspected += 1;
            if transition.name_id != name_id
                || transition.predecessor != current
                || transition.successor.name_id != name_id
                || transition.successor.version != current.version + 1
            {
                continue;
            }

            current = transition.successor;
            latest = Some(*transition);
            accepted_transitions += 1;
        }
    }

    Resolution {
        latest,
        current,
        search_range,
        candidate_heights,
        blocks_fetched,
        transitions_inspected,
        accepted_transitions,
    }
}

fn merged_windows(name_id: NameId, epoch: u64, params: ScheduleParams) -> Vec<(u64, u64)> {
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for window in candidate_windows(name_id, epoch, params) {
        let start = *window.start();
        let end = *window.end();
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= previous_end.saturating_add(1) {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn next_legal_delay_in_first_epoch(
    epoch_size: u64,
    first_epoch: &[(u64, u64)],
    second_epoch: &[(u64, u64)],
    height: u64,
) -> u64 {
    for &(start, end) in first_epoch {
        if (start..=end).contains(&height) {
            return 0;
        }
        if start >= height {
            return start - height;
        }
    }

    let next_start = second_epoch
        .first()
        .map(|(start, _)| *start)
        .expect("schedule has at least one slot");
    next_start + epoch_size - height
}

fn exact_worst_delay(name_id: NameId, params: ScheduleParams) -> u64 {
    let first_epoch = merged_windows(name_id, 0, params);
    let second_epoch = merged_windows(name_id, 1, params);
    let epoch_end = params.epoch_size;
    let mut cursor = 0;
    let mut worst = 0;

    for (start, end) in first_epoch {
        if start > cursor {
            worst = worst.max(start - cursor);
        }
        cursor = cursor.max(end.saturating_add(1));
    }

    if cursor < epoch_end {
        let next_start = second_epoch
            .first()
            .map(|(start, _)| *start)
            .expect("schedule has at least one slot")
            .saturating_add(epoch_end);
        worst = worst.max(next_start - cursor);
    }
    worst
}

#[derive(Clone, Copy, Debug)]
struct DelayStats {
    average: f64,
    worst: u64,
    p50: u64,
    p95: u64,
}

/// Uniform deterministic samples over one epoch provide average/p50/p95;
/// worst is computed exactly from the legal interval gaps.
fn publication_delay_stats(name_id: NameId, params: ScheduleParams) -> DelayStats {
    let first_epoch = merged_windows(name_id, 0, params);
    let second_epoch = merged_windows(name_id, 1, params);
    let sample_count = (params.epoch_size as usize).min(4096);
    let mut samples = Vec::with_capacity(sample_count);
    for index in 0..sample_count {
        let height = (index as u64 * params.epoch_size) / sample_count as u64;
        samples.push(next_legal_delay_in_first_epoch(
            params.epoch_size,
            &first_epoch,
            &second_epoch,
            height,
        ));
    }
    samples.sort_unstable();
    let sum: u64 = samples.iter().sum();
    let percentile = |percent: usize| samples[(samples.len() - 1) * percent / 100];

    DelayStats {
        average: sum as f64 / samples.len() as f64,
        worst: exact_worst_delay(name_id, params),
        p50: percentile(50),
        p95: percentile(95),
    }
}

#[derive(Clone, Copy, Debug)]
struct Measurement {
    lease_window: u64,
    epoch_size: u64,
    slot_width: u64,
    slots_per_epoch: u64,
    candidate_blocks: usize,
    fraction_of_lease: f64,
    lookup_improvement: f64,
    delay: DelayStats,
    work_times_worst_delay: u128,
}

fn measure(
    name_id: NameId,
    lease_window: u64,
    epoch_size: u64,
    slot_width: u64,
    slots_per_epoch: u64,
    offsets_by_epoch: &BTreeMap<u64, Vec<u64>>,
) -> Measurement {
    let params = ScheduleParams {
        epoch_size,
        slot_width,
        slots_per_epoch,
    };
    // The reference tip makes the snapshot deterministic while retaining the
    // real resolver's lease-boundary behavior. When E > L, work can be zero
    // for a phase with no legal slot in the lease; that is an important result,
    // not an error in the measurement.
    let tip = lease_window
        .checked_mul(10)
        .and_then(|value| value.checked_sub(1))
        .expect("synthetic measurement tip overflow");
    let candidate_blocks =
        candidate_block_count_from_offsets(tip, lease_window, params, offsets_by_epoch);
    let delay = publication_delay_stats(name_id, params);

    Measurement {
        lease_window,
        epoch_size,
        slot_width,
        slots_per_epoch,
        candidate_blocks,
        fraction_of_lease: candidate_blocks as f64 / lease_window as f64,
        lookup_improvement: if candidate_blocks == 0 {
            0.0
        } else {
            lease_window as f64 / candidate_blocks as f64
        },
        delay,
        work_times_worst_delay: candidate_blocks as u128 * delay.worst as u128,
    }
}

fn epoch_sizes_for(lease_window: u64) -> Vec<u64> {
    let sqrt = (lease_window as f64).sqrt() as u64;
    let candidates = [
        8,
        16,
        32,
        64,
        128,
        256,
        sqrt.max(1),
        sqrt.saturating_mul(2).max(1),
        lease_window.saturating_mul(2).max(1),
    ];
    candidates
        .into_iter()
        .filter(|size| *size > 0)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn activity_history(tip: u64, percent: u64) -> CanonicalHistory {
    assert!(percent <= 100);
    let mut history = CanonicalHistory::empty(tip);
    for height in 0..=tip {
        let bucket = height
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407)
            % 100;
        if bucket < percent {
            history.add_ironwood_actions(height, 1);
        }
    }
    history
}

fn body_fetches_with_tree_skip(history: &CanonicalHistory, heights: &[u64]) -> usize {
    let tree_sizes = history.tree_sizes();
    heights
        .iter()
        .filter(|&&height| {
            let after = tree_sizes[height as usize];
            let before = if height == 0 {
                0
            } else {
                tree_sizes[height as usize - 1]
            };
            after != before
        })
        .count()
}

fn collision_stats(name_count: u64, epoch: u64, epoch_size: u64) -> (usize, usize) {
    let mut buckets = BTreeMap::<u64, usize>::new();
    for number in 0..name_count {
        let slot = candidate_slot(NameId::from_number(number), epoch, epoch_size);
        *buckets.entry(slot).or_default() += 1;
    }
    let maximum = buckets.values().copied().max().unwrap_or(0);
    (buckets.len(), maximum)
}

fn find_grind(target: u64, epoch: u64, epoch_size: u64) -> Option<(u64, u64)> {
    (0..100_000).find_map(|number| {
        let slot = candidate_slot(NameId::from_number(number), epoch, epoch_size);
        (slot == target).then_some((number, slot))
    })
}

fn selected_row<'a>(
    rows: &'a [Measurement],
    lease_window: u64,
    epoch_size: u64,
    slot_width: u64,
    slots_per_epoch: u64,
) -> &'a Measurement {
    rows.iter()
        .find(|row| {
            row.lease_window == lease_window
                && row.epoch_size == epoch_size
                && row.slot_width == slot_width
                && row.slots_per_epoch == slots_per_epoch
        })
        .expect("selected sweep row must exist")
}

#[test]
fn temporal_sharding_correctness_and_fetch_boundary() {
    let alice = NameId::from_tag(0xa1);
    let bob = NameId::from_tag(0xb1);
    let carol = NameId::from_tag(0xc1);
    let params = ScheduleParams {
        epoch_size: 32,
        slot_width: 4,
        slots_per_epoch: 1,
    };
    let tip = 4 * params.epoch_size - 1;
    let lease = tip + 1;
    let alice_heights: Vec<u64> = (0..3)
        .map(|epoch| *candidate_window(alice, epoch, params.epoch_size, params.slot_width).start())
        .collect();

    // 1. Multiple epochs resolve to Alice's latest canonical transition.
    let mut history = CanonicalHistory::empty(tip);
    history.add_transition(alice_heights[0], transition(alice, 0, 1));
    history.add_transition(alice_heights[1], transition(alice, 1, 2));
    history.add_transition(alice_heights[2], transition(alice, 2, 3));
    let resolved = resolve_latest(alice, tip, lease, params, &history);
    assert_eq!(resolved.latest, Some(transition(alice, 2, 3)));
    assert_eq!(resolved.current, state(alice, 3));
    assert_eq!(resolved.accepted_transitions, 3);
    assert_eq!(resolved.blocks_fetched, resolved.candidate_heights.len());
    assert_eq!(
        candidate_block_count(alice, tip, lease, params),
        resolved.candidate_heights.len()
    );
    assert_eq!(resolved.search_range, 0..=tip);

    // 2. A name with no transition in its lease is absent after checking only
    // its schedule windows. An old transition outside the lease is ignored.
    let short_lease = params.epoch_size;
    let mut old_history = CanonicalHistory::empty(tip);
    old_history.add_transition(0, transition(alice, 0, 1));
    let absent = resolve_latest(alice, tip, short_lease, params, &old_history);
    assert_eq!(absent.latest, None);
    assert!(!absent.candidate_heights.is_empty());
    assert_eq!(absent.transitions_inspected, 0);
    assert_eq!(absent.blocks_fetched, absent.candidate_heights.len());

    // 3. Hundreds of unrelated transitions outside Alice's slots do not add
    // any Alice lookup work.
    let baseline = resolve_latest(alice, tip, lease, params, &history);
    let allowed: BTreeSet<u64> = baseline.candidate_heights.iter().copied().collect();
    let mut noisy = history.clone();
    for height in 0..=tip {
        if !allowed.contains(&height) {
            for index in 0..3 {
                let unrelated = if index == 0 { bob } else { carol };
                noisy.add_transition(height, transition(unrelated, 0, 1));
            }
        }
    }
    let noisy_result = resolve_latest(alice, tip, lease, params, &noisy);
    assert_eq!(noisy_result.latest, baseline.latest);
    assert_eq!(noisy_result.candidate_heights, baseline.candidate_heights);
    assert_eq!(noisy_result.blocks_fetched, baseline.blocks_fetched);
    assert_eq!(
        noisy_result.transitions_inspected,
        baseline.transitions_inspected
    );

    // 4. Same-slot unrelated activity is inspected because the ordinary block
    // body is needed, but it does not change Alice's result.
    let same_slot = alice_heights[1];
    let mut shared = history.clone();
    shared.add_transition(same_slot, transition(bob, 0, 1));
    shared.add_transition(same_slot, transition(carol, 0, 1));
    let shared_result = resolve_latest(alice, tip, lease, params, &shared);
    assert_eq!(shared_result.latest, baseline.latest);
    assert_eq!(
        shared_result.transitions_inspected,
        baseline.transitions_inspected + 2
    );

    // 5. A valid-looking Alice transition at a non-permitted height is not a
    // legal publication and cannot affect the resolver.
    let disallowed = (0..=tip)
        .find(|height| !baseline.candidate_heights.contains(height))
        .expect("the window must leave at least one disallowed height");
    let mut invalid_publication = CanonicalHistory::empty(tip);
    invalid_publication.add_transition(disallowed, transition(alice, 0, 1));
    let invalid_result = resolve_latest(alice, tip, lease, params, &invalid_publication);
    assert_eq!(invalid_result.latest, None);
    assert!(!invalid_result.candidate_heights.contains(&disallowed));

    // 6. Two candidate successors from the same predecessor are resolved in
    // canonical vector order. The second one is stale after the first is
    // accepted; this is the synthetic equivalent of a nullifier conflict.
    let conflict_height = alice_heights[0];
    let mut conflict = CanonicalHistory::empty(tip);
    let first = transition_between(state(alice, 0), tagged_state(alice, 1, 1));
    let second = transition_between(state(alice, 0), tagged_state(alice, 1, 2));
    conflict.add_transition(conflict_height, first);
    conflict.add_transition(conflict_height, second);
    let conflict_result = resolve_latest(alice, tip, lease, params, &conflict);
    assert_eq!(conflict_result.latest, Some(first));
    assert_eq!(conflict_result.accepted_transitions, 1);
    assert_eq!(conflict_result.transitions_inspected, 2);

    // 7. A changed predecessor identity, changed successor identity/version,
    // changed lookup name, and cross-name successor are all rejected by the
    // minimal state-lineage checks.
    let mut malformed = CanonicalHistory::empty(tip);
    malformed.add_transition(
        conflict_height,
        transition_between(tagged_state(alice, 0, 99), tagged_state(alice, 1, 3)),
    );
    malformed.add_transition(
        alice_heights[1],
        transition_between(state(alice, 0), state(alice, 2)),
    );
    malformed.add_transition(
        alice_heights[2],
        transition_between(state(alice, 0), state(bob, 1)),
    );
    let malformed_result = resolve_latest(alice, tip, lease, params, &malformed);
    assert_eq!(malformed_result.latest, None);
    assert_eq!(
        resolve_latest(bob, tip, lease, params, &malformed).latest,
        None
    );
}

#[test]
fn temporal_sharding_boundary_and_reorg_cases() {
    let alice = NameId::from_tag(0xa1);
    let params = ScheduleParams {
        epoch_size: 16,
        slot_width: 4,
        slots_per_epoch: 1,
    };

    for epoch in [0, 1, 2] {
        let window = candidate_window(alice, epoch, params.epoch_size, params.slot_width);
        let first = *window.start();
        let last = *window.end();
        assert!(first >= epoch * params.epoch_size);
        assert!(last < (epoch + 1) * params.epoch_size);

        // Tip exactly at the first legal block: the resolver handles a tip
        // inside the current slot/window.
        let mut first_history = CanonicalHistory::empty(first);
        first_history.add_transition(first, transition(alice, 0, 1));
        let first_result = resolve_latest(alice, first, 1, params, &first_history);
        assert_eq!(first_result.latest, Some(transition(alice, 0, 1)));

        // The last permitted block and the lease start are both inclusive.
        let lease = last + 1;
        let mut last_history = CanonicalHistory::empty(last);
        last_history.add_transition(last, transition(alice, 0, 1));
        let last_result = resolve_latest(alice, last, lease, params, &last_history);
        assert_eq!(last_result.latest, Some(transition(alice, 0, 1)));
    }

    // A publication exactly on a lease-window boundary is still searched.
    let epoch = 4;
    let boundary = *candidate_window(alice, epoch, params.epoch_size, params.slot_width).start();
    let tip = boundary + 63;
    let mut boundary_history = CanonicalHistory::empty(tip);
    boundary_history.add_transition(boundary, transition(alice, 0, 1));
    let boundary_result = resolve_latest(alice, tip, 64, params, &boundary_history);
    assert_eq!(*boundary_result.search_range.start(), boundary);
    assert_eq!(boundary_result.latest, Some(transition(alice, 0, 1)));

    // A canonical reorg replaces the block body; the same resolver follows
    // the replacement history without a checkpoint or special Names rule.
    let reorg_height = *candidate_window(alice, 3, params.epoch_size, params.slot_width).start();
    let mut canonical = CanonicalHistory::empty(reorg_height);
    let original = transition_between(state(alice, 0), tagged_state(alice, 1, 1));
    canonical.add_transition(reorg_height, original);
    assert_eq!(
        resolve_latest(alice, reorg_height, reorg_height + 1, params, &canonical).latest,
        Some(original)
    );
    let replacement = transition_between(state(alice, 0), tagged_state(alice, 1, 2));
    let mut replacement_block = Block::empty(reorg_height);
    replacement_block.ironwood_action_count = 1;
    replacement_block.transitions.push(replacement);
    canonical.replace_block(replacement_block);
    assert_eq!(
        resolve_latest(alice, reorg_height, reorg_height + 1, params, &canonical).latest,
        Some(replacement)
    );
}

#[test]
fn ironwood_tree_size_metadata_skips_only_empty_candidate_bodies() {
    let alice = NameId::from_tag(0xa1);
    let params = ScheduleParams {
        epoch_size: 64,
        slot_width: 4,
        slots_per_epoch: 1,
    };
    let lease = 10_000;
    let tip = lease - 1;
    let heights = candidate_heights(alice, tip, lease, params);
    assert!(!heights.is_empty());

    for percent in [1, 10, 50, 100] {
        let history = activity_history(tip, percent);
        let body_fetches_without_metadata = heights.len();
        let body_fetches_with_metadata = body_fetches_with_tree_skip(&history, &heights);
        assert!(body_fetches_with_metadata <= body_fetches_without_metadata);
        if percent == 100 {
            assert_eq!(body_fetches_with_metadata, body_fetches_without_metadata);
        }
        println!(
            "tree-density={}%, searched-heights={}, body-fetches-without-tree={}, body-fetches-with-tree={}, reduction={:.1}%",
            percent,
            heights.len(),
            body_fetches_without_metadata,
            body_fetches_with_metadata,
            100.0 * (body_fetches_without_metadata - body_fetches_with_metadata) as f64
                / body_fetches_without_metadata as f64
        );
    }

    // Tree metadata changes body work only; it cannot change the schedule's
    // candidate heights.
    assert_eq!(heights, candidate_heights(alice, tip, lease, params));
}

#[test]
fn temporal_sharding_parameter_sweep_and_adversarial_observations() {
    let alice = NameId::from_tag(0xa1);
    let lease_windows = [1_000, 10_000, 40_000, 100_000];
    let widths = [1, 2, 4, 8];
    let slot_counts = [1, 2, 4];
    let mut rows = Vec::new();

    for lease in lease_windows {
        for epoch_size in epoch_sizes_for(lease) {
            let reference_tip = lease * 10 - 1;
            let search = lease_range(reference_tip, lease);
            let first_epoch = *search.start() / epoch_size;
            let last_epoch = *search.end() / epoch_size;
            for slots_per_epoch in slot_counts {
                let offsets_by_epoch: BTreeMap<u64, Vec<u64>> = (first_epoch..=last_epoch)
                    .map(|epoch| {
                        let offsets = candidate_offsets(
                            alice,
                            epoch,
                            ScheduleParams {
                                epoch_size,
                                slot_width: 1,
                                slots_per_epoch,
                            },
                        );
                        (epoch, offsets)
                    })
                    .collect();
                for slot_width in widths {
                    rows.push(measure(
                        alice,
                        lease,
                        epoch_size,
                        slot_width,
                        slots_per_epoch,
                        &offsets_by_epoch,
                    ));
                }
            }
        }
    }

    assert_eq!(rows.len(), 4 * 9 * 4 * 3);
    println!("temporal-sweep-rows={}", rows.len());
    println!(
        "L E slots width candidate-blocks fraction-of-L improvement avg-delay worst-delay p50 p95 work*worst"
    );

    println!("strict-schedule rows (slots=1, width=1)");
    for lease in lease_windows {
        for epoch_size in epoch_sizes_for(lease) {
            let row = selected_row(&rows, lease, epoch_size, 1, 1);
            println!(
                "strict {} {} {} {:.6} {:.2} {:.2} {} {} {} {}",
                row.lease_window,
                row.epoch_size,
                row.candidate_blocks,
                row.fraction_of_lease,
                row.lookup_improvement,
                row.delay.average,
                row.delay.worst,
                row.delay.p50,
                row.delay.p95,
                row.work_times_worst_delay
            );
        }
    }

    // Representative rows make the central tradeoff directly reviewable:
    // strict slot, four-block window, and four slots at the same spacing.
    let representative_lease = 40_000;
    for (width, slots) in [(1, 1), (4, 1), (1, 4), (4, 4)] {
        let row = selected_row(&rows, representative_lease, 256, width, slots);
        println!(
            "{} {} {} {} {} {:.6} {:.2} {:.2} {} {} {} {}",
            row.lease_window,
            row.epoch_size,
            row.slots_per_epoch,
            row.slot_width,
            row.candidate_blocks,
            row.fraction_of_lease,
            row.lookup_improvement,
            row.delay.average,
            row.delay.worst,
            row.delay.p50,
            row.delay.p95,
            row.work_times_worst_delay
        );
    }

    for lease in lease_windows {
        let lease_rows: Vec<_> = rows
            .iter()
            .filter(|row| row.lease_window == lease && row.candidate_blocks > 0)
            .collect();
        let min_work = lease_rows
            .iter()
            .min_by_key(|row| row.candidate_blocks)
            .expect("at least one schedule row has a candidate block");
        let latency_limited = lease_rows
            .iter()
            .filter(|row| row.delay.worst <= lease / 10)
            .min_by_key(|row| row.candidate_blocks)
            .expect("a dense enough schedule has a row under L/10 delay");
        let min_product = lease_rows
            .iter()
            .min_by_key(|row| row.work_times_worst_delay)
            .expect("at least one schedule row has a product");
        println!(
            "best L={} min-work=(E={},slots={},w={},blocks={},worst={}) latency<=L/10=(E={},slots={},w={},blocks={},worst={}) min-work*worst=(E={},slots={},w={},blocks={},worst={},product={})",
            lease,
            min_work.epoch_size,
            min_work.slots_per_epoch,
            min_work.slot_width,
            min_work.candidate_blocks,
            min_work.delay.worst,
            latency_limited.epoch_size,
            latency_limited.slots_per_epoch,
            latency_limited.slot_width,
            latency_limited.candidate_blocks,
            latency_limited.delay.worst,
            min_product.epoch_size,
            min_product.slots_per_epoch,
            min_product.slot_width,
            min_product.candidate_blocks,
            min_product.delay.worst,
            min_product.work_times_worst_delay
        );
    }

    let (occupied, maximum_collision) = collision_stats(1_000, 0, 64);
    let grind = find_grind(0, 0, 64).expect("a 64-slot target should be found by grinding");
    println!(
        "collisions names=1000 epoch-size=64 occupied-slots={} max-names-in-slot={} grind-first-slot-name-number={} grind-slot={}",
        occupied, maximum_collision, grind.0, grind.1
    );

    // This is an observational check, not a protocol rule: deterministic
    // public schedules permit name-choice grinding, while domain separation
    // prevents cross-purpose hash interpretation but does not add entropy.
    assert_eq!(grind.1, 0);
    assert!(maximum_collision >= 1);
}
