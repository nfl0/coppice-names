//! Test-only experiment for sparse, owner-authenticated Names locator
//! refreshes.
//!
//! This file deliberately does not implement a production Names API. It uses
//! a synthetic canonical history to test the discovery boundary:
//!
//! * state transitions are legal at arbitrary heights;
//! * locators are legal only in deterministic name-derived windows;
//! * a locator authenticates a canonical state-note lineage head;
//! * a resolver scans the canonical tail after the locator; and
//! * no global application root or server-side name index exists.
//!
//! The `CanonicalFacts` value is a test-side stand-in for the authenticated
//! state-note proof already established by the prior experiments. It is not a
//! lookup index and is never used to choose which blocks the resolver fetches.

use blake2b_simd::Params;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

type Digest = [u8; 32];

const LOCATOR_DOMAIN: &[u8] = b"coppice.names.locator-slot.v1";
const AUTH_DOMAIN: &[u8] = b"coppice.names.locator-auth.v1";
const AUTH_PERSONALIZATION: &[u8] = b"CoppiceLocAuthV1";

const BLOCKS_PER_YEAR_AT_75_SECONDS: u64 = 365 * 24 * 60 * 60 / 75;
const BLOCKS_PER_100K: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct NameId(Digest);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Authority(Digest);

impl Authority {
    fn from_tag(tag: u8) -> Self {
        Self([tag; 32])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    name_id: NameId,
    version: u64,
    value: u64,
    commitment: Digest,
    owner: Authority,
}

fn digest(parts: &[&[u8]]) -> Digest {
    let mut input = Vec::new();
    for part in parts {
        input.extend_from_slice(part);
    }
    Params::new()
        .hash_length(32)
        .personal(AUTH_PERSONALIZATION)
        .hash(&input)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn state(name_id: NameId, version: u64, value: u64, owner: Authority, branch_tag: u64) -> State {
    let commitment = digest(&[
        b"coppice.names.synthetic-state.v1",
        &name_id.0,
        &version.to_le_bytes(),
        &value.to_le_bytes(),
        &owner.0,
        &branch_tag.to_le_bytes(),
    ]);
    State {
        name_id,
        version,
        value,
        commitment,
        owner,
    }
}

fn genesis(name_id: NameId, owner: Authority) -> State {
    state(name_id, 0, 0, owner, 0)
}

fn locator_offset(name_id: NameId, epoch: u64, epoch_size: u64) -> u64 {
    assert!(epoch_size > 0);
    let mut input = Vec::with_capacity(LOCATOR_DOMAIN.len() + 32 + 8);
    input.extend_from_slice(LOCATOR_DOMAIN);
    input.extend_from_slice(&name_id.0);
    input.extend_from_slice(&epoch.to_le_bytes());
    let hash = Params::new()
        .hash_length(8)
        .personal(b"CoppiceLocSlot")
        .hash(&input);
    let bytes: [u8; 8] = hash.as_bytes().try_into().unwrap();
    u64::from_le_bytes(bytes) % epoch_size
}

fn locator_window(
    name_id: NameId,
    epoch: u64,
    epoch_size: u64,
    slot_width: u64,
) -> RangeInclusive<u64> {
    assert!(epoch_size > 0);
    assert!(slot_width > 0);
    let epoch_start = epoch
        .checked_mul(epoch_size)
        .expect("synthetic locator height overflow");
    let epoch_end = epoch_start
        .checked_add(epoch_size - 1)
        .expect("synthetic locator height overflow");
    let start = epoch_start
        .checked_add(locator_offset(name_id, epoch, epoch_size))
        .expect("synthetic locator height overflow");
    let end = start.saturating_add(slot_width - 1).min(epoch_end);
    start..=end
}

fn is_locator_height(name_id: NameId, height: u64, epoch_size: u64, slot_width: u64) -> bool {
    locator_window(name_id, height / epoch_size, epoch_size, slot_width).contains(&height)
}

fn next_locator_height_after(
    name_id: NameId,
    height: u64,
    epoch_size: u64,
    slot_width: u64,
) -> u64 {
    let first_epoch = height / epoch_size;
    for delta in 0..=8 {
        let epoch = first_epoch + delta;
        let window = locator_window(name_id, epoch, epoch_size, slot_width);
        if let Some(next) = (*window.start()..=*window.end()).find(|candidate| *candidate > height)
        {
            return next;
        }
    }
    panic!("synthetic schedule did not provide a future locator height")
}

fn schedule_heights_in_range(
    name_id: NameId,
    start: u64,
    end: u64,
    epoch_size: u64,
    slot_width: u64,
) -> Vec<u64> {
    if start > end {
        return Vec::new();
    }
    let first_epoch = start / epoch_size;
    let last_epoch = end / epoch_size;
    let mut heights = BTreeSet::new();
    for epoch in first_epoch..=last_epoch {
        let window = locator_window(name_id, epoch, epoch_size, slot_width);
        let window_start = (*window.start()).max(start);
        let window_end = (*window.end()).min(end);
        if window_start <= window_end {
            heights.extend(window_start..=window_end);
        }
    }
    heights.into_iter().collect()
}

fn candidate_locator_heights(
    name_id: NameId,
    tip: u64,
    search_window: u64,
    epoch_size: u64,
    slot_width: u64,
) -> Vec<u64> {
    assert!(search_window > 0);
    let start = tip.saturating_sub(search_window - 1);
    schedule_heights_in_range(name_id, start, tip, epoch_size, slot_width)
}

fn locator_authorization(locator: &LocatorRefresh) -> Digest {
    digest(&[
        AUTH_DOMAIN,
        &locator.name_id.0,
        &locator.epoch.to_le_bytes(),
        &locator.referenced_state.name_id.0,
        &locator.referenced_state.version.to_le_bytes(),
        &locator.referenced_state.value.to_le_bytes(),
        &locator.referenced_commitment,
        &locator.authority.0,
        &locator.expiry_epoch.to_le_bytes(),
        &[locator.immediate_publication as u8],
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateTransition {
    name_id: NameId,
    predecessor_state: State,
    successor_state: State,
    successor_commitment: Digest,
    operation: u64,
    authority: Authority,
    authorization: Digest,
}

fn transition_authorization(transition: &StateTransition) -> Digest {
    digest(&[
        b"coppice.names.synthetic-transition.v1",
        &transition.name_id.0,
        &transition.predecessor_state.commitment,
        &transition.successor_state.commitment,
        &transition.operation.to_le_bytes(),
        &transition.authority.0,
    ])
}

fn update_transition(predecessor: State, successor: State, operation: u64) -> StateTransition {
    let mut transition = StateTransition {
        name_id: predecessor.name_id,
        predecessor_state: predecessor,
        successor_state: successor,
        successor_commitment: successor.commitment,
        operation,
        authority: predecessor.owner,
        authorization: [0; 32],
    };
    transition.authorization = transition_authorization(&transition);
    transition
}

fn transition_is_valid(current: &State, transition: &StateTransition) -> bool {
    transition.name_id == current.name_id
        && transition.predecessor_state == *current
        && transition.successor_state.name_id == current.name_id
        && transition.successor_commitment == transition.successor_state.commitment
        && transition.successor_state.version == current.version + 1
        && transition.authority == current.owner
        && transition.authorization == transition_authorization(transition)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocatorRefresh {
    name_id: NameId,
    epoch: u64,
    referenced_state: State,
    referenced_commitment: Digest,
    authority: Authority,
    expiry_epoch: u64,
    immediate_publication: bool,
    authorization: Digest,
}

impl LocatorRefresh {
    fn for_state(state: State, epoch: u64) -> Self {
        let mut locator = Self {
            name_id: state.name_id,
            epoch,
            referenced_state: state,
            referenced_commitment: state.commitment,
            authority: state.owner,
            expiry_epoch: epoch,
            immediate_publication: false,
            authorization: [0; 32],
        };
        locator.authorization = locator_authorization(&locator);
        locator
    }

    fn on_update(state: State, epoch: u64) -> Self {
        let mut locator = Self {
            name_id: state.name_id,
            epoch,
            referenced_state: state,
            referenced_commitment: state.commitment,
            authority: state.owner,
            expiry_epoch: epoch,
            immediate_publication: true,
            authorization: [0; 32],
        };
        locator.authorization = locator_authorization(&locator);
        locator
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocatorBatch {
    epoch: u64,
    entries: Vec<LocatorRefresh>,
}

impl LocatorBatch {
    fn new(epoch: u64, entries: Vec<LocatorRefresh>) -> Self {
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|entry| entry.epoch == epoch));
        Self { epoch, entries }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Block {
    height: u64,
    ironwood_action_count: u64,
    locator_transaction_count: u64,
    transitions: Vec<StateTransition>,
    /// Entries are in canonical transaction/action order within the block.
    locators: Vec<LocatorRefresh>,
}

impl Block {
    fn empty(height: u64) -> Self {
        Self {
            height,
            ironwood_action_count: 0,
            locator_transaction_count: 0,
            transitions: Vec::new(),
            locators: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalHistory {
    initial_states: BTreeMap<NameId, State>,
    blocks: Vec<Block>,
}

impl CanonicalHistory {
    fn empty(tip: u64, initial_states: impl IntoIterator<Item = State>) -> Self {
        Self {
            initial_states: initial_states
                .into_iter()
                .map(|state| (state.name_id, state))
                .collect(),
            blocks: (0..=tip).map(Block::empty).collect(),
        }
    }

    fn add_transition(&mut self, height: u64, transition: StateTransition) {
        let block = self
            .blocks
            .get_mut(height as usize)
            .expect("synthetic history must cover transition height");
        assert_eq!(block.height, height);
        block.ironwood_action_count += 1;
        block.transitions.push(transition);
    }

    fn add_locator(&mut self, height: u64, locator: LocatorRefresh) {
        let block = self
            .blocks
            .get_mut(height as usize)
            .expect("synthetic history must cover locator height");
        assert_eq!(block.height, height);
        block.ironwood_action_count += 1;
        block.locator_transaction_count += 1;
        block.locators.push(locator);
    }

    fn add_locator_batch(
        &mut self,
        height: u64,
        batch: LocatorBatch,
        epoch_size: u64,
        slot_width: u64,
    ) {
        assert!(batch.entries.iter().all(|entry| {
            locator_window(entry.name_id, batch.epoch, epoch_size, slot_width).contains(&height)
        }));
        let block = self
            .blocks
            .get_mut(height as usize)
            .expect("synthetic history must cover batch height");
        assert_eq!(block.height, height);
        block.ironwood_action_count += batch.entries.len() as u64;
        block.locator_transaction_count += 1;
        block.locators.extend(batch.entries);
    }

    fn add_ironwood_actions(&mut self, height: u64, count: u64) {
        let block = self
            .blocks
            .get_mut(height as usize)
            .expect("synthetic history must cover action height");
        assert_eq!(block.height, height);
        block.ironwood_action_count += count;
    }

    fn replace_block(&mut self, block: Block) {
        let destination = self
            .blocks
            .get_mut(block.height as usize)
            .expect("synthetic reorg must replace an existing block");
        *destination = block;
    }

    fn block(&self, height: u64) -> &Block {
        let block = self
            .blocks
            .get(height as usize)
            .expect("resolver must remain inside the synthetic tip");
        assert_eq!(block.height, height);
        block
    }

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

    /// Produce authenticated state-note facts for this canonical branch.
    ///
    /// A real locator proof would authenticate these facts cryptographically;
    /// this oracle is intentionally separate from resolver block fetching.
    fn authenticated_facts(&self) -> CanonicalFacts {
        let mut current = self.initial_states.clone();
        let mut states = BTreeMap::new();
        for state in current.values() {
            states.insert(state.commitment, *state);
        }

        let mut current_after = Vec::with_capacity(self.blocks.len());
        let mut accepted_transitions = Vec::new();
        for block in &self.blocks {
            for transition in &block.transitions {
                let Some(previous) = current.get(&transition.name_id).copied() else {
                    continue;
                };
                if transition_is_valid(&previous, transition) {
                    current.insert(transition.name_id, transition.successor_state);
                    states.insert(
                        transition.successor_state.commitment,
                        transition.successor_state,
                    );
                    accepted_transitions.push((block.height, *transition));
                }
            }
            current_after.push(current.clone());
        }

        CanonicalFacts {
            states,
            current_after,
            accepted_transitions,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalFacts {
    states: BTreeMap<Digest, State>,
    current_after: Vec<BTreeMap<NameId, State>>,
    accepted_transitions: Vec<(u64, StateTransition)>,
}

impl CanonicalFacts {
    fn current_at(&self, height: u64, name_id: NameId) -> Option<State> {
        self.current_after
            .get(height as usize)
            .and_then(|states| states.get(&name_id).copied())
    }
}

/// The locator proof includes currentness at the locator's canonical
/// position. Without this fact, an owner could publish a validly signed old
/// state after a newer state already existed, and a locator-only resolver
/// would be unsound.
fn locator_is_valid(
    locator: &LocatorRefresh,
    height: u64,
    target_name: NameId,
    epoch_size: u64,
    slot_width: u64,
    facts: &CanonicalFacts,
) -> bool {
    let current = facts.current_at(height, target_name);
    locator.name_id == target_name
        && locator.referenced_state.name_id == target_name
        && locator.epoch == height / epoch_size
        && locator.expiry_epoch >= locator.epoch
        && locator.referenced_commitment == locator.referenced_state.commitment
        && locator.authority == locator.referenced_state.owner
        && locator.authorization == locator_authorization(locator)
        && (locator.immediate_publication
            || locator_window(locator.name_id, locator.epoch, epoch_size, slot_width)
                .contains(&height))
        && facts.states.get(&locator.referenced_commitment) == Some(&locator.referenced_state)
        && current == Some(locator.referenced_state)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolutionStatus {
    Current,
    MissingLocator,
    ExpiredLocator,
    LocatorOnly,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LookupStats {
    candidate_locator_blocks_checked: usize,
    tail_blocks_scanned: usize,
    header_probes: usize,
    bodies_inspected: usize,
    bodies_skipped_by_tree: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Resolution {
    status: ResolutionStatus,
    state: Option<State>,
    locator_height: Option<u64>,
    stats: LookupStats,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FoundLocator {
    height: u64,
    locator: LocatorRefresh,
}

#[derive(Clone, Debug)]
struct SearchResult {
    found: Option<FoundLocator>,
    stats: LookupStats,
    probed: BTreeSet<u64>,
    bodies: BTreeSet<u64>,
    skipped: BTreeSet<u64>,
}

fn probe_block<'a>(
    history: &'a CanonicalHistory,
    height: u64,
    use_tree_sizes: bool,
    tree_sizes: &[u64],
    stats: &mut LookupStats,
    probed: &mut BTreeSet<u64>,
    bodies: &mut BTreeSet<u64>,
    skipped: &mut BTreeSet<u64>,
) -> Option<&'a Block> {
    if probed.insert(height) {
        stats.header_probes += 1;
    }
    let has_ironwood_action = if use_tree_sizes {
        let after = tree_sizes[height as usize];
        let before = if height == 0 {
            0
        } else {
            tree_sizes[height as usize - 1]
        };
        after != before
    } else {
        true
    };
    if !has_ironwood_action {
        skipped.insert(height);
        return None;
    }
    if bodies.insert(height) {
        stats.bodies_inspected += 1;
    }
    Some(history.block(height))
}

fn search_latest_locator(
    name_id: NameId,
    tip: u64,
    search_window: u64,
    epoch_size: u64,
    slot_width: u64,
    history: &CanonicalHistory,
    facts: &CanonicalFacts,
    use_tree_sizes: bool,
) -> SearchResult {
    let candidate_heights =
        candidate_locator_heights(name_id, tip, search_window, epoch_size, slot_width);
    let tree_sizes = history.tree_sizes();
    let mut result = SearchResult {
        found: None,
        stats: LookupStats::default(),
        probed: BTreeSet::new(),
        bodies: BTreeSet::new(),
        skipped: BTreeSet::new(),
    };

    'candidate: for height in candidate_heights.into_iter().rev() {
        result.stats.candidate_locator_blocks_checked += 1;
        let Some(block) = probe_block(
            history,
            height,
            use_tree_sizes,
            &tree_sizes,
            &mut result.stats,
            &mut result.probed,
            &mut result.bodies,
            &mut result.skipped,
        ) else {
            continue;
        };
        for locator in block.locators.iter().rev() {
            if locator_is_valid(locator, height, name_id, epoch_size, slot_width, facts) {
                result.found = Some(FoundLocator {
                    height,
                    locator: *locator,
                });
                break 'candidate;
            }
        }
    }
    result
}

fn scan_tail(
    name_id: NameId,
    tip: u64,
    found: FoundLocator,
    mut result: SearchResult,
    history: &CanonicalHistory,
    use_tree_sizes: bool,
) -> Resolution {
    let tree_sizes = history.tree_sizes();
    let mut state = found.locator.referenced_state;
    if found.height < tip {
        for height in (found.height + 1)..=tip {
            result.stats.tail_blocks_scanned += 1;
            let Some(block) = probe_block(
                history,
                height,
                use_tree_sizes,
                &tree_sizes,
                &mut result.stats,
                &mut result.probed,
                &mut result.bodies,
                &mut result.skipped,
            ) else {
                continue;
            };
            for transition in &block.transitions {
                if transition.name_id == name_id && transition_is_valid(&state, transition) {
                    state = transition.successor_state;
                }
            }
        }
    }
    result.stats.bodies_skipped_by_tree = result.skipped.len();
    Resolution {
        status: ResolutionStatus::Current,
        state: Some(state),
        locator_height: Some(found.height),
        stats: result.stats,
    }
}

/// Strategy 1: find the newest valid locator in a recent discovery window,
/// then scan the entire canonical tail after it.
fn resolve_latest_locator_tail(
    name_id: NameId,
    tip: u64,
    search_window: u64,
    epoch_size: u64,
    slot_width: u64,
    history: &CanonicalHistory,
    facts: &CanonicalFacts,
    use_tree_sizes: bool,
) -> Resolution {
    let result = search_latest_locator(
        name_id,
        tip,
        search_window,
        epoch_size,
        slot_width,
        history,
        facts,
        use_tree_sizes,
    );
    let Some(found) = result.found else {
        let mut stats = result.stats;
        stats.bodies_skipped_by_tree = result.skipped.len();
        return Resolution {
            status: ResolutionStatus::MissingLocator,
            state: None,
            locator_height: None,
            stats,
        };
    };
    scan_tail(name_id, tip, found, result, history, use_tree_sizes)
}

/// Strategy 2: the protocol promises a locator at least every `refresh_period`
/// blocks. Missing one is an explicit expiry, never an implicit current state.
fn resolve_bounded_locator_tail(
    name_id: NameId,
    tip: u64,
    refresh_period: u64,
    epoch_size: u64,
    slot_width: u64,
    history: &CanonicalHistory,
    facts: &CanonicalFacts,
    use_tree_sizes: bool,
) -> Resolution {
    let result = search_latest_locator(
        name_id,
        tip,
        refresh_period,
        epoch_size,
        slot_width,
        history,
        facts,
        use_tree_sizes,
    );
    let Some(found) = result.found else {
        let mut stats = result.stats;
        stats.bodies_skipped_by_tree = result.skipped.len();
        return Resolution {
            status: ResolutionStatus::ExpiredLocator,
            state: None,
            locator_height: None,
            stats,
        };
    };
    scan_tail(name_id, tip, found, result, history, use_tree_sizes)
}

/// Strategy 3 for comparison: a locator-only client does not scan the tail
/// and therefore knows only what was true at the locator position.
fn resolve_locator_only(
    name_id: NameId,
    tip: u64,
    search_window: u64,
    epoch_size: u64,
    slot_width: u64,
    history: &CanonicalHistory,
    facts: &CanonicalFacts,
    use_tree_sizes: bool,
) -> Resolution {
    let result = search_latest_locator(
        name_id,
        tip,
        search_window,
        epoch_size,
        slot_width,
        history,
        facts,
        use_tree_sizes,
    );
    let Some(found) = result.found else {
        let mut stats = result.stats;
        stats.bodies_skipped_by_tree = result.skipped.len();
        return Resolution {
            status: ResolutionStatus::MissingLocator,
            state: None,
            locator_height: None,
            stats,
        };
    };
    let mut stats = result.stats;
    stats.bodies_skipped_by_tree = result.skipped.len();
    let _ = tip;
    Resolution {
        status: ResolutionStatus::LocatorOnly,
        state: Some(found.locator.referenced_state),
        locator_height: Some(found.height),
        stats,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct DelaySummary {
    average: f64,
    worst: u64,
    p50: u64,
    p95: u64,
    samples: usize,
}

fn summarize_delays(mut delays: Vec<u64>) -> Option<DelaySummary> {
    if delays.is_empty() {
        return None;
    }
    delays.sort_unstable();
    let sum: u64 = delays.iter().sum();
    let percentile = |percent: usize| delays[(delays.len() - 1) * percent / 100];
    Some(DelaySummary {
        average: sum as f64 / delays.len() as f64,
        worst: *delays.last().unwrap(),
        p50: percentile(50),
        p95: percentile(95),
        samples: delays.len(),
    })
}

fn upper_bound(values: &[u64], target: u64) -> usize {
    let mut low = 0;
    let mut high = values.len();
    while low < high {
        let middle = low + (high - low) / 2;
        if values[middle] <= target {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low
}

fn lower_bound(values: &[u64], target: u64) -> usize {
    let mut low = 0;
    let mut high = values.len();
    while low < high {
        let middle = low + (high - low) / 2;
        if values[middle] < target {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low
}

fn refreshes_from_legal_heights(legal: &[u64], refresh_period: u64) -> Vec<u64> {
    let mut refreshes = Vec::new();
    let mut previous = None;
    for &height in legal {
        if previous.is_none_or(|old| height.saturating_sub(old) >= refresh_period) {
            refreshes.push(height);
            previous = Some(height);
        }
    }
    refreshes
}

#[derive(Clone, Debug)]
struct ScheduleMeasurement {
    publication: Option<DelaySummary>,
    candidate_average: f64,
    candidate_worst: usize,
    tail: Option<DelaySummary>,
    total_average: f64,
    lookup_improvement: f64,
    expiry_rate: f64,
}

fn simulate_schedule_lookup(
    name_id: NameId,
    horizon: u64,
    lookup_window: u64,
    refresh_period: u64,
    epoch_size: u64,
    slot_width: u64,
    bounded: bool,
) -> ScheduleMeasurement {
    let schedule_end = horizon
        .saturating_add(refresh_period)
        .saturating_add(epoch_size.saturating_mul(2));
    let legal = schedule_heights_in_range(name_id, 0, schedule_end, epoch_size, slot_width);
    let refreshes = refreshes_from_legal_heights(&legal, refresh_period);
    let sample_start = refreshes.first().copied().unwrap_or(0);
    let span = horizon.saturating_sub(sample_start);
    let sample_count = (span as usize + 1).min(4096).max(1);
    let mut candidate_total = 0usize;
    let mut candidate_worst = 0usize;
    let mut lookup_total = 0u64;
    let mut expired = 0usize;
    let mut tails = Vec::new();
    let publication_sample_count = (horizon as usize + 1).min(4096).max(1);
    let mut publication_delays = Vec::with_capacity(publication_sample_count);

    for index in 0..sample_count {
        let tip = if sample_count == 1 {
            horizon
        } else {
            sample_start + (index as u64 * span) / (sample_count as u64 - 1)
        };
        let search_start = tip.saturating_sub(lookup_window - 1);
        let legal_start = lower_bound(&legal, search_start);
        let candidate_end = upper_bound(&legal, tip);
        let candidate_count = candidate_end.saturating_sub(legal_start);
        let refresh_index = upper_bound(&refreshes, tip);
        let latest_refresh = refresh_index.checked_sub(1).map(|index| refreshes[index]);
        let age = latest_refresh.map(|height| tip - height);
        let valid =
            age.is_some_and(|age| age < lookup_window && (!bounded || age < refresh_period));

        let candidate_checked = if valid {
            let refresh_height = latest_refresh.unwrap();
            let first_checked = lower_bound(&legal, refresh_height.max(search_start));
            candidate_end.saturating_sub(first_checked)
        } else {
            candidate_count
        };
        candidate_total += candidate_checked;
        candidate_worst = candidate_worst.max(candidate_checked);
        if valid {
            let tail = age.unwrap();
            tails.push(tail);
            // The locator block plus the canonical tail. Candidate header
            // probes in the tail are reused; no hidden second scan is counted.
            lookup_total += tail + 1;
        } else {
            expired += 1;
            lookup_total += candidate_checked as u64;
        }
    }

    // Publication latency is measured independently from lookup age: a state
    // transition may occur at any height, and the owner publishes its next
    // periodic locator at the first legal scheduled height at or after that
    // transition. The uniformly spaced sample keeps the sweep cheap while
    // covering the full horizon deterministically.
    for index in 0..publication_sample_count {
        let update_height = if publication_sample_count == 1 {
            horizon
        } else {
            (index as u64 * horizon) / (publication_sample_count as u64 - 1)
        };
        let next = lower_bound(&legal, update_height);
        if let Some(&next_height) = legal.get(next) {
            publication_delays.push(next_height - update_height);
        }
    }

    let total_average = lookup_total as f64 / sample_count as f64;
    ScheduleMeasurement {
        publication: summarize_delays(publication_delays),
        candidate_average: candidate_total as f64 / sample_count as f64,
        candidate_worst,
        tail: summarize_delays(tails),
        total_average,
        lookup_improvement: if total_average == 0.0 {
            0.0
        } else {
            lookup_window as f64 / total_average
        },
        expiry_rate: expired as f64 / sample_count as f64,
    }
}

fn locator_count_per_100k(refresh_period: u64) -> u64 {
    (BLOCKS_PER_100K + refresh_period - 1) / refresh_period
}

fn locator_count_per_year(refresh_period: u64) -> u64 {
    (BLOCKS_PER_YEAR_AT_75_SECONDS + refresh_period - 1) / refresh_period
}

fn locator_collision_stats(name_count: u64, epoch: u64, epoch_size: u64) -> (usize, usize) {
    let mut buckets = BTreeMap::<u64, usize>::new();
    for number in 0..name_count {
        let slot = locator_offset(NameId::from_number(number), epoch, epoch_size);
        *buckets.entry(slot).or_default() += 1;
    }
    let maximum = buckets.values().copied().max().unwrap_or(0);
    (buckets.len(), maximum)
}

fn find_slot_grind(target: u64, epoch: u64, epoch_size: u64) -> Option<u64> {
    (0..100_000)
        .find(|number| locator_offset(NameId::from_number(*number), epoch, epoch_size) == target)
}

fn activity_history(
    tip: u64,
    activity_percent: u64,
    initial_states: impl IntoIterator<Item = State>,
) -> CanonicalHistory {
    assert!(activity_percent <= 100);
    let mut history = CanonicalHistory::empty(tip, initial_states);
    for height in 0..=tip {
        let bucket = height
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407)
            % 100;
        if bucket < activity_percent {
            history.add_ironwood_actions(height, 1);
        }
    }
    history
}

fn find_common_locator_group(epoch: u64, epoch_size: u64, slot_width: u64) -> ([NameId; 3], u64) {
    let epoch_start = epoch * epoch_size;
    let epoch_end = epoch_start + epoch_size - 1;
    for height in epoch_start..=epoch_end {
        let mut names = Vec::new();
        for number in 1..10_000 {
            let name = NameId::from_number(number);
            if locator_window(name, epoch, epoch_size, slot_width).contains(&height) {
                names.push(name);
                if names.len() == 3 {
                    return ([names[0], names[1], names[2]], height);
                }
            }
        }
    }
    panic!("test names must share one locator window")
}

fn selected_schedule_row<'a>(
    rows: &'a [(u64, u64, u64, ScheduleMeasurement)],
    lease: u64,
    refresh_period: u64,
    epoch_size: u64,
) -> &'a ScheduleMeasurement {
    rows.iter()
        .find(|(row_lease, row_period, row_epoch, _)| {
            *row_lease == lease && *row_period == refresh_period && *row_epoch == epoch_size
        })
        .map(|(_, _, _, row)| row)
        .expect("selected schedule row must exist")
}

#[test]
fn locator_refresh_resolves_arbitrary_updates_and_canonical_tail() {
    let alice = NameId::from_tag(0xa1);
    let bob = NameId::from_tag(0xb1);
    let alice_owner = Authority::from_tag(0x11);
    let bob_owner = Authority::from_tag(0x22);
    let epoch_size = 32;
    let slot_width = 2;
    let tip = 12 * epoch_size - 1;
    let alice0 = genesis(alice, alice_owner);
    let bob0 = genesis(bob, bob_owner);
    let alice1 = state(alice, 1, 7, alice_owner, 1);
    let alice1_competing = state(alice, 1, 70, alice_owner, 101);
    let alice2 = state(alice, 2, 8, alice_owner, 2);
    let alice3 = state(alice, 3, 9, alice_owner, 3);
    let alice4 = state(alice, 4, 10, alice_owner, 4);

    let update_height = (1..tip)
        .find(|height| !is_locator_height(alice, *height, epoch_size, slot_width))
        .expect("an arbitrary non-locator update height must exist");
    let locator1_height = next_locator_height_after(alice, update_height, epoch_size, slot_width);
    let update2_height = locator1_height + 3;
    let update3_height = update2_height + 3;
    let update4_height = update3_height + 3;
    assert!(update4_height < tip);

    let mut history = CanonicalHistory::empty(tip, [alice0, bob0]);
    history.add_transition(update_height, update_transition(alice0, alice1, 1));
    history.add_transition(
        update_height,
        update_transition(alice0, alice1_competing, 101),
    );

    // State mutation is immediate and does not wait for a locator slot.
    let facts_after_update = history.authenticated_facts();
    assert_eq!(facts_after_update.current_at(tip, alice), Some(alice1));
    assert_eq!(facts_after_update.accepted_transitions.len(), 1);
    assert!(!is_locator_height(
        alice,
        update_height,
        epoch_size,
        slot_width
    ));

    // Model D: an on-update locator can be valid and authenticated, but a
    // fresh client cannot discover its arbitrary publication height without
    // scanning arbitrary history. The later scheduled refresh is still
    // required for predictable lookup.
    let mut immediate_only = history.clone();
    immediate_only.add_locator(
        update_height,
        LocatorRefresh::on_update(alice1, update_height / epoch_size),
    );
    let immediate_facts = immediate_only.authenticated_facts();
    let immediate_result = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &immediate_only,
        &immediate_facts,
        false,
    );
    assert_eq!(immediate_result.status, ResolutionStatus::MissingLocator);

    history.add_locator(
        locator1_height,
        LocatorRefresh::for_state(alice1, locator1_height / epoch_size),
    );

    // Several arbitrary-height updates occur after the locator. A tail scan
    // must find all of them, even though none is required to be locatable.
    history.add_transition(update2_height, update_transition(alice1, alice2, 2));
    history.add_transition(update3_height, update_transition(alice2, alice3, 3));
    history.add_transition(update4_height, update_transition(alice3, alice4, 4));
    let facts = history.authenticated_facts();

    let locator_only = resolve_locator_only(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &history,
        &facts,
        false,
    );
    assert_eq!(locator_only.status, ResolutionStatus::LocatorOnly);
    assert_eq!(locator_only.state, Some(alice1));

    let resolved_without_new_locator = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &history,
        &facts,
        false,
    );
    assert_eq!(
        resolved_without_new_locator.status,
        ResolutionStatus::Current
    );
    assert_eq!(resolved_without_new_locator.state, Some(alice4));
    assert_eq!(
        resolved_without_new_locator.stats.tail_blocks_scanned,
        (tip - locator1_height) as usize
    );

    // Repeated locators for an unchanged state are redundant and harmless.
    let repeated_height = next_locator_height_after(alice, update4_height, epoch_size, slot_width);
    history.add_locator(
        repeated_height,
        LocatorRefresh::for_state(alice4, repeated_height / epoch_size),
    );
    let repeated_again_height =
        next_locator_height_after(alice, repeated_height, epoch_size, slot_width);
    assert!(repeated_again_height < tip);
    history.add_locator(
        repeated_again_height,
        LocatorRefresh::for_state(alice4, repeated_again_height / epoch_size),
    );
    let facts_with_repeated = history.authenticated_facts();
    let repeated = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &history,
        &facts_with_repeated,
        false,
    );
    assert_eq!(repeated.status, ResolutionStatus::Current);
    assert_eq!(repeated.state, Some(alice4));
    assert_eq!(repeated.locator_height, Some(repeated_again_height));

    // A later locator for the newer state is selected by canonical position,
    // while the state lineage itself remains per-name and independent of Bob.
    assert_eq!(facts_with_repeated.current_at(tip, bob), Some(bob0));
    assert!(
        facts_with_repeated
            .accepted_transitions
            .iter()
            .all(|(_, transition)| transition.name_id == alice)
    );
}

#[test]
fn locator_refresh_rejects_forgery_old_state_and_locator_spam() {
    let alice = NameId::from_tag(0xa1);
    let bob = NameId::from_tag(0xb1);
    let alice_owner = Authority::from_tag(0x11);
    let bob_owner = Authority::from_tag(0x22);
    let epoch_size = 32;
    let slot_width = 2;
    let tip = 8 * epoch_size - 1;
    let alice0 = genesis(alice, alice_owner);
    let alice1 = state(alice, 1, 1, alice_owner, 1);
    let alice2 = state(alice, 2, 2, alice_owner, 2);
    let bob0 = genesis(bob, bob_owner);
    let update1 = 3;
    let update2 = 11;
    let old_locator_height = next_locator_height_after(alice, update2, epoch_size, slot_width);
    assert!(old_locator_height < tip);

    // A periodic locator carrying an otherwise valid current state is still
    // invalid outside its deterministic publication window. Immediate
    // on-update locators are the explicitly separate optional model tested
    // above; they are not discoverable by this scheduled resolver.
    let invalid_periodic_height = (0..=tip)
        .find(|height| !is_locator_height(alice, *height, epoch_size, slot_width))
        .expect("there must be an off-slot height");
    let invalid_periodic = LocatorRefresh::for_state(alice0, invalid_periodic_height / epoch_size);
    let initial_only = CanonicalHistory::empty(tip, [alice0]);
    let initial_facts = initial_only.authenticated_facts();
    assert!(!locator_is_valid(
        &invalid_periodic,
        invalid_periodic_height,
        alice,
        epoch_size,
        slot_width,
        &initial_facts,
    ));

    // A fabricated state is not in the authenticated canonical lineage.
    let fake_state = state(alice, 99, 99, alice_owner, 99);
    let fake_height = next_locator_height_after(alice, old_locator_height, epoch_size, slot_width);
    let mut fabricated = CanonicalHistory::empty(tip, [alice0, bob0]);
    fabricated.add_transition(update1, update_transition(alice0, alice1, 1));
    fabricated.add_locator(
        fake_height,
        LocatorRefresh::for_state(fake_state, fake_height / epoch_size),
    );
    let fabricated_facts = fabricated.authenticated_facts();
    let fabricated_result = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &fabricated,
        &fabricated_facts,
        false,
    );
    assert_eq!(fabricated_result.status, ResolutionStatus::MissingLocator);
    assert_eq!(fabricated_result.state, None);

    // Wrong-name and wrong-authority locators fail even when their signatures
    // are recomputed over the mutated fields.
    let wrong_name_height = next_locator_height_after(alice, fake_height, epoch_size, slot_width);
    let mut wrong_name = LocatorRefresh::for_state(bob0, wrong_name_height / epoch_size);
    wrong_name.name_id = alice;
    wrong_name.authorization = locator_authorization(&wrong_name);
    let mut wrong_authority = LocatorRefresh::for_state(alice1, old_locator_height / epoch_size);
    wrong_authority.authority = bob_owner;
    wrong_authority.authorization = locator_authorization(&wrong_authority);
    let mut wrong_history = CanonicalHistory::empty(tip, [alice0, bob0]);
    wrong_history.add_transition(update1, update_transition(alice0, alice1, 1));
    wrong_history.add_locator(wrong_name_height, wrong_name);
    wrong_history.add_locator(old_locator_height, wrong_authority);
    let wrong_facts = wrong_history.authenticated_facts();
    let wrong_result = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &wrong_history,
        &wrong_facts,
        false,
    );
    assert_eq!(wrong_result.status, ResolutionStatus::MissingLocator);

    // Critical old-state attack: the owner signs State1 after State2 is
    // already current. Existence and authority alone are insufficient; the
    // locator proof must bind currentness at its canonical position.
    let mut old_state_attack = CanonicalHistory::empty(tip, [alice0, bob0]);
    old_state_attack.add_transition(update1, update_transition(alice0, alice1, 1));
    old_state_attack.add_transition(update2, update_transition(alice1, alice2, 2));
    old_state_attack.add_locator(
        old_locator_height,
        LocatorRefresh::for_state(alice1, old_locator_height / epoch_size),
    );
    let old_facts = old_state_attack.authenticated_facts();
    assert_eq!(
        old_facts.current_at(old_locator_height, alice),
        Some(alice2)
    );
    assert!(!locator_is_valid(
        &old_state_attack.block(old_locator_height).locators[0],
        old_locator_height,
        alice,
        epoch_size,
        slot_width,
        &old_facts,
    ));
    let old_result = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &old_state_attack,
        &old_facts,
        false,
    );
    assert_eq!(old_result.status, ResolutionStatus::MissingLocator);
    assert_eq!(old_result.state, None);

    // Replaying a statement in a later epoch is rejected because epoch,
    // deployment domain, name, commitment, authority, and expiry are all
    // authenticated fields.
    let valid_epoch = old_locator_height / epoch_size;
    let replay_height =
        next_locator_height_after(alice, old_locator_height, epoch_size, slot_width);
    let replayed = LocatorRefresh::for_state(alice1, valid_epoch);
    assert_ne!(replay_height / epoch_size, replayed.epoch);
    assert!(!locator_is_valid(
        &replayed,
        replay_height,
        alice,
        epoch_size,
        slot_width,
        &wrong_facts,
    ));

    // Invalid locator-like entries at all candidate blocks do not alter the
    // result. They do increase body inspection, which is a bandwidth/DoS cost.
    let mut spammed = fabricated.clone();
    for height in candidate_locator_heights(alice, tip, tip + 1, epoch_size, slot_width) {
        let mut spam = LocatorRefresh::for_state(fake_state, height / epoch_size);
        spam.authorization = locator_authorization(&spam);
        spammed.add_locator(height, spam);
    }
    let spam_facts = spammed.authenticated_facts();
    let spam_result = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &spammed,
        &spam_facts,
        false,
    );
    assert_eq!(spam_result.status, ResolutionStatus::MissingLocator);
    assert!(spam_result.stats.bodies_inspected >= fabricated_result.stats.bodies_inspected);
}

#[test]
fn locator_refresh_reorg_and_missed_refresh_follow_canonical_history() {
    let alice = NameId::from_tag(0xa1);
    let owner = Authority::from_tag(0x11);
    let epoch_size = 32;
    let slot_width = 2;
    let refresh_period = 40;
    let tip = 10 * epoch_size - 1;
    let alice0 = genesis(alice, owner);
    let alice1 = state(alice, 1, 1, owner, 1);
    let alice2 = state(alice, 2, 2, owner, 2);
    let update1 = 3;
    let locator1 = next_locator_height_after(alice, update1, epoch_size, slot_width);
    let update2 = locator1 + 4;
    let locator2 = next_locator_height_after(alice, update2, epoch_size, slot_width);
    assert!(locator2 < tip);

    let mut canonical = CanonicalHistory::empty(tip, [alice0]);
    canonical.add_transition(update1, update_transition(alice0, alice1, 1));
    canonical.add_locator(
        locator1,
        LocatorRefresh::for_state(alice1, locator1 / epoch_size),
    );
    canonical.add_transition(update2, update_transition(alice1, alice2, 2));
    canonical.add_locator(
        locator2,
        LocatorRefresh::for_state(alice2, locator2 / epoch_size),
    );
    let facts = canonical.authenticated_facts();
    let before_reorg = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &canonical,
        &facts,
        false,
    );
    assert_eq!(before_reorg.state, Some(alice2));
    assert_eq!(before_reorg.locator_height, Some(locator2));

    // Replacement canonical history removes both State2 and its locator.
    // The resolver follows the replacement without checkpoints or special
    // Names fork-choice logic.
    let mut replacement = canonical.clone();
    replacement.replace_block(Block::empty(update2));
    replacement.replace_block(Block::empty(locator2));
    let replacement_facts = replacement.authenticated_facts();
    let after_reorg = resolve_latest_locator_tail(
        alice,
        tip,
        tip + 1,
        epoch_size,
        slot_width,
        &replacement,
        &replacement_facts,
        false,
    );
    assert_eq!(after_reorg.state, Some(alice1));
    assert_eq!(after_reorg.locator_height, Some(locator1));

    // Missed refresh: bounded strategy expires explicitly; a wider snapshot
    // strategy can still find the old locator and scan the old-to-tip tail.
    let missed_tip = locator1 + refresh_period + 10;
    let missed = resolve_bounded_locator_tail(
        alice,
        missed_tip,
        refresh_period,
        epoch_size,
        slot_width,
        &replacement,
        &replacement_facts,
        false,
    );
    assert_eq!(missed.status, ResolutionStatus::ExpiredLocator);
    assert_eq!(missed.state, None);

    let fallback = resolve_latest_locator_tail(
        alice,
        missed_tip,
        missed_tip + 1,
        epoch_size,
        slot_width,
        &replacement,
        &replacement_facts,
        false,
    );
    assert_eq!(fallback.status, ResolutionStatus::Current);
    assert_eq!(fallback.state, Some(alice1));
}

#[test]
fn locator_batch_is_independently_authenticated_and_optional() {
    let (names, common_height) = find_common_locator_group(1, 32, 8);
    let [alice, bob, carol] = names;
    let alice_owner = Authority::from_tag(0x11);
    let bob_owner = Authority::from_tag(0x22);
    let carol_owner = Authority::from_tag(0x33);
    let epoch_size = 32;
    let slot_width = 8;
    let tip = common_height + 2 * epoch_size;
    let alice0 = genesis(alice, alice_owner);
    let bob0 = genesis(bob, bob_owner);
    let carol0 = genesis(carol, carol_owner);
    let entries = vec![
        LocatorRefresh::for_state(alice0, 1),
        LocatorRefresh::for_state(bob0, 1),
        LocatorRefresh::for_state(carol0, 1),
    ];
    let batch = LocatorBatch::new(1, entries);
    let mut history = CanonicalHistory::empty(tip, [alice0, bob0, carol0]);
    history.add_locator_batch(common_height, batch, epoch_size, slot_width);
    assert_eq!(history.block(common_height).locator_transaction_count, 1);
    assert_eq!(history.block(common_height).locators.len(), 3);
    let facts = history.authenticated_facts();

    for name in names {
        let resolved = resolve_latest_locator_tail(
            name,
            tip,
            tip + 1,
            epoch_size,
            slot_width,
            &history,
            &facts,
            false,
        );
        assert_eq!(resolved.status, ResolutionStatus::Current);
        assert_eq!(resolved.state.map(|state| state.name_id), Some(name));
    }

    // Entries are independently owner-authenticated. A batcher/fee payer is
    // optional: a valid entry can be carried in a standalone transaction if
    // no batcher appears.
    let standalone_height = next_locator_height_after(alice, common_height, epoch_size, slot_width);
    history.add_locator(
        standalone_height,
        LocatorRefresh::for_state(alice0, standalone_height / epoch_size),
    );
    assert_eq!(
        history.block(standalone_height).locator_transaction_count,
        1
    );
    assert_eq!(history.block(standalone_height).locators.len(), 1);
}

#[test]
fn locator_refresh_tree_sizes_skip_bodies_without_changing_search() {
    let alice = NameId::from_tag(0xa1);
    let owner = Authority::from_tag(0x11);
    let epoch_size = 64;
    let slot_width = 4;
    let tip = 12 * epoch_size - 1;
    let alice0 = genesis(alice, owner);
    let alice1 = state(alice, 1, 1, owner, 1);
    let alice2 = state(alice, 2, 2, owner, 2);
    let update_height = (1..tip)
        .find(|height| !is_locator_height(alice, *height, epoch_size, slot_width))
        .unwrap();
    let locator_height = next_locator_height_after(alice, update_height, epoch_size, slot_width);
    let tail_height = locator_height + 17;
    assert!(tail_height < tip);

    for density in [1, 10, 50, 100] {
        let mut history = activity_history(tip, density, [alice0]);
        history.add_transition(update_height, update_transition(alice0, alice1, 1));
        history.add_locator(
            locator_height,
            LocatorRefresh::for_state(alice1, locator_height / epoch_size),
        );
        history.add_transition(tail_height, update_transition(alice1, alice2, 2));
        let facts = history.authenticated_facts();
        let without_tree = resolve_latest_locator_tail(
            alice,
            tip,
            tip + 1,
            epoch_size,
            slot_width,
            &history,
            &facts,
            false,
        );
        let with_tree = resolve_latest_locator_tail(
            alice,
            tip,
            tip + 1,
            epoch_size,
            slot_width,
            &history,
            &facts,
            true,
        );
        assert_eq!(without_tree.status, with_tree.status);
        assert_eq!(without_tree.state, with_tree.state);
        assert_eq!(without_tree.locator_height, with_tree.locator_height);
        assert_eq!(
            without_tree.stats.header_probes,
            with_tree.stats.header_probes
        );
        assert_eq!(
            without_tree.stats.tail_blocks_scanned,
            with_tree.stats.tail_blocks_scanned
        );
        assert!(with_tree.stats.bodies_inspected <= without_tree.stats.bodies_inspected);
        if density == 100 {
            assert_eq!(
                with_tree.stats.bodies_inspected,
                without_tree.stats.bodies_inspected
            );
        }
        println!(
            "tree-density={}%, header-probes={}, tail-blocks={}, bodies-without-tree={}, bodies-with-tree={}, reduction={:.1}%",
            density,
            without_tree.stats.header_probes,
            without_tree.stats.tail_blocks_scanned,
            without_tree.stats.bodies_inspected,
            with_tree.stats.bodies_inspected,
            100.0 * (without_tree.stats.bodies_inspected - with_tree.stats.bodies_inspected) as f64
                / without_tree.stats.bodies_inspected as f64
        );
    }
}

#[test]
fn locator_refresh_parameter_sweep_and_chain_load() {
    let alice = NameId::from_tag(0xa1);
    let lease_windows = [10_000, 40_000, 100_000];
    let refresh_periods = [32, 64, 128, 256, 512, 1_024, 2_048, 4_096];
    let epoch_sizes = [32, 64, 128, 256, 512, 1_024, 2_048, 4_096];
    let mut rows = Vec::new();

    for lease in lease_windows {
        for refresh_period in refresh_periods {
            for epoch_size in epoch_sizes {
                rows.push((
                    lease,
                    refresh_period,
                    epoch_size,
                    simulate_schedule_lookup(
                        alice,
                        100_000,
                        lease,
                        refresh_period,
                        epoch_size,
                        1,
                        true,
                    ),
                ));
            }
        }
    }
    assert_eq!(rows.len(), 3 * 8 * 8);

    println!("locator-sweep-rows={}", rows.len());
    println!(
        "bounded L R E publication-average publication-worst publication-p50 publication-p95 candidate-average candidate-worst tail-average tail-worst tail-p50 tail-p95 total-average improvement expiry-rate"
    );
    for lease in lease_windows {
        for refresh_period in refresh_periods {
            let row = selected_schedule_row(&rows, lease, refresh_period, refresh_period);
            let publication = row.publication;
            let tail = row.tail;
            println!(
                "bounded {} {} {} {:.2} {} {} {} {:.2} {} {:.2} {} {} {} {:.2} {:.2} {:.2}%",
                lease,
                refresh_period,
                refresh_period,
                publication.map_or(0.0, |summary| summary.average),
                publication.map_or(0, |summary| summary.worst),
                publication.map_or(0, |summary| summary.p50),
                publication.map_or(0, |summary| summary.p95),
                row.candidate_average,
                row.candidate_worst,
                tail.map_or(0.0, |summary| summary.average),
                tail.map_or(0, |summary| summary.worst),
                tail.map_or(0, |summary| summary.p50),
                tail.map_or(0, |summary| summary.p95),
                row.total_average,
                row.lookup_improvement,
                100.0 * row.expiry_rate,
            );
        }
    }

    println!("bounded-spacing L=40000 (E=R/2)");
    for refresh_period in [64, 128, 256, 512, 1_024, 2_048, 4_096] {
        let row = selected_schedule_row(&rows, 40_000, refresh_period, refresh_period / 2);
        let publication = row.publication;
        println!(
            "bounded {} {} {} {:.2} {} {} {} {:.2} {} {:.2} {} {} {} {:.2} {:.2} {:.2}%",
            40_000,
            refresh_period,
            refresh_period / 2,
            publication.map_or(0.0, |summary| summary.average),
            publication.map_or(0, |summary| summary.worst),
            publication.map_or(0, |summary| summary.p50),
            publication.map_or(0, |summary| summary.p95),
            row.candidate_average,
            row.candidate_worst,
            row.tail.map_or(0.0, |summary| summary.average),
            row.tail.map_or(0, |summary| summary.worst),
            row.tail.map_or(0, |summary| summary.p50),
            row.tail.map_or(0, |summary| summary.p95),
            row.total_average,
            row.lookup_improvement,
            100.0 * row.expiry_rate,
        );
    }

    println!("locator-window-effect L=40000 R=256 E=256");
    for width in [1, 4, 8] {
        let row = simulate_schedule_lookup(alice, 100_000, 40_000, 256, 256, width, true);
        println!(
            "width={} candidate-average={:.2} candidate-worst={} tail-average={} tail-worst={} total-average={:.2} expiry-rate={:.2}%",
            width,
            row.candidate_average,
            row.candidate_worst,
            row.tail.map_or(0.0, |summary| summary.average),
            row.tail.map_or(0, |summary| summary.worst),
            row.total_average,
            100.0 * row.expiry_rate,
        );
    }

    println!("snapshot-strategy representative rows");
    for (lease, refresh_period, epoch_size) in [
        (10_000, 256, 256),
        (40_000, 1_024, 1_024),
        (100_000, 4_096, 4_096),
    ] {
        let row =
            simulate_schedule_lookup(alice, 100_000, lease, refresh_period, epoch_size, 1, false);
        println!(
            "snapshot L={} R={} E={} candidate-average={:.2} candidate-worst={} tail-average={} tail-worst={} total-average={:.2} improvement={:.2}x missing-rate={:.2}%",
            lease,
            refresh_period,
            epoch_size,
            row.candidate_average,
            row.candidate_worst,
            row.tail.map_or(0.0, |summary| summary.average),
            row.tail.map_or(0, |summary| summary.worst),
            row.total_average,
            row.lookup_improvement,
            100.0 * row.expiry_rate,
        );
    }

    println!(
        "load-assumption block-interval=75s blocks-per-year={} blocks-per-100k={}",
        BLOCKS_PER_YEAR_AT_75_SECONDS, BLOCKS_PER_100K
    );
    println!("R locators-per-100k locators-per-year txs@1k txs@10k txs@100k txs@1m");
    for refresh_period in refresh_periods {
        let per_100k = locator_count_per_100k(refresh_period);
        let per_year = locator_count_per_year(refresh_period);
        println!(
            "{} {} {} {} {} {} {}",
            refresh_period,
            per_100k,
            per_year,
            per_100k * 1_000,
            per_100k * 10_000,
            per_100k * 100_000,
            per_100k * 1_000_000,
        );
    }

    let (occupied_slots, busiest_slot) = locator_collision_stats(1_000, 0, 64);
    let grind_name = find_slot_grind(0, 0, 64).expect("a target locator slot is grindable");
    println!(
        "locator-collisions names=1000 E=64 occupied-slots={} busiest-slot={} grind-name-number={} target-slot=0",
        occupied_slots, busiest_slot, grind_name
    );
    assert!(busiest_slot >= 1);
}
