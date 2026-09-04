//! Manual accepted-population storage proxy.
//!
//! Usage:
//! `cargo run -p coppice-names-sqlite --release --example accepted_population -- DB ACTIVE HISTORICAL`
//!
//! This exercises authoritative accepted-head insertion, terminal compaction
//! (represented by the reducer's deletion delta), explicit journal
//! finalization, index rebuild, and warm exact lookups. It does not benchmark
//! proof generation, Zcash acquisition, or a mobile device.

use coppice::transaction::TransactionHost;
use coppice_names::{
    protocol::{CanonicalUa, FieldElement, Name, Network, StateRef},
    reducer::{Head, HeadChange, ReducerTip, StateDelta},
    ruleset::ruleset_fingerprint,
};
use coppice_names_sqlite::{Coverage, SqliteNamesStore, StoreIdentity};
use std::{env, fs, path::PathBuf, time::Instant};

const BATCH: usize = 10_000;
const UA: &str = "uregtest1rxnn8qurdex552draeuvvvucggeknmmsxazg52mkatf0hrclhppe5jeqj6w7svqtxvxq320tw6ejsk4nm8zk8f35274vlwqerfx74904pydaxe27wnpq8llqxclaa0n04zg764ppzfruu4gsagmqw0mlvx";

fn main() {
    let mut arguments = env::args().skip(1);
    let path = PathBuf::from(arguments.next().expect("DB path is required"));
    let active: usize = arguments
        .next()
        .expect("active count is required")
        .parse()
        .expect("active count must be an integer");
    let historical: usize = arguments
        .next()
        .expect("historical count is required")
        .parse()
        .expect("historical count must be an integer");
    assert!(historical >= active, "historical must be at least active");

    let identity = StoreIdentity {
        deployment_id: [1; 32],
        ruleset_fingerprint: ruleset_fingerprint(),
        network: Network::Regtest,
        coverage: Coverage::Complete,
        minimum_rollback_blocks: 1,
    };
    let mut store = SqliteNamesStore::open(&path, identity).expect("open benchmark store");
    let ua = CanonicalUa::parse(Network::Regtest, UA).expect("benchmark UA");
    let started = Instant::now();
    let mut tip = None;
    let mut next_height = 1u32;

    let historical_only = historical - active;
    for first in (0..historical_only).step_by(BATCH) {
        let count = BATCH.min(historical_only - first);
        let heads = population(first, count, next_height, &ua);
        tip = apply_heads(&mut store, tip, next_height, &heads, true);
        next_height += 1;
        tip = apply_heads(&mut store, tip, next_height, &heads, false);
        next_height += 1;
        finalize_safe_prefix(&mut store, tip.expect("tip").height);
    }

    for first in (historical_only..historical).step_by(BATCH) {
        let count = BATCH.min(historical - first);
        let heads = population(first, count, next_height, &ua);
        tip = apply_heads(&mut store, tip, next_height, &heads, true);
        next_height += 1;
        finalize_safe_prefix(&mut store, tip.expect("tip").height);
    }
    let population_seconds = started.elapsed().as_secs_f64();

    let rebuild_started = Instant::now();
    store.rebuild_derived_indexes().expect("rebuild indexes");
    let rebuild_seconds = rebuild_started.elapsed().as_secs_f64();

    let lookup_count = active.min(1_000);
    let lookup_started = Instant::now();
    for offset in 0..lookup_count {
        let name = Name::parse(&format!("n{}", historical_only + offset)).unwrap();
        assert!(store.head(name.id().unwrap()).unwrap().is_some());
    }
    let lookup_seconds = lookup_started.elapsed().as_secs_f64();
    store
        .connection()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .expect("checkpoint WAL");
    let bytes = fs::metadata(&path).expect("database metadata").len();

    println!(
        "active={active} historical={historical} bytes={bytes} population_seconds={population_seconds:.3} index_rebuild_seconds={rebuild_seconds:.3} warm_lookups={lookup_count} warm_lookup_seconds={lookup_seconds:.6} tip_height={}",
        tip.expect("tip").height
    );
}

fn population(
    first: usize,
    count: usize,
    height: u32,
    ua: &CanonicalUa,
) -> Vec<(coppice_names::protocol::NameId, Head)> {
    (first..first + count)
        .map(|index| {
            let name = Name::parse(&format!("n{index}")).unwrap();
            let name_id = name.id().unwrap();
            let mut field = [0u8; 32];
            field[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_le_bytes());
            (
                name_id,
                Head {
                    name,
                    ua: ua.clone(),
                    producer: StateRef {
                        height,
                        tx_index: u32::try_from(index).unwrap(),
                        txid: name_id.to_bytes(),
                        action_index: 0,
                    },
                    commitment: FieldElement::from_bytes(field).unwrap(),
                    future_nf: FieldElement::from_bytes(field).unwrap(),
                    producer_epoch: 0,
                    expiry_height: u32::MAX,
                    terminal_height: None,
                },
            )
        })
        .collect()
}

fn apply_heads(
    store: &mut SqliteNamesStore,
    from_tip: Option<ReducerTip>,
    height: u32,
    heads: &[(coppice_names::protocol::NameId, Head)],
    insert: bool,
) -> Option<ReducerTip> {
    let to_tip = ReducerTip {
        height,
        hash: height_hash(height),
    };
    let delta = StateDelta {
        from_tip,
        to_tip: Some(to_tip),
        heads: heads
            .iter()
            .map(|(name_id, head)| HeadChange {
                name_id: *name_id,
                previous: (!insert).then(|| head.clone()),
                current: insert.then(|| head.clone()),
            })
            .collect(),
        commits: Vec::new(),
    };
    store
        .with_transaction(|transaction| transaction.apply_delta(&delta))
        .expect("apply accepted-state delta");
    Some(to_tip)
}

fn finalize_safe_prefix(store: &mut SqliteNamesStore, tip_height: u32) {
    if let Some(height) = tip_height.checked_sub(1) {
        store
            .with_transaction(|transaction| transaction.finalize_through(height))
            .expect("finalize explicit safe prefix");
    }
}

fn height_hash(height: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&height.to_le_bytes());
    hash
}
