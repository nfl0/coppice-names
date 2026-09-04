# ADR 0005: Transactional Names state and explicit coverage

Status: Accepted for the undeployed Names protocol

Date: 2026-09-04

## Context

The reducer's monolithic clone/snapshot path is useful for tests and small
exact resolvers, but complete local Names state must scale without cloning or
rewriting every head per block. A partial resolver also must not accidentally
interpret absence from its subset as globally authoritative `Missing`.

## Decision

The reducer emits exact per-block authoritative record deltas, including prior
and current head and COMMIT values. Its in-memory implementation maintains
rebuildable indexes for non-unique `future_nullifier -> {NameId}`, active-head
expiry height, terminal height, and COMMIT inclusion height. All transitions,
including rollback, pass through index-maintaining replacement functions;
snapshot restore rebuilds indexes from authoritative records.

`coppice-names-sqlite` is the first host implementation. It uses WAL, foreign
keys, and `synchronous=FULL`, and stores:

- one row per current or cooldown head;
- a deliberately non-unique native index over future nullifiers;
- native partial indexes over active expiry and terminal height;
- one row per pending COMMIT, indexed by inclusion height;
- deployment, ruleset, network, canonical tip, finalization, coverage, and
  staged Core metadata; and
- bounded per-block prior records for rollback.

When embedded in a `zcash_client_sqlite` wallet, every schema object uses its
reserved `ext_` namespace. The optional `wallet-extension` adapter accepts the
wallet's restricted extension-transaction handle, so it can write Names rows
inside the wallet's already-open transaction without gaining permission to
write wallet tables or issue transaction-control statements. The same outer
commit therefore publishes the wallet scan, Core checkpoint, indexed Names
records, and rollback journal. The stored Core checkpoint is cleared on a
rewind and replaced only after the host has replayed to the wallet's new tip.
If a wallet must rewind deeper than the retained Names journal, the same outer
transaction clears only replayable public Names state; it never blocks the
wallet rewind or silently deletes account-private workflow and custody data.

The host owns an outer transaction for a bounded sync batch and a savepoint per
block. A deterministic block failure may roll back that savepoint and commit
the preceding consistent prefix. A storage, integrity, transaction,
interruption, or panic failure rolls back the complete batch. Journals are
pruned only through explicit finalization and never below the configured safe
minimum.

Coverage is part of durable identity and is exactly one of:

- `Complete`: complete local public chain-derived state for one network,
  runtime, and Names deployment;
- `Exact(NameId)`: authenticated evidence for one exact requested name; or
- `Owned`: an account-selected set, which can never establish arbitrary
  absence.

Complete and partial stores may share authenticated block acquisition but are
not interchangeable. A `Missing` answer is valid only at the store's exact
authenticated `(height, block_hash)` tip. Tip advance or reorganization makes
the negative answer stale until the corresponding evidence is processed.

Full bootstrap authority is replay from the user's own archival Zcash node.
Remote Names snapshots and mutable indexes never become authority. A light
wallet may use one authenticated Zaino/lightwalletd-style provider for exact
resolution, including user-facing `Missing`; provider omission can therefore
deny a valid name. Only authenticated `Active` is payable, and wallets must not
substitute a fallback address.

Unsupported schemas fail closed. Public chain-derived complete or exact state
may be deliberately discarded and replayed from authenticated history.
Account-private workflow, note locks, owned-name discovery, and recovery data
must never be silently discarded: they require an explicit migration or a
documented fail-closed recovery path.

## Consequences

- Ordinary spend detection and block-start lifecycle work use bounded indexed
  lookup instead of scanning all retained heads.
- SQLite index deletion can be detected and rebuilt transactionally from table
  rows; an index-only corruption is removed before integrity verification.
- The clone reducer and JSON snapshot remain supported for focused tests and
  small applications; transactional mode is an explicit host choice.
- “Complete local Names state” is the required term. It is not a global,
  trusted, remotely authoritative, or mandatory public directory.
- Performance numbers are qualification targets, not protocol validity rules.
  Misses require measurements, bottleneck analysis, and tracked follow-up, not
  silent target relaxation or automatic semantic failure.

## Rejected alternatives

- **Unique future-nullifier index:** adds a non-normative rejection rule;
  multiple accepted heads may share a nullifier and all must terminate when it
  is spent.
- **Persist mutable lifecycle labels:** risks disagreement with height-derived
  boundary rules. Expiry and optional terminal height remain authoritative.
- **One store with implicit partial coverage:** permits a partial cache to
  claim arbitrary `Missing`.
- **Trusted remote Names snapshots:** introduces a new state authority not
  committed by Zcash.
- **Silent private-state rebuild:** can lose custody and recovery information
  that canonical public replay cannot reconstruct by itself.
