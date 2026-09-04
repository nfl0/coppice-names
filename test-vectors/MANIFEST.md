# Coppice Names normative vector manifest

`replacement_protocol.json` is the canonical positive conformance artifact
for the current protocol. It freezes deployment, verifier-suite, name-route,
schedule, statement, proof, operation, and resolved-head values. Its vector-set
identity is
`334b2694ddb808bdfb859dc3dc45ddb93ce3467285e1447b921990b529491a80`.

The Rust consumer and explicit generator live in
`crates/coppice-names/tests/replacement_protocol_vectors.rs`. The independent
Python consumer is `scripts/verify-replacement-vectors.py`. Ordinary test runs
only verify the checked-in artifact and never rewrite it.

## Semantic history corpus

`semantic_histories.json` is the neutral, implementation-independent replay
corpus for reducer and exact-name resolver semantics. Its SHA-256 digest is
`a7ec6a5d4ef9caf4732b361ba2b566037d9eda2e91cb4939076b69a81b4ae067`.
The corpus is not a deployment-identity input. It is deterministic agreement
evidence and can grow without changing deployed protocol bytes.

The top-level format identifier is
`coppice-names-semantic-history-v1`. Each case fixes:

- the deployment schedule and activation-parent hash;
- names whose full and exact resolutions must agree;
- canonical block steps, authenticated action effects, decoded operations,
  and referenced historical COMMIT evidence;
- explicit proof verdicts (`proof_valid`), which stand in for cryptographic
  verification at this semantic boundary;
- deterministic empty-block ranges, branch identifiers, and rollback
  instructions.

For compactness, a block's 32-byte test hash is defined as 28 repetitions of
`branch_byte` followed by the block height as a four-byte big-endian integer.
`advance_empty` expands every height in the inclusive range; it never skips a
canonical height. A missing `prev_hash_hex` means the current canonical tip.
An explicit value is used to exercise wrong-parent rejection.
Field elements may be expressed as a small nonnegative JSON integer or as a
32-byte little-endian hex string; both consumers validate and normalize them
to canonical Pallas encodings in the trace.

The standard-library-only Python checker is
`scripts/verify-semantic-histories.py`. It was authored from
`docs/SPECIFICATION.md` and implements its own schedule, reducer, exact-name
filter, lifecycle, referenced-COMMIT, and rollback logic. It neither imports
nor invokes the Rust crate. Canonical UA parsing and cryptographic proof
verification occur before this semantic boundary and remain covered by their
dedicated conformance suites.

The Rust trace consumer is the `names-semantic-trace` binary. Both consumers
emit canonical `coppice-names-semantic-trace-v1` JSON containing every
operation decision, accepted transition class, current head and producer
reference, lifecycle, pending referenced COMMIT, rollback result, and final
full/exact resolution. The current canonical trace is 76,639 bytes and has
SHA-256 digest
`d89a9abaee479efe3b416f78cdd0b6ca3762d70e08e609fb04fdb20be87641d8`.

Run the focused exact-agreement suite with:

```sh
cargo test -p coppice-names --test semantic_history_agreement --no-fail-fast
```

Run either consumer directly with:

```sh
python3 scripts/verify-semantic-histories.py
cargo run -q -p coppice-names --bin names-semantic-trace -- test-vectors/semantic_histories.json
```

The focused corpus covers proof rejection, first-valid competition,
ordinary-bond-spend termination, expiry and cooldown boundaries, replacement,
stale and valid refreshes, referenced-COMMIT admission and conflict rejection,
canonical position errors, wrong height and parent errors, fork rollback,
reapply, COMMIT maturity/TTL endpoints, operation-window endpoints, and
full/exact filtering parity. Large seeded randomized histories remain a manual
architecture qualification gate and are not claimed by this focused suite.
