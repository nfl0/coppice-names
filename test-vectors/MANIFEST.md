# Coppice Names normative vector manifest

`replacement_protocol.json` is the canonical positive conformance artifact
for the current protocol. It freezes deployment, verifier-suite, name-route,
schedule, statement, proof, operation, and resolved-head values. Its vector-set
identity is
`a49da9d0dffee91e2b1c661e0d1af84a69cebd79b43e5b0951c9901f20bf0523`.
The enclosing file's SHA-256 digest is
`dba014744d35cbb83ceec4c38c5f83f0214a410dd4af4ce1c6da1dbea70939f7`.
The vector binds ruleset revision 1, ruleset fingerprint
`2954d670ecbac478b4f394eae6b696501e9bf8d242dcde63db6d00462f6f0c1f`,
deployment-preimage revision 1, and deployment ID
`db88a3cb0559d0428f17bf6ceef5222e713ee1129f2102b49cede7ce2e126df9`.

The Rust consumer and explicit generator live in
`crates/coppice-names/tests/replacement_protocol_vectors.rs`. The independent
Python consumer is `scripts/verify-replacement-vectors.py`. Ordinary test runs
only verify the checked-in artifact and never rewrite it.

## Semantic ruleset

`../ruleset/names-v2.json` is the normative RFC 8785 canonical JSON semantic
manifest. Its file SHA-256 digest is
`1c824eb979c1a348b78c41f5b0afed62c45e0f8e54c4c1f97fda0ed4bc3a9691`.
Its protocol fingerprint is BLAKE2b-256 over the canonical bytes with
personalization `CoppiceN2Rule`; that fingerprint, rather than this SHA-256
evidence digest, is included directly in the deployment preimage. Clause IDs
are permanent: retired IDs remain reserved and are never reassigned.

## Semantic history corpus

`semantic_histories.json` is the neutral, implementation-independent replay
corpus for reducer and exact-name resolver semantics. Its SHA-256 digest is
`36bcd9a617bcbbb4c428652580557332e9a3385c9ffe65f3cc0178b30548d6a4`.
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
clause-addressed operation decision, explicit terminal-head compaction and
ordinary-spend transition, current head and producer reference, lifecycle,
protocol identity, pending referenced COMMIT, rollback result, and final
full/exact resolution. The current canonical trace is 103,065 bytes and has
SHA-256 digest
`cc0d010727394fe7852b7cb295ecf8b74c33d0846e6ea2d556eabe6c760cd6e7`.

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
