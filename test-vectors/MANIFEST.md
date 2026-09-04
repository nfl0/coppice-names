# Coppice Names normative vector manifest

`protocol.json` is the canonical positive conformance artifact
for the current protocol. It freezes deployment, verifier-suite, name-route,
schedule, statement, proof, operation, and resolved-head values. Its vector-set
identity is
`af2fc327d28d4afc2100434c63a63d93ddffbc90959963ff57fc393b36a290f9`.
The enclosing file's SHA-256 digest is
`656b57bad1a82da44dd33c975fbd3c7b0703bdc6ca0152d4ed2df4237f2882b6`.
The vector binds ruleset fingerprint
`03ba5032d5ea3ac2f4784d29a04abdaef1bd5560a98dd263f22450ee86544ab2`,
deployment ID
`6afc44d6773169fd5a4e787e9da8f33137defd245128db26357e352f2473f0ad`,
and deployment-specific ApplicationId
`09159f1cedd1b1a16175b7c344ea59dba9bcfdb4426168312b13b4018cf768af`.

The Rust consumer and explicit generator live in
`crates/coppice-names/tests/protocol_vectors.rs`. The independent
Python consumer is `scripts/verify-protocol-vectors.py`. Ordinary test runs
only verify the checked-in artifact and never rewrite it.

## Semantic ruleset

`../ruleset/names.json` is the normative RFC 8785 canonical JSON semantic
manifest. Its file SHA-256 digest is
`861e218c02e7146f67dea395466bebf3aacfa4a7481c7499e010bdb8b2868cd1`.
Its protocol fingerprint is BLAKE2b-256 over the canonical bytes with
personalization `CoppiceNmRule`; that fingerprint, rather than this SHA-256
evidence digest, is included directly in the deployment preimage. Clause IDs
are permanent: retired IDs remain reserved and are never reassigned.

## Semantic history corpus

`semantic_histories.json` is the neutral, implementation-independent replay
corpus for reducer and exact-name resolver semantics. Its SHA-256 digest is
`9fc6ed37e21388a159c9eb3e1ece1133c317ff03dd1999e008ce2f6234885795`.
The corpus is not a deployment-identity input. It is deterministic agreement
evidence and can grow without changing deployed protocol bytes.

The top-level format identifier is
`coppice-names-semantic-history`. Each case fixes:

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
emit canonical `coppice-names-semantic-trace` JSON containing every
clause-addressed operation decision, explicit terminal-head compaction and
ordinary-spend transition, current head and producer reference, lifecycle,
protocol identity, pending referenced COMMIT, rollback result, and final
full/exact resolution. The current canonical trace is 102,066 bytes and has
SHA-256 digest
`3bba539c2bca34d4047a72a1a729c1629141678e25d5916aff7f6d6270d32ffe`.

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
