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
