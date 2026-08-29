# Coppice Names

Coppice Names is the deterministic Names application for the generic
[Coppice runtime](../coppice/). It owns the Names state-note lineage,
COMMIT/REVEAL registration, local transition proofs, canonical applicability,
and fresh resolution.

The protocol operations are `COMMIT`, `REVEAL`, `UPDATE`, `RENEW`, and
`RELEASE`. The bare canonical label is protocol data; `.zec` is presentation
only. This repository does not redefine CPV1, CA01, canonical Zcash replay, or
Core rendezvous semantics.

```text
crates/coppice-names                 Names state machine, resolver, proofs, and wire
docs/                                Names protocol and qualification material
test-vectors/                        Names v1 normative wire vectors
```

The application uses Coppice's generic transport and canonical source
interfaces. Zcash consensus is the sole transaction and fork-choice authority;
Names ZK proves local transition validity, while `FreshResolver` and replay
decide canonical applicability and history.

## License

Apache-2.0.
