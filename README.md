# Coppice Names

Coppice Names is the deterministic Names application for the generic
[Coppice runtime](https://github.com/nfl0/coppice/). It owns hidden-authority
bond lineages, COMMIT/REVEAL registration, REFRESH, canonical applicability,
and exact arbitrary-name resolution.

The protocol operations are `COMMIT`, `REVEAL`, and `REFRESH`; changing a
record and renewing its lease are deliberately the same operation. Explicit
release is an ordinary spend of the managed bond. The bare canonical label is
protocol data; `.zec` is presentation only. This repository does not redefine
CPV1, CA01, canonical Zcash replay, or Core rendezvous semantics.

```text
crates/coppice-names                 Names reducer, resolver, proofs, and wire
crates/coppice-names-wallet          Recoverable operation and V6 PCZT construction
test-vectors/                        Replacement protocol conformance artifact
```

The application uses Coppice's generic transport and canonical source
interfaces. Zcash consensus is the sole transaction and fork-choice authority;
Names ZK proves hidden-authority and exact bond-note relations, while the
canonical reducer and `ExactResolver` decide applicability and currentness.

## License

Apache-2.0.
