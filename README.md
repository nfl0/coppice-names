# Coppice Names

Coppice Names is a native deterministic application for the generic
[Coppice runtime](../coppice/). It owns Names v1 identity, state, bonds, owner
authorization, wallet workflow, documentation, and normative vectors.

The protocol operations are frozen as `COMMIT`, `REVEAL`, `UPDATE`, and
`RELEASE`. The bare canonical label is protocol data; `.zec` is presentation
only. This repository does not redefine CPV1, CA01, canonical Zcash replay, or
Core rendezvous semantics.

```text
crates/coppice-names                 Names state machine and protocol
crates/coppice-names-librustzcash    Names wallet, bond, pending-intent, and protection helpers
docs/                                Names protocol and qualification material
test-vectors/                        Names normative vectors
```

The application uses Coppice's public `CoppiceApplication` contract and
`CoppiceRuntime` compositor. Its Core+Names snapshot wrapper remains a
Names-owned compatibility format around the generic Core and application
snapshots. Generic CompactBlock ingestion and host-authoritative canonical
reconciliation are imported from Coppice; this repository adds only
Names-specific wallet and policy reconciliation.

## License

Apache-2.0.
