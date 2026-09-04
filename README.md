# Coppice Names

Coppice Names is the deterministic Names application for the generic
[Coppice runtime](https://github.com/nfl0/coppice/). It owns hidden-authority
bond lineages, COMMIT/REVEAL registration, REFRESH, canonical applicability,
and exact arbitrary-name resolution.

The protocol operations are `COMMIT`, `REVEAL`, and `REFRESH`; changing a
record and renewing its lease are deliberately the same operation. Explicit
release is an ordinary spend of the managed bond. The bare canonical label is
protocol data; `.zec` is presentation only. This repository does not redefine
Coppice Core's content-addressed carrier, application envelope, canonical
Zcash replay, or rendezvous semantics.

```text
crates/coppice-names                 Names reducer, resolver, proofs, and wire
crates/coppice-names-sqlite          Transactional indexed state and wallet adapter
crates/coppice-names-wallet          Recoverable operation and V6 PCZT construction
ruleset/names.json                   Canonical semantic ruleset identity
test-vectors/                        Protocol conformance artifact
```

The application uses Coppice's generic transport and canonical source
interfaces. Zcash consensus is the sole transaction and fork-choice authority;
Names ZK proves hidden-authority and exact bond-note relations, while the
canonical reducer and `ExactResolver` decide applicability and currentness.
Exact resolution discovers REVEALs in the requested name's deterministic
windows and then authenticates only the historical COMMIT named by the
REVEAL's bounded `CommitRef`; it does not continuously download unrelated
generic-rendezvous traffic.

The draft whitepaper is available as
[PDF](docs/WHITEPAPER.pdf) and [LaTeX](docs/WHITEPAPER.tex). It explains the
design, security model, privacy properties, and preliminary performance
evidence. A worked end-to-end lifecycle example is in
[`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md). The current normative protocol
is documented in
[`docs/SPECIFICATION.md`](docs/SPECIFICATION.md). The checked-in conformance
artifact and its independent consumers are described in
[`test-vectors/MANIFEST.md`](test-vectors/MANIFEST.md). The claimable-head
compaction and ruleset-identity decision is recorded in
[`docs/decisions/0004-claimable-compaction-and-ruleset-identity.md`](docs/decisions/0004-claimable-compaction-and-ruleset-identity.md).

## License

Apache-2.0.
