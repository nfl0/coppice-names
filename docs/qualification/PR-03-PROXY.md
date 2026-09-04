# PR-03 transactional-state proxy qualification

Date: 2026-09-04

Evidence classification: internally measured Ryzen 7 5800X / 24 GiB host
proxy. This is not a mobile measurement, production load test, external audit,
or proof-verification benchmark.

Configuration:

- `coppice-names-sqlite` release profile;
- SQLite WAL, foreign keys, and `synchronous=FULL`;
- accepted authoritative head records in 10,000-record block deltas;
- explicit safe-prefix journal finalization;
- complete local coverage; and
- 1,000 warm exact primary-key lookups after a full native-index rebuild.

Commands and results:

```text
cargo run -p coppice-names-sqlite --release --example accepted_population -- /tmp/coppice-names-pr03-100k.sqlite 100000 100000
active=100000 historical=100000 bytes=50556928 population_seconds=2.784 index_rebuild_seconds=0.204 warm_lookups=1000 warm_lookup_seconds=0.007848 tip_height=10

target/release/examples/accepted_population /tmp/coppice-names-pr03-1m.sqlite 1000000 1000000
active=1000000 historical=1000000 bytes=489295872 population_seconds=37.478 index_rebuild_seconds=1.956 warm_lookups=1000 warm_lookup_seconds=0.008726 tip_height=100

target/release/examples/accepted_population /tmp/coppice-names-pr03-churn-100k.sqlite 10000 100000
active=10000 historical=100000 bytes=15667200 population_seconds=3.894 index_rebuild_seconds=0.015 warm_lookups=1000 warm_lookup_seconds=0.007358 tip_height=19
```

Interpretation:

- One million retained heads fit well below the 8 GiB qualification target in
  this reference schema (489,295,872 bytes after WAL checkpoint).
- Warm exact lookup stayed far below one second in this local proxy.
- After 90,000 distinct heads were inserted and compacted, retained database
  size followed the 10,000 live population plus SQLite free pages; canonical
  history was not retained as a dedicated Names feature.
- The numbers do not establish cold network latency, wallet-sync CPU overhead,
  exact/owned mobile evidence size, ten-million historical churn, action-dense
  block cost, COMMIT floods, expiry waves, crash recovery throughput, or
  multi-block reorganization latency. Those remain explicit qualification
  follow-ups. The targets are guidance rather than PR-03 semantic closure
  gates, but no unmeasured target is claimed as met.
