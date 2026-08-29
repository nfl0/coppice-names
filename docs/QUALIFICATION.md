# Names v1 qualification record

This record is the reset handoff for Names v1. The prior corrected-v2 live run
is historical evidence only; v1 artifact regeneration and live qualification
remain pending. Any eventual run is local evidence only, not a public-network
deployment or an independent security audit.

The qualification path is `zcash-devtool/scripts/live-qualification.sh
--phase 2`. It drives the pinned Zakura -> Zaino -> `zcash-devtool` stack and
checks canonical `COMMIT -> REVEAL -> UPDATE -> RENEW -> RELEASE` acceptance.
Each operation is independently checked by full replay and `FreshResolver`.
The run also checks the exact `Released`/`Expired` claimability boundary.

Reset artifact status:

- CNV1 revision: `0x01`
- wire-vector identity:
  `dff01501326305709dc1eda3241a92458ce17a3461b6dd254c7f8f841a6932b1`
- state-note transition VK identity: pending v1 freeze
- state-note genesis VK identity: pending v1 freeze
- Orchard source pin: `5588c4e42d7158233a50471c04340ea58615bb0e`

Proof-size and performance optimization remain separate post-qualification
work. Final wire/VK regeneration and live qualification must be rerun if any
normative circuit, wire, or protocol-version input changes.
