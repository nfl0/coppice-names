# ADR 0004: Claimable-head compaction and ruleset identity

Status: Accepted for undeployed Names

Date: 2026-09-04

## Context

The reducer retained the latest terminal head for every name indefinitely and
exposed a public `Claimable` lifecycle. Current state therefore grew with all
historical distinct names. The deployment identity bound parameters and
verifier identities, but did not bind the complete reducer semantics.

## Decision

Names remains undeployed and is revised in place without compatibility
behavior. A terminal head is retained through the half-open cooldown interval
`[terminal_height, terminal_height + cooldown_blocks)`. At block start at the
first height at or beyond that boundary, the reducer deletes the head before
evaluating transactions. Resolution is then `Missing`; `Claimable` is removed
from the public lifecycle. The first canonically ordered valid REVEAL in that
same block may register the name. A valid COMMIT may have been published during
cooldown if it is mature, unexpired, and otherwise eligible.

Compaction is journaled with the full prior head for bounded rollback. A reorg
within retained history restores it exactly. Recovery beyond retained history
requires replay from the user's archival canonical Zcash source. No permanent
tombstone or dedicated historical Names state is authoritative. Wallet-local
history may remain visible but cannot affect resolution or payment.

The canonical semantic manifest is `ruleset/names.json`. Its restricted
schema uses printable ASCII strings and unique non-reusable clause
IDs, and RFC 8785 canonical JSON. Personalized BLAKE2b-256 under
`CoppiceNmRule` produces the ruleset fingerprint. The deployment preimage keeps
the stable Names family identifier and binds the 32-byte fingerprint. The
resulting deployment ID is then included in the deployment-specific Coppice
ApplicationId. The ApplicationId therefore selects one exact immutable wire,
circuit, verifier, parameter, and reducer interpretation without a sequential
protocol version. Unknown deployment identities and old snapshots fail closed.

Names does not maintain an independent protocol-family revision or monotonic
ruleset revision. A future normative semantic, wire, circuit, authority, or
parameter change produces a different ruleset fingerprint or deployment ID
and therefore a different ApplicationId. Independently persisted local
snapshot and storage formats retain explicit schema identifiers because their
bytes require migration or rejection outside canonical replay. This follows
Core ADR 0001, `Content-addressed protocol identity`.

## Consequences

- Current authoritative head count is bounded by active and cooldown names,
  rather than all historical names.
- `Missing` intentionally does not distinguish never-used from formerly-used
  names. Historical investigation uses canonical Zcash history.
- Cooldown remains as a non-payable anti-impersonation quarantine.
- The deployment ID, public statements, proofs, vectors, and downstream
  configuration must be regenerated. Verifier keys remain only if their
  fingerprints are demonstrably unchanged.
- Exact resolution reports incomplete authenticated coverage as an error, not
  as a lifecycle state, and rejects historical-height queries unless a
  separate authenticated replay ends at that exact height.
- PR-03 remains responsible for indexed lifecycle work, COMMIT-spam scaling,
  transactional storage, and population benchmarks.

## Rejected alternatives

- **Retain `Claimable` heads forever:** preserves history in current state but
  leaves unbounded growth.
- **Permanent tombstones:** hides some payload bytes but remains proportional
  to historical distinct names.
- **Immediate Active-to-Missing transition:** reduces one boundary but removes
  the visible non-payable interval and enables seamless takeover after expiry
  or accidental release.
- **Trusted remote Names snapshots or mutable indexes:** weakens the canonical
  Zcash history trust model and can turn omission into false authority.
- **Sequential Names compatibility layer:** unnecessary before deployment and
  would preserve obsolete semantics and migration ambiguity.
