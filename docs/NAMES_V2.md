# Coppice Names v2 production reference

This document describes the implemented, qualified, and frozen Names v2
production path from the actual code. It supersedes the design-time notes in
[`NAMES_V2_EXPERIMENTAL.md`](NAMES_V2_EXPERIMENTAL.md) where they disagree
with the implementation; that document remains as design history. Normative
bytes are frozen in [`../test-vectors/names_v2_wire.json`](../test-vectors/names_v2_wire.json)
and asserted by `crates/coppice-names/tests/names_v2_wire_vectors.rs`. The
frozen v1 protocol, its vectors, and its BondProof identity are unchanged.

Status: this code path is qualified locally against the pinned Zakura/Zaino
stack. It is not a public deployment and has no independent security audit.

## 1. Authority and layering

Zcash remains the only consensus and fork-choice authority. Coppice Core
(`coppice`, `coppice-librustzcash`) stays application-blind and proof-system
agnostic: it owns identities, CPV1/CA01 transport, canonical acquisition,
replay, rewind, persistence, and host reconciliation, and never imports a
name, lease, release, state note, or policy parameter. `coppice-names` owns
Names state, lineage, scheduling, lease lifecycle, replacement, abandonment,
reset eligibility, proof semantics, and resolution. `orchard-coppice`
(see its `COPPICE_PATCH.md`) supplies only the non-consensus proof support:
the state-note binding circuits and the designated Ironwood action pairing.

Registration is always two operations: `COMMIT` then `REVEAL`. There is no
`REGISTER` and no `TRANSFER` in v2. Transfer is planned for v3; see
[§13](#13-roadmap-planned-v3-transfer-and-marketplace).

Physical invariant: the designated Names spend and the designated successor
state output occupy the same Ironwood action, whose nullifier is the Names
input nullifier and whose commitment is the successor commitment. Carrier,
funding, and change effects occupy other actions. The designated action index
is finalized before CNV2 encoding (the operation commits to it) and cannot be
reassigned by any later builder stage.

## 2. Frozen protocol surfaces

The v2 operation family is exactly `COMMIT`, `REVEAL`, `UPDATE`, `RENEW`,
`RELEASE`. Wire encoding is `CNV2 || 0x01 || canonical postcard` of one
operation; the decoder re-encodes and compares bytes, rejecting every
non-canonical encoding, and the prefix is disjoint from frozen v1. CPV1
framing is the unchanged generic transport: one distinct rendezvous output
per frame, 16,093-byte maximum payload.

- `StateData` fields: `name_id`, `owner_pk` (canonical Ironwood `ak`
  encoding), `sequence` (u64), `record` (bounded by `MAX_RECORD_BYTES`),
  `lease_expiry` (exclusive u32), `status` (`Active`/`Released` code),
  `terminal_height` (u32, zero while active).
- `StateRef` fields: producer height, transaction index, transaction ID,
  producer action index, producer operation index, state-note commitment,
  proof-authenticated future nullifier of the state note. A successor's
  producer position is assigned by the chain after mining and is bound by
  neither the proofs nor the wire format; a REVEAL's `CommitRef` and a
  transition's predecessor `StateRef` must already be canonical and are bound
  into the operation and its proof.
- `replacement_predecessor` encoding: `Option<StateRef>`. `None` is the
  first-registration and the bounded-history no-predecessor reset encoding
  (one canonical encoding; see the frozen `reveal_no_predecessor_reset_shaped`
  vector). `Some(exact prior terminal head)` is the explicit replacement
  path. Whether a `None` reset is canonically eligible is a state-machine and
  canonical-replay semantic check; constructors and wallets never decide it.
- State digest: `CoppiceN2State` domain over canonical state fields plus the
  note commitment; the genesis proof commits it, and transition proofs commit
  both predecessor and successor digests.
- COMMIT commitment: `CoppiceN2Com` domain over version, name id, owner,
  record digest, record length, and fresh secret, via
  `RegistrationIntent::commitment()`. The formula lives only in
  `coppice-names`; no wallet or harness duplicates it.
- Operation tags: `Commit` (no action), `Reveal` (genesis), and
  `Update`/`Renew`/`Release` (transition codes 1/2/3 in the circuit).
- Schedule, lease, claimability, reset-horizon, and abandonment rules are the
  qualified ones in `coppice-names::v2::{lease, schedule}` and
  `v2::machine`: exactly one deterministic anchor per epoch; REVEAL/RENEW
  only at the anchor; lease extension only by renewal at a scheduled slot;
  expired claimability at `lease_expiry + grace`; released claimability at
  `terminal_height + reuse_delay`; abandoned claimability at
  `min(spend_height + reuse_delay, lease_expiry + grace)`; reset horizon
  `H = max(D + G, D - 1 + R)` evaluated at the COMMIT's own height.

Frozen vector-set identity (SHA-256 over the length-prefixed canonical
envelopes in family order):
`0c9bfdd7b0a26fb5c645b356f418d97fb48c7d910e2d1ce0e8d18c3e7f2cb7d5`.

## 3. Proof boundaries and circuit freeze

The genesis public inputs are: name id, owner `ak`, successor commitment,
sequence, record digest, lease expiry, status, terminal height, state digest,
registration-input nullifier, successor future nullifier, and minimum bond.
The transition public inputs are: name and owner, predecessor commitment and
action nullifier, successor commitment, operation code, both sequences, both
record digests, both lease expiries, both statuses, both terminal heights,
operation height, both state digests, the predecessor `StateRef` digest, the
transition binding, and the successor future nullifier. Both circuits prove
the successor recipient derives from the predecessor's full-viewing-key
authority and `rho_successor = nullifier_predecessor`; the transition circuit
additionally proves exact value preservation. The actual Ironwood spend
authority remains the ordinary Zcash proof.

The circuits live in `orchard-coppice` under the `experimental-state-note`
feature and are derived deterministically from the pinned params (`K = 11`)
and pinned Halo2 `0.3.2`. Verifying-key identities are frozen and asserted by
the fork's own test:

- transition VK ID: `676e9883651309ad75e73ff937d3f046cfe966c18079371f80d3f91ded4baf17`
- genesis VK ID: `a9cfe4bf4c9ff3abeebb41c348e4189f5ec5649f16296c04f573f3d97de952fc`

Any change to the circuits, their public-input layout, or the pinned Halo2
version changes these IDs and requires an explicit protocol-version bump.
Proving keys are derived at runtime from the same pinned derivation; no
trusted parameter distribution exists or is needed.

## 4. Wallet construction flow

The reusable production construction layer is
`zcash-devtool::names_v2_operation` over the low-level designated-pair PCZT
builder `zcash-devtool::names_v2_builder`. A wallet host drives:

1. `prepare_commit(&RegistrationIntent)` — canonical pre-broadcast COMMIT
   transport. It intentionally exposes no producer position: the canonical
   `CommitRef` exists only after the COMMIT transaction is canonically
   included, and the host discovers it by replay.
2. `prepare_reveal(RevealInputs, V2Parameters)` /
   `prepare_update` / `prepare_renew` / `prepare_release(TransitionInputs)`
   — binds the intent↔COMMIT commitment, the exact canonical references, the
   exact successor note (rho = spent nullifier, value preserved, recipient
   derived from the owner key at the supplied scope), the authoritative
   lease/schedule values, and the statement plus witness. Failures here are
   local typed-binding failures (wrong intent/COMMIT pairing, mismatched
   predecessor note, inactive or expired predecessor, non-scheduled RENEW
   height, unchanged UPDATE record).
3. Host proving with `OrchardV2ProofProver` under the host RNG, then
   `finalize(proof)` — the complete proof-carrying operation, CNV2 bytes,
   CPV1 frames, footprint, and the exact successor note opening.
4. `planned_state_operation_shape_and_fee` then `plan_state_operation` — the
   designated-pair Ironwood plan. Funding is fully general
   (`OperationFunding`: zero or more funding spends, zero or more change
   outputs); carriers are parameterized (`CarrierPlan`); the successor output
   transport is explicit (`SuccessorTransport`). Planning fails closed unless
   the supplied funding contributes exactly the ZIP-317 fee after paying
   carriers and change, so underfunded and overfunding shapes are rejected
   before any proving.
5. The existing PCZT pipeline: `build_names_v2_bundle`, `build_names_v2_pczt`,
   `finalize_names_v2_pczt_io`, `install_names_v2_ironwood_witnesses` (witness
   plan resolved by nullifier), `prove_names_v2_ironwood_pczt`,
   `sign_names_v2_ironwood_pczt`, `extract_names_v2_transaction`, then host
   broadcast.

Outgoing recovery and memos are explicit wallet decisions. The empty memo is
the canonical Orchard default and carries no Names semantics. A wallet that
must later spend a state note from a restored database should supply its own
outgoing viewing key in `SuccessorTransport` (and in its change outputs) so
the exact note opening remains recoverable from the chain; the construction
layer never silently applies qualification defaults. Qualification defaults
(one funding note, one-zatoshi carriers, no outgoing ciphertexts) live only
in the disposable live harness.

State-note retention: `FinalizedOperation::successor_note()` is the exact
opening of the created state note. The wallet host must persist it (or be
able to recover it from the outgoing ciphertext via its OVK) together with
its scope, the predecessor relation, and the canonical `StateRef` once mined.
No parallel secret store is created; the ordinary wallet database represents
this information, exactly as the qualified v1 adapter retains bond notes.

## 5. Resolution

`coppice-names::v2::FreshResolver` is the application-facing resolution API.
Given the name and the canonical blocks, it returns `ResolutionResult`:
`status` (`Active`, `Stale`, `Grace`, `Released`, `Abandoned`, `Expired`,
`Missing`), the accepted `NameState` (`data` record/owner/sequence/lease/
status/terminal plus `commitment` and canonical `state_ref`), the discovery
anchor when genuinely useful, and bounded replay stats. `V2StateMachine`
full replay remains the independent authority; production callers treat
resolver/replay disagreement as a host error. `CanonicalBlock::
from_application_context` is the adapter from generic Core transaction
contexts; Core never interprets Names payload bytes.

## 6. Persistence and caching model

There is no v2-specific cache and no trusted snapshot. Canonical chain data
remains authoritative; everything local is re-derivable. Startup and per-name
lookups are bounded by the qualified FreshResolver discovery window; full
state-machine state is reconstructed by replay from the activation height.
The only persisted acceleration is the generic Coppice runtime
snapshot/rewind machinery (independently validated Core/application layers,
retention-horizon rewind, rebuild-from-activation beyond retention), which is
owned by Core and the composed runtime and never trusts stale cached state.
Restart behavior, reorg rewind, and beyond-retention rebuild are covered by
the qualified runtime facilities and the deterministic Phase 6 companion.

## 7. Zallet integration boundary

Zallet remains external and unmodified in this release, pinned at
`f904040613d6b2c3f24ab58cfef1b555bf68e918` (upstream `zcash/zallet`
`v0.1.0-beta.3`). Its JSON-RPC and internal wallet pipeline are pre-stable
and provide no application-extension surface, so binding Names v2 into it
would require inventing Zallet APIs and redesigning its wallet path — that is
a deliberate future integration decision, not part of this release. The
documented host contract for any future wallet host (Zallet included) is
exactly the construction flow in section 4 plus: canonical source acquisition
(generic `coppice-librustzcash`), wallet-database retention of state-note
openings, OVK/memo policy, funding selection, and canonical replay for
accepted references.

## 8. Security review results

The qualified machine's adversarial properties were re-verified during this
release pass: transaction-local structural first-claim reservation of action
indices (later messages naming a claimed index are rejected even if the
first is semantically invalid); operation-atomic semantic rejection that
never consumes pending COMMITs or indices; duplicate-COMMIT rejection;
canonical transaction/operation/action ordering enforcement; stale-
predecessor and shadow-lineage exclusion via exact `StateRef` references and
one-time nullifiers; checked arithmetic throughout lease, schedule, sequence,
and height boundaries; CNV2 canonical re-encode equality and CPV1-bounded
payloads (no unbounded decode); abandonment from ordinary canonical nullifier
effects including the claimability floor.

One concrete construction bug was found and fixed during this release work:
the funding-balance check initially ignored the successor output, which
returns the designated bond value intact (the value-preservation invariant),
and therefore mis-counted the fee contribution. Planning now subtracts the
successor output and fails closed on unbalanced funding, with regression
coverage including the zero-funding failure case.

## 9. Performance notes

Measured on the development machine used for qualification: the routine
(cheap) test suites run in seconds; the full coppice-names suite including
heavy v1 proof tests completes in a few minutes. The Names v2 genesis and
transition proofs measured during live qualification produce 4,640-byte
proofs; per-operation proving dominates construction time. Ironwood
consensus proof generation per transaction is the other dominant cost.
FreshResolver cost is bounded by the discovery window: only the name's
visible operations in the bounded anchor tail are replayed, and only
scheduled anchor blocks are probed for reset eligibility; no global index or
lookup RPC is required. No trusted provider is introduced to improve any of
these costs.

## 10. Consensus-version handling

The production construction layer is parameterized over `Parameters` for fee
and shape planning and targets the `BranchId::Nu6_3` V6/Ironwood consensus
branch explicitly at PCZT creation, with a documented gate in
`names_v2_builder`. Ironwood is the NU6.3-era shielded pool; until upstream
dependencies define a successor branch and transaction version for Ironwood
transactions, that gate is the explicit current-support boundary rather than a
hidden assumption. No speculative NU7 behavior exists in the code.

## 11. Test organization

Routine CI runs only cheap deterministic tests: construction, wire vectors
(conformance only), funding/accounting, machine/resolver semantics with
synthetic blocks, and the existing v1 suites. Heavy work is opt-in:

- `cargo test -- --ignored` runs the proof-generating unit tests (real
  Names genesis proof and real Ironwood consensus proof fixtures).
- `scripts/live-qualification.sh` drives the real Zakura → Zaino →
  zcash-devtool stack; its disposable v2 phases build and mine live
  operations and verify canonical acceptance. Phase 6 reorgan coverage is
  deterministic and does not launch the stack.

The qualified v1 tooling and the `names-v2-live` harness are retained as
release-regression tooling; construction logic is not duplicated between
them and the library.

## 12. Release qualification

The final release qualification record, transaction IDs, and artifact hashes
are maintained in [`QUALIFICATION.md`](QUALIFICATION.md) and the repository
release records. Qualification demonstrates the production construction path
end to end on the pinned stack; it is local evidence, not an audit or a
deployment guarantee.

## 13. Roadmap: planned v3 transfer and marketplace

This section is a roadmap note, not a specification: nothing here is
implemented, frozen, or qualified, and no v3 wire layout, circuit public
input, marketplace offer format, payment mechanic, or transfer cryptography
is fixed here.

Names v2 deliberately ships without a `TRANSFER` operation. **TRANSFER is
planned for v3**, together with a **Names marketplace** built around transfer
with atomic Zcash settlement: offers and payment are expected to settle
through ordinary Zcash transactions/PCZTs rather than any separate consensus
or fork-choice system. Zcash remains the sole consensus and fork-choice
authority.

The intended compatibility model is continuation of the existing per-name
state-note lineage. An existing canonical v2 `NameState` remains the
registered name, and a future v3 operation should be able to consume that
existing canonical state head directly. There is no global state migration,
no migration transaction merely for upgrading, no `RELEASE` + `COMMIT` +
`REVEAL` cycle, and no requirement for existing owners to re-register their
names. Conceptually the desired evolution is:

```text
... -> UPDATE_v2 -> RENEW_v2 -> TRANSFER_v3 -> UPDATE_v3 -> ...
```

The name identity and lineage survive protocol-version upgrades: protocol
version belongs to the operation and proof advancing the lineage, not to
whether the name still exists. A v3 transfer is expected to change ownership
while preserving the same `name_id` and continuing the sequence and state
lineage.
