# Coppice Names production reference

This document describes the current Zakura-backed Names v1 production path
from the actual code. Normative bytes are frozen in
[`../test-vectors/names_v1_wire.json`](../test-vectors/names_v1_wire.json) and
asserted by `crates/coppice-names/tests/names_v1_wire_vectors.rs`.

Status: the current Zakura-backed source has regenerated and frozen the CNV1
vectors and state-note VK identities, and the complete lifecycle passed live
local-regtest qualification. The coordinated release tag is
`names-v1.0.1`; the historical `names-v1.0.0` tag remains unchanged. This is
not a public deployment and not an independent security audit.

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
`REGISTER` and no `TRANSFER` in v1. Transfer is planned for v2; see
[§13](#13-roadmap-planned-v2-transfer-and-marketplace).

Physical invariant: the designated Names spend and the designated successor
state output occupy the same Ironwood action, whose nullifier is the Names
input nullifier and whose commitment is the successor commitment. Carrier,
funding, and change effects occupy other actions. The designated action index
is finalized before CNV1 encoding (the operation commits to it) and cannot be
reassigned by any later builder stage.

## 2. Frozen protocol surfaces

The v1 operation family is exactly `COMMIT`, `REVEAL`, `UPDATE`, `RENEW`,
`RELEASE`. The v1 wire encoding is `CNV1 || 0x01 || canonical
postcard` of one operation; the decoder re-encodes and compares bytes,
rejecting every non-canonical encoding. CPV1
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
- State digest: the `N1STATE` Poseidon domain field
  (`0x004e_3153_5441_5445`) over canonical state fields plus the note
  commitment; the genesis proof commits it, and transition proofs commit both
  predecessor and successor digests.
- COMMIT commitment: `CoppiceN1Com` domain over version, name id, owner,
  record digest, record length, and fresh secret, via
  `RegistrationIntent::commitment()`. The formula lives only in
  `coppice-names`; no wallet or harness duplicates it.
- Operation tags: `Commit` (no action), `Reveal` (genesis), and
  `Update`/`Renew`/`Release` (transition codes 1/2/3 in the circuit).
- Lease, claimability, reset-horizon, and abandonment rules are the qualified
  ones in `coppice-names::v1::{lease, schedule}` and `v1::machine`.
  REVEAL declares a lease-start/proof height strictly after the canonical
  COMMIT height and no later than the inclusive COMMIT TTL; the REVEAL
  transaction may be canonically included later, provided that declared
  height remains within that window. RENEW declares a height in the
  predecessor's renewal window (`renewal_opening <= height < lease_expiry`)
  and may likewise be included later, but before the predecessor's exclusive
  lease expiry. Exact name-derived scheduling is not a validity rule. The
  transaction expiry used for each operation must cover its declaration and
  canonical-inclusion window. Expired claimability remains at
  `lease_expiry + grace`; released claimability at `terminal_height +
  reuse_delay`; abandoned claimability at
  `min(spend_height + reuse_delay, lease_expiry + grace)`; reset horizon
  `H = max(D + G, D - 1 + R)` is evaluated at the COMMIT's own height.
  Proofs enforce the local declaration and lease predicates; runtime/replay
  enforces canonical history and applicability (claimability, reset,
  abandonment, and the inclusion bounds).

The reset invalidates the former CNV2 vector identity. The final CNV1 vector-set
identity (SHA-256 over length-prefixed canonical envelopes in family order) is
`dff01501326305709dc1eda3241a92458ce17a3461b6dd254c7f8f841a6932b1`.
The checked-in vector file SHA-256 is
`0aeb8795386c47f235375a648b0a3c512e75c8f3d9a5b40ae8c224d0807ef40a`.

## 3. Proof boundaries and circuit freeze

The responsibility split is: Zcash consensus proves Ironwood Action validity,
canonical ordering, and fork choice; Names ZK proves complete local Names
transition validity under authenticated canonical inputs; the Names
runtime/replay owns canonical applicability and history only (current head,
accepted predecessor, COMMIT history, claimability/replacement, abandonment,
competing spends, reorgs). "Proof-valid" therefore means a valid local Names
transition from the stated predecessor under correctly derived canonical
public inputs — never that the predecessor is currently canonical, and never a
re-derivation of Ironwood spend authority, which the ordinary Zcash proof
already establishes.

The genesis public inputs are: name id, owner `ak`, successor commitment,
sequence, record digest, lease expiry, status, terminal height, state digest,
registration-input nullifier, successor future nullifier, minimum bond, the
disclosed intent's name id, owner `ak`, and record digest, the declared REVEAL
lease-start/proof height, the protocol lease duration, and the lease
predicate. The transition public inputs are: name and owner, predecessor
commitment and action nullifier, successor commitment, operation code, both
sequences, both record digests, both lease expiries, both statuses, both
terminal heights, operation height, both state digests, the predecessor
`StateRef` digest, the transition binding, the successor future nullifier, the
successor name id and owner key, the protocol lease duration, the renewal
window predicate, and the predecessor head's proof-authenticated future
nullifier.

Both circuits prove the successor recipient derives from the predecessor's
full-viewing-key authority and `rho_successor = nullifier_predecessor`; the
transition circuit additionally proves exact hidden bond-value preservation
from the predecessor note opening, which is retained in the witness solely for
that relation. UPDATE/RENEW/RELEASE local legality, REVEAL/genesis formation,
name/owner continuity, sequence increments, and the lease-window predicates are
enforced by the circuits, not by runtime validation. The runtime authenticates
the canonical action facts before proof verification (exact accepted
predecessor, successor commitment, and action nullifier equal to the head's
proof-authenticated future nullifier); a canonical spend whose Names successor
fails verification becomes abandonment. The lease-window predicate and lease
duration are canonical deterministic statement preprocessing derived by the
runtime from the declared operation height and the protocol parameters; exact
name-derived scheduling is not a validity rule.

The circuits live in the `state-note` feature of the `zakura-port` branch of
`orchard-coppice` and are derived deterministically from the pinned params
(`K = 11`) and current Zakura Halo2 packages. The regenerated and frozen
transition VK identity is
`5ed1a1385f15e0e13e284cf1a7c319449d42b4902abc57b5ebefb60d04995cc1`; the
regenerated and frozen genesis VK identity is
`81aa1ade09b0ca86eb80c021a66e2cf629875ecab258a99a4a2ecd0df2c7f5ae`.
Proving keys are derived at runtime from the same pinned derivation; no
trusted parameter distribution exists or is needed. The semantic Names
registration preimage version is `1`; CNV1 `0x01` rejects the superseded CNV2
`0x02` envelopes.

## 4. Wallet construction flow

The reusable production construction layer is
`zcash-devtool::names_v1_operation` over the low-level designated-pair PCZT
builder `zcash-devtool::names_v1_builder`. A wallet host drives:

1. `prepare_commit(&RegistrationIntent)` — canonical pre-broadcast COMMIT
   transport. It intentionally exposes no producer position: the canonical
   `CommitRef` exists only after the COMMIT transaction is canonically
   included, and the host discovers it by replay.
2. `prepare_reveal(RevealInputs, V1Parameters)` /
   `prepare_update` / `prepare_renew` / `prepare_release(TransitionInputs)`
   — binds the intent↔COMMIT commitment, the exact canonical references, the
   exact successor note (rho = spent nullifier, value preserved, recipient
   derived from the owner key at the supplied scope), the authoritative lease
   values, and the statement plus witness. Failures here are local typed-binding
   failures (wrong intent/COMMIT pairing, mismatched predecessor note, inactive
   or expired predecessor, declaration outside its validity window, unchanged
   UPDATE record).
3. Host proving with `OrchardV1ProofProver` under the host RNG, then
   `finalize(proof)` — the complete proof-carrying operation, CNV1 bytes,
   CPV1 frames, footprint, and the exact successor note opening.
4. `planned_state_operation_shape_and_fee` then `plan_state_operation` — the
   designated-pair Ironwood plan. Funding is fully general
   (`OperationFunding`: zero or more funding spends, zero or more change
   outputs); carriers are parameterized (`CarrierPlan`); the successor output
   transport is explicit (`SuccessorTransport`). Planning fails closed unless
   the supplied funding contributes exactly the ZIP-317 fee after paying
   carriers and change, so underfunded and overfunding shapes are rejected
   before any proving.
5. The existing PCZT pipeline: `build_names_v1_bundle`, `build_names_v1_pczt`,
   `finalize_names_v1_pczt_io`, `install_names_v1_ironwood_witnesses` (witness
   plan resolved by nullifier), `prove_names_v1_ironwood_pczt`,
   `sign_names_v1_ironwood_pczt`, `extract_names_v1_transaction`, then host
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
this information together with the state-note opening and its canonical
producer reference.

## 5. Resolution

`coppice-names::v1::FreshResolver` is the application-facing resolution API.
Given the name and the canonical blocks, it returns `ResolutionResult`:
`status` (`Active`, `Stale`, `Grace`, `Released`, `Abandoned`, `Expired`,
`Missing`), the accepted `NameState` (`data` record/owner/sequence/lease/
status/terminal plus `commitment` and canonical `state_ref`), the discovery
anchor when genuinely useful, and bounded replay stats. `V1StateMachine`
full replay remains the independent authority; production callers treat
resolver/replay disagreement as a host error. `CanonicalBlock::
from_application_context` is the adapter from generic Core transaction
contexts; Core never interprets Names payload bytes.

`NamesApplication<P>` is the thin `CoppiceApplication` adapter for hosting the
same machine in `CoppiceRuntime`. It advances position-only through blocks
before the Names activation height, converts active Core contexts through
`CanonicalBlock::from_application_context`, and stages the existing machine
atomically. The verifier is held behind `Arc` so Core's clone-before-apply
boundary does not require a proof-system-specific `Clone` implementation.
Wallet hosts construct it at the Core tip (or the authenticated activation
parent), and use `bootstrap_canonical_chain_with_progress` for a complete
directory bootstrap. No wallet funding, note selection, key storage, or
proving policy is hidden in this adapter.
Its `resolve_fresh` convenience method only delegates to the existing bounded
`FreshResolver` against a host-supplied canonical source; it is not a directory
index or a replacement for full replay.
For persistence, `from_snapshot` checks local payload/envelope consistency;
`from_snapshot_at_runtime` additionally takes the host's actual Core runtime
activation height and enforces the common rewind boundary before composition.
A checkpoint is never canonical evidence.

## 6. Persistence and caching model

There is no v1-specific canonical cache or remote/trusted snapshot. Canonical
chain data remains authoritative; everything local is re-derivable. Startup
and per-name lookups are bounded by the qualified FreshResolver discovery
window; full state-machine state is reconstructed by replay from the
activation height. `NamesApplication` exposes an application-owned checkpoint
payload and common `ApplicationSnapshot` metadata for local wallet persistence.
The payload contains the current machine and deliberately omits its in-memory
undo journal, so a restored checkpoint advertises only its current tip as a
rewind boundary. If a reorg reaches before that boundary, the host rebuilds
the Names application from the authenticated activation checkpoint; it never
uses the checkpoint as proof of canonical applicability. Generic Core and
application snapshots remain independently validated and persisted by the
host.

For wallet records that should resolve directly to a shielded Unified Address,
`PaymentRecord` provides the optional `N1UA` profile. It fixes a network
discriminant, canonical Unified Address encoding, and a known Sapling or
Orchard receiver; transparent, wrong-network, non-canonical, malformed, and
oversized records are rejected. The profile is application-level and does not
make Core an address parser. Other bounded record formats remain valid Names
application data.

## 7. Zallet integration boundary

Zallet remains external and unmodified in this release, pinned at
`f904040613d6b2c3f24ab58cfef1b555bf68e918` (upstream `zcash/zallet`
`v0.1.0-beta.3`). Its JSON-RPC and internal wallet pipeline are pre-stable
and provide no application-extension surface, so binding Names v1 into it
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
and height boundaries; CNV1 canonical re-encode equality and CPV1-bounded
payloads (no unbounded decode); abandonment from ordinary canonical nullifier
effects including the claimability floor.

One concrete construction bug was found and fixed during this release work:
the funding-balance check initially ignored the successor output, which
returns the designated bond value intact (the value-preservation invariant),
and therefore mis-counted the fee contribution. Planning now subtracts the
successor output and fails closed on unbalanced funding, with regression
coverage including the zero-funding failure case.

## 9. Performance notes

The live release qualification recorded the current unoptimized proving and
Ironwood consensus costs. Proof-size and performance optimization remains a
separate post-regeneration campaign, including evaluation of the Zakura Common
cryptography stack; it is not part of this compatibility migration or the
final v1 release gate.
FreshResolver cost is bounded by its block-window discovery: only the name's
visible operations in the bounded probe window are replayed, with bounded
block probing for reset eligibility; no global index or lookup RPC is required.
No trusted provider is introduced to improve any of these costs.

## 10. Consensus-version handling

The production construction layer is parameterized over `Parameters` for fee
and shape planning and targets the `BranchId::Nu6_3` V6/Ironwood consensus
branch explicitly at PCZT creation, with a documented gate in
`names_v1_builder`. Ironwood is the NU6.3-era shielded pool; until upstream
dependencies define a successor branch and transaction version for Ironwood
transactions, that gate is the explicit current-support boundary rather than a
hidden assumption. No speculative NU7 behavior exists in the code.

## 11. Test organization

Routine CI runs only cheap deterministic tests: construction, wire vectors
(conformance only), funding/accounting, machine/resolver semantics with
synthetic blocks and wire conformance. Heavy work is opt-in:

- `cargo test -- --ignored` runs the proof-generating unit tests (real
  Names genesis proof and real Ironwood consensus proof fixtures).
- `scripts/live-qualification.sh` drives the real Zakura → Zaino →
  zcash-devtool stack; its disposable v1 phases build and mine live
  operations and verify canonical acceptance.

The `names-v1-live` harness is retained as release-regression tooling;
construction logic is not duplicated between it and the library.

## 12. Release qualification

The final release qualification record, transaction IDs, and artifact hashes
are maintained in [`QUALIFICATION.md`](QUALIFICATION.md) and the repository
release records. Qualification demonstrates the production construction path
end to end on the pinned stack; it is local evidence, not an audit or a
deployment guarantee.

## 13. Roadmap: planned v2 transfer and marketplace

This section is a roadmap note, not a specification: nothing here is
implemented, frozen, or qualified, and no v2 wire layout, circuit public
input, marketplace offer format, payment mechanic, or transfer cryptography
is fixed here.

Names v1 deliberately ships without a `TRANSFER` operation. **TRANSFER is
planned for v2**, together with a **Names marketplace** built around transfer
with atomic Zcash settlement: offers and payment are expected to settle
through ordinary Zcash transactions/PCZTs rather than any separate consensus
or fork-choice system. Zcash remains the sole consensus and fork-choice
authority.

The intended compatibility model is continuation of the existing per-name
state-note lineage. An existing canonical v1 `NameState` remains the
registered name, and a future v2 operation should be able to consume that
existing canonical state head directly. There is no global state migration,
no migration transaction merely for upgrading, no `RELEASE` + `COMMIT` +
`REVEAL` cycle, and no requirement for existing owners to re-register their
names. Conceptually the desired evolution is:

```text
... -> UPDATE_v1 -> RENEW_v1 -> TRANSFER_v2 -> UPDATE_v2 -> ...
```

The name identity and lineage survive protocol-version upgrades: protocol
version belongs to the operation and proof advancing the lineage, not to
whether the name still exists. A v2 transfer is expected to change ownership
while preserving the same `name_id` and continuing the sequence and state
lineage.
