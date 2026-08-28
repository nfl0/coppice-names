# Coppice Names v2 architectural correction report

## 1. Executive verdict

The diagnosis is confirmed.

The current Names v2 proof is a strong state-note binding proof, but it is not a complete local Names transition proof. UPDATE, RENEW, RELEASE, and most REVEAL formation rules remain ordinary Rust checks in `V2StateMachine` and `FreshResolver`.

Consequently:

> “valid Names proof = guaranteed valid LOCAL Names transition”

is false for the current circuit.

The intended three-authority architecture is sound, provided the correction preserves:

- exact canonical action authentication;
- explicit equality between the action nullifier and the current head’s previously proof-authenticated future nullifier;
- successor CMX opening, owner/recipient binding, future-nullifier binding, and bond-value semantics;
- all canonical currentness, COMMIT, replacement, abandonment, and fork-history decisions in replay;
- canonical public-statement construction for byte-oriented values such as records and scheduled anchors.

The current circuit should not be released as the final v2 local-transition circuit.

## 2. Intended architecture reconstructed from current design goals

The code already supports the intended high-level division:

```text
Zcash consensus
  canonical blocks and fork choice
  valid Ironwood Actions
  public NF/CMX action tuple
  hidden spent-note validity and authorization
  hidden output-note commitment validity
  rho_new = nf_old

Names ZK
  complete legality of one local state transition
  application-specific interpretation of the successor note
  owner, bond, state, and future-nullifier bindings not exposed by consensus

Names runtime/history
  exact current head
  accepted predecessor lineage
  canonical action and operation position
  COMMIT history
  replacement and claimability
  abandonment and competing spends
  reorg/rebuild
```

One correction to the shorthand runtime algorithm is required:

```text
1. require exact accepted current predecessor
2. require canonical action NF == current head's stored future NF
3. authenticate the same action's canonical NF/CMX and actual block height
4. verify complete local Names proof
5. replace head
6. treat a canonical current-NF spend without an accepted successor as abandonment
```

REVEAL additionally requires canonical COMMIT/replacement history. These are not candidates for ZK merely to make the proof “prove everything.”

## 3. Current transition circuit: exact responsibilities

The transition statement has 22 public field elements. Its definitive implementation is [`state_note_binding.rs`](/home/besudo/Git/Coppice/orchard-coppice/src/circuit/state_note_binding.rs:47), with Names-side statement construction in [`transition.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/transition.rs:37).

It proves the following:

1. **Predecessor note commitment reconstruction**

   It privately witnesses predecessor `g_d`, `pk_d`, value, `rho`, `psi`, and `rcm`, evaluates Ironwood `NoteCommit`, and constrains the extracted commitment to the public predecessor commitment.

   Security property: the application proof’s predecessor note opening really corresponds to the declared prior CMX. It does not prove Merkle membership or canonical currentness.

2. **Predecessor owner/FVK relation**

   It witnesses `ak`, `nk`, and `rivk`, computes `CommitIvk(ak, nk, rivk)`, converts that to `ivk`, and constrains `pk_d = [ivk]g_d`.

   Security property: the predecessor note is addressed to the hidden FVK whose `ak` is later bound to the public owner.

3. **Predecessor nullifier derivation**

   It derives `NF = DeriveNullifier(nk, rho, psi, cm)` and constrains it to the public action nullifier.

   Security property: the public canonical NF is linked to the privately opened predecessor note.

4. **Spend-authorizing-key relation**

   It proves `ak = [ask]SpendAuthG`.

   Security property: the Names prover knows an `ask` corresponding to the hidden/publicly declared owner key. This duplicates authorization already required by the consensus transaction’s SpendAuth signature.

5. **Successor note commitment reconstruction**

   It independently witnesses the successor note opening and computes its exact CMX, constrained to the public successor commitment.

   Security property: Names state, owner, value, `rho`, and future NF refer to the same hidden note behind the canonical action CMX.

6. **Successor recipient relationship**

   Using the predecessor FVK’s `ivk`, it proves:

   ```text
   successor.pk_d = [predecessor.ivk] successor.g_d
   ```

   Security property: the successor remains payable to the same FVK, while allowing a different diversifier.

7. **Successor rho binding**

   It enforces:

   ```text
   successor.rho = predecessor-derived/public-action NF
   ```

   Security property: the successor opening is tied to the output half of the same intended Ironwood Action.

8. **Value preservation**

   It enforces exact equality of predecessor and successor `NoteValue`.

   Security property: the hidden state-note bond cannot be reduced, increased, or moved to another action under the Names statement.

9. **Successor future nullifier**

   It derives the successor NF using the successor opening and predecessor `nk`, then exposes it as a public input.

   Security property: replay can later recognize the exact canonical spend of the otherwise hidden successor note.

10. **Owner binding**

    The x-coordinate of the hidden predecessor `ak` is constrained to the public canonical owner field. Names-side state parsing separately requires the byte representation to be a valid RedPallas key.

11. **Sequence relation**

    Both sequences are u64-range-checked, and:

    ```text
    successor_sequence = predecessor_sequence + 1
    ```

    is enforced in the field. Since both sides are u64, wraparound at the field modulus is excluded. `u64::MAX + 1` cannot be represented by the successor u64 range.

12. **State digests**

    Each state digest is nested Poseidon over:

    ```text
    domain
    name_id
    owner_key
    sequence
    record_digest
    lease_expiry
    status
    terminal_height
    note_commitment
    ```

    The circuit does not hash record bytes. Rust computes the record digest from canonical public bytes before forming the proof statement.

13. **Predecessor reference binding**

    It hashes:

    ```text
    predecessor_state_digest
    predecessor_ref_digest
    operation
    operation_height
    ```

    into the public transition-binding field.

    This binds those already-public fields together, but does not authenticate the reference as current or canonical. `StateRef::digest()` itself is computed outside the circuit from producer height, tx index, txid, action index, operation index, commitment, and stored future NF.

14. **Operation binding**

    The operation code is public and included in the binding hash.

    Critical limitation: it is only range-checked as a u8. The circuit does not require code 1/2/3 and does not branch on UPDATE/RENEW/RELEASE.

15. **Operation-height binding**

    The field named `RENEWAL_HEIGHT_INPUT` in Orchard is used by Names as the actual operation height for every transition. It is u32-range-checked and included in the binding hash.

    Critical limitation: it is not used in any lease, schedule, status, or terminal-height rule.

16. **Range and configuration constraints**

    - sequences: u64;
    - leases, terminal heights, operation height: u32;
    - operation and statuses: u8;
    - note values: Ironwood note-commitment u64 encoding;
    - nonidentity curve points for addresses and keys;
    - anchored-base ECC configuration;
    - one instance column, ten equality-enabled advice columns;
    - Sinsemilla, Poseidon, ECC, addition, and lookup-range machinery;
    - `K = 11`.

It does **not** prove:

- UPDATE semantics;
- RENEW semantics or scheduled-anchor membership;
- RELEASE semantics;
- predecessor Active status;
- operation before lease expiry;
- status limited to Active/Released;
- Active implies terminal zero;
- current-head membership;
- predecessor canonicality;
- action index or canonical producer position;
- Merkle membership;
- consensus SpendAuth signature;
- action value commitment;
- action anchor;
- record-byte hashing.

## 4. Current genesis circuit: exact responsibilities

The genesis circuit uses 12 public inputs and proves:

- registration input note commitment reconstruction;
- registration input FVK/address relationship;
- registration input NF derivation, constrained to the designated action NF;
- `ask → ak`;
- public owner → hidden registration `ak`;
- successor note CMX reconstruction;
- successor recipient under the registration input’s IVK;
- `successor.rho = registration action NF`;
- exact registration-value → successor-value preservation;
- registration value `= minimum_bond + u64 delta`, hence `>= minimum_bond`;
- successor future NF under the same `nk`;
- genesis state digest;
- u64 sequence and minimum-bond ranges;
- u32 lease and terminal ranges;
- u8 status range.

It does **not** prove:

- sequence is zero;
- status is Active;
- terminal height is zero;
- lease expiry equals `operation_height + lease_duration`;
- REVEAL is at the scheduled anchor;
- name, owner, and record equal the disclosed intent;
- intent preimage matches the referenced COMMIT;
- COMMIT authenticity, maturity, TTL, or canonical position;
- replacement/claimability legality;
- operation height at all—the genesis proof has no height public input.

Thus a genesis proof proves a valid hidden registration-note → successor-note/bond relation around supplied state fields, not a valid REVEAL operation.

## 5. Current runtime/state-machine responsibilities

Classification:

- **A** — inherently canonical-history/runtime-only
- **B** — local transition semantics that should be in the corrected proof
- **C** — duplicated in current runtime and ZK
- **D** — only in current ZK
- **E** — only in current runtime

### Common block/transaction processing

The state machine checks canonical sequential height, predecessor block hash, transaction-index order, action-index order, operation/action order, and first operation claim per physical action. It processes operations atomically and then uses unmatched canonical nullifiers to mark active heads abandoned. These are **A/E**.

### REVEAL

[`apply_reveal`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/machine.rs:349) checks:

- canonical normalized name and valid registration intent — **B/E**, except parsing;
- state name/owner/record equal intent — **B/E**;
- sequence zero — **B/E**;
- Active status and terminal zero — **B/E**;
- exact lease expiry from actual block height — **B/E**;
- owner representation, record bound, status/terminal consistency — **B/E**, partially range-checked in ZK;
- disclosed intent hashes to referenced COMMIT value — history linkage, **A/E**;
- exact accepted pending `CommitRef`, including operation position — **A/E**;
- same-block prohibition, maturity, TTL — **A/E**;
- scheduled REVEAL anchor — local time rule, currently **B/E**;
- current name claimability — **A/E**;
- replacement predecessor equals current terminal head, or bounded no-predecessor reset is eligible — **A/E**;
- replacement COMMIT does not predate claimability — **A/E**;
- exact action exists and its CMX equals the declared successor commitment — canonical fact selection, **A/E**, followed by ZK CMX opening;
- genesis proof verification — note/bond relations **D**.

### UPDATE/RENEW/RELEASE common checks

[`apply_transition`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/machine.rs:493) checks:

- a current head exists — **A/E**;
- exact `StateRef` and commitment equal current head — **A/E**;
- current head is not abandoned — **A/E**;
- predecessor status Active and actual height before lease expiry — local, **B/E**;
- successor state representation is valid and record bounded — **B/E**, with partial ZK ranges;
- name and owner unchanged — **C**;
- sequence exactly +1 with checked Rust arithmetic — **C**;
- selected action exists and action CMX equals declared successor CMX — **A/E**, then ZK;
- proof statement uses the actual canonical block height — input authenticity **A/E**, but height semantics remain outside ZK.

There is no explicit runtime equality:

```text
action.nullifier == current.state_ref.nullifier
```

The current circuit establishes this indirectly by reopening the predecessor note and deriving its NF. That explicit equality becomes mandatory if predecessor-note reconstruction is removed.

### UPDATE

Runtime requires:

- successor Active;
- terminal height zero;
- lease unchanged;
- record changed.

All four are **B/E**. None is enforced by the current circuit.

### RENEW

Runtime requires:

- successor Active;
- terminal height zero;
- record unchanged;
- actual block height is the name-derived scheduled anchor;
- successor lease equals `block.height + lease_duration`;
- successor lease strictly exceeds predecessor lease.

All are **B/E**. None is enforced by the current circuit.

A stale-but-unexpired predecessor may renew; abandonment, expiry, or a noncurrent predecessor may not. Staleness is derived lifecycle/history; the local proof only needs Active status and `height < lease_expiry`, while abandonment/currentness remain runtime.

### RELEASE

Runtime requires:

- successor Released;
- terminal height equals actual block height;
- record unchanged;
- lease unchanged.

All are **B/E**. None is enforced by the current circuit.

### FreshResolver

[`resolver.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/resolver.rs:363) independently authenticates accepted producer positions rather than accepting proof-valid physical notes. It replays:

- exact canonical blocks, txids, action and carrier-message positions;
- first-action ownership;
- accepted predecessor producers;
- finite pending-COMMIT history;
- accepted COMMIT consumption;
- replacement and reset eligibility;
- canonical nullifier spends and abandonment;
- the same operation-specific Rust semantics.

These are essential **A** responsibilities, except for the duplicated local transition rules.

Wallet-side `prepare_update`, `prepare_renew`, and `prepare_release` also construct semantically correct states, but wallet construction is not a validation authority.

## 6. Constraint-by-constraint authority matrix

| Invariant | Current ZK | Current runtime | Zcash consensus | Proposed owner | Notes |
|---|---:|---:|---:|---|---|
| Canonical chain and fork choice | No | Yes | Yes | ZCASH_CONSENSUS | Runtime follows the node-selected branch |
| Canonical block/tx/action ordering | No | Yes | Yes | NAMES_RUNTIME_HISTORY | Names authenticates its ordered observation |
| Action proof validity | No | Assumed from canonical source | Yes | ZCASH_CONSENSUS | Core does not re-run consensus proof verification |
| Spent-note Merkle membership | No | No | Yes for nonzero spend | ZCASH_CONSENSUS | State-note bond is nonzero |
| Old note commitment validity | Yes | Indirect | Yes, hidden | ZCASH_CONSENSUS | Transition can inherit after exact stored-NF check; genesis caveat below |
| Old nullifier correctness | Yes | Not explicitly for acceptance | Yes | ZCASH_CONSENSUS | Runtime must explicitly match action NF to stored future NF |
| Spend authority and signature | `ask → ak` only | No | Yes | ZCASH_CONSENSUS | Current Names `ask` relation is redundant |
| Same action carries NF and CMX | Public pair, no index | Yes | Yes | ZCASH_CONSENSUS | Runtime selects the exact canonical index |
| Output CMX is a valid hidden note commitment | Yes | CMX equality | Yes | ZCASH_CONSENSUS | Names still needs its own opening for app bindings |
| Consensus `rho_new = nf_old` | Yes | Same-action selection | Yes | ZCASH_CONSENSUS | Keep app-opening equality as cheap defense |
| Names successor opening uses action NF as rho | Yes | Indirect | Similar existential fact | DEFENSE_IN_DEPTH_DUPLICATE | Cheap and avoids cross-proof existential ambiguity |
| Output addressed to declared Names owner | Yes | Owner bytes checked | No with `Flags::ENABLED` | NAMES_ZK | Consensus output is not tied to Names owner |
| Successor future NF | Yes | Stored/replayed | No until future spend | NAMES_ZK | Must remain |
| Exact bond-value preservation | Yes | Hidden | No; only commits to `v_old-v_new` | NAMES_ZK | May bind authenticated `cv_net` to zero value |
| Genesis minimum bond | Yes | Parameter supplied | No | NAMES_ZK | Must remain |
| Name and owner continuity | Yes | Yes | No | NAMES_ZK | Runtime may retain cheap statement sanity checks |
| Sequence +1 | Yes | Yes | No | NAMES_ZK | Current duplicate |
| State digest | Yes | Computed in Rust | No | NAMES_ZK | Public byte-to-field canonicalization remains host code |
| Valid Active/Released encoding | Range only | Yes | No | NAMES_ZK | Circuit must enforce exact allowed codes and terminal rule |
| UPDATE semantics | No | Yes | No | NAMES_ZK | Record changes; other fields preserved |
| RENEW semantics | No | Yes | No | NAMES_ZK | Includes scheduled anchor and exact extension |
| RELEASE semantics | No | Yes | No | NAMES_ZK | Exact terminal state |
| Actual operation-height provenance | Merely public/bound | Yes | Canonical block height | NAMES_RUNTIME_HISTORY | ZK then uses that authenticated height semantically |
| Exact current predecessor | No | Yes | No | NAMES_RUNTIME_HISTORY | Never prove global currentness |
| Current head unspent/unabandoned | No | Yes | Canonical NF observations | NAMES_RUNTIME_HISTORY | Includes unmatched-spend detection |
| COMMIT authenticity/maturity/TTL | No | Yes | Only transaction canonicality | NAMES_RUNTIME_HISTORY | Preserve COMMIT → REVEAL |
| Replacement and claimability | No | Yes | No | NAMES_RUNTIME_HISTORY | Depends on accepted lineage/history |
| Competing children/winner | No | Yes | Zcash nullifier/fork choice | NAMES_RUNTIME_HISTORY | Zcash selects canonical spend |
| Wire canonicality and public representation checks | No | Yes | No | DEFENSE_IN_DEPTH_DUPLICATE | Required to parse and construct the proof statement safely |

## 7. Confirmed duplicated work

### Spend-authorizing-key multiplication

- Zcash proves `rk = ak + [alpha]G` inside the Action proof and verifies the transaction SpendAuth signature under `rk`.
- Names separately proves `ak = [ask]G`.
- Names does not bind its proof to the consensus signature.
- Once the Names hidden `ak` is otherwise tied to the relevant note, this is redundant knowledge-of-`ask`.
- **Removable:** yes, without weakening transaction authorization.

### Transition predecessor NoteCommit/CommitIvk/nullifier work

Zcash proves that the canonical action NF comes from a valid hidden spent note, with valid FVK/address relation and membership. Names repeats those computations to prove that the note is the declared predecessor.

For a non-genesis transition this can be inherited safely only if:

1. the predecessor is an accepted Names head;
2. its future NF was authenticated by the prior Names proof;
3. runtime explicitly checks canonical action NF equals that stored future NF;
4. the action CMX is the proof-bound successor CMX.

Under those conditions, predecessor NoteCommit, predecessor CommitIvk, and predecessor NF derivation are unnecessary for lineage identity. Exact bond preservation still needs a replacement relation, discussed below.

### Successor rho equality

Consensus proves output `rho = action NF`. Names proves its successor opening has the same rho.

This is duplicated, but the Names equality is extremely cheap once the successor note is already witnessed and directly prevents an application opening from relying solely on cross-proof commitment binding. It is justified defense in depth and should remain.

### State and sequence checks

Name/owner continuity, state-digest construction, and sequence +1 are presently checked in both Rust and ZK. The corrected primary authority should be Names ZK, with Rust limited to canonical statement construction and cheap fail-fast checks.

## 8. Necessary-looking duplication / hidden-binding caveats

| Circuit component | Why present | Duplicates consensus? | Must remain in ZK? | Cost class | Confidence |
|---|---|---:|---:|---|---|
| Predecessor NoteCommit | Link old opening to prior CMX | Yes | Transition: likely no; genesis: likely yes under current owner semantics | Very expensive | High |
| Predecessor CommitIvk/address | Link hidden old FVK to note | Yes | Transition: likely no; genesis: likely yes | Very expensive | High |
| Predecessor NF derivation | Link action NF to old opening | Yes | No after explicit stored-future-NF check | Very expensive | High |
| `ask → ak` | Extra ownership knowledge | Yes | No | Very expensive ECC | High |
| Successor NoteCommit | Bind app state/owner/value/rho/NF to action CMX | Existentially | Yes | Very expensive | High |
| Successor CommitIvk and `pk_d=[ivk]g_d` | Bind output to Names owner/FVK | No usable consensus fact | Yes | Very expensive | High |
| Successor `rho = action NF` | Exact same-action binding | Yes | Yes, as cheap defense | Cheap equality | High |
| Exact value preservation | Preserve hidden bond | Consensus proves only committed value delta | Yes, in some form | Current: cheap equality after two expensive openings | High |
| Successor future NF | Enable later compact-spend recognition | No | Yes | Very expensive | High |
| State Poseidon hashes | Bind application state | No | Yes | Moderate | High |
| Ref/operation/height binding hash | Explicit tuple digest | Public inputs already transcript-bound | Not necessarily in current form | Moderate | Medium |
| Ranges and sequence arithmetic | Canonical state arithmetic | No | Yes | Cheap | High |
| UPDATE/RENEW/RELEASE selectors | Complete local legality | No | Yes | Cheap except schedule hash issue | High |
| Genesis minimum delta | Hidden minimum-bond check | No | Yes | Cheap after value witness | High |

Two apparent duplications are not freely removable:

1. **Successor NoteCommit:** consensus proves there exists a valid hidden output note matching CMX. Names must prove that the same CMX hides the specific owner, value, rho, and future NF asserted by Names. Consensus does not expose those facts.

2. **Successor owner/future NF:** Core exposes no output plaintext, `nk`, `rivk`, IVK, or future NF. These remain application-proof responsibilities.

For exact value preservation, Core can expose authenticated `cv_net` through extended full-transaction effects. A potentially smaller relation is:

```text
canonical_action.cv_net = ValueCommit(0, rcv)
```

with private `rcv`. Consensus already proves `cv_net` commits to `v_old-v_new`, so this establishes equality without reopening the predecessor note. This is sound in principle but requires a focused audit of:

- value-commitment binding assumptions;
- access to the exact action `rcv`;
- reordering the current construction pipeline, because Names proof generation currently precedes final Ironwood action construction;
- selective extended-effect acquisition.

It does not require Core to understand Names.

Genesis is harder: current semantics require the registration input and successor owner/FVK to match. The registration input has no previously authenticated Names future NF, so removing its hidden note/FVK binding would weaken current semantics. Public `rk` alone does not identify the unrandomized hidden `ak`, because the consensus randomizer is not publicly bound to the Names proof.

## 9. Concrete mismatch: proof-valid but runtime-invalid examples

Each example can satisfy the current circuit if supplied with valid predecessor/successor note witnesses, preserved value, owner, rho relation, future NF, sequence +1, ranges, and consistent public hashes:

- **UPDATE with unchanged record:** circuit accepts equal record digests; runtime returns `InvalidUpdate`.
- **UPDATE changing lease:** circuit accepts any u32 successor lease; runtime rejects unless unchanged.
- **UPDATE producing Released status:** circuit accepts status 2 and a nonzero terminal; runtime requires Active/zero terminal.
- **RENEW outside scheduled anchor:** operation height is only range-checked and hashed; runtime returns `InvalidRenewal`.
- **RENEW changing record:** circuit permits it; runtime requires equality.
- **RENEW that does not extend the lease:** circuit permits equal or smaller u32 lease; runtime requires exact `height + duration` and strict extension.
- **RENEW with arbitrary lease extension:** circuit permits it even if not the parameter-derived expiry.
- **RELEASE with wrong terminal height:** circuit permits any u32 terminal; runtime requires actual block height.
- **RELEASE changing record or lease:** circuit permits both; runtime rejects.
- **RELEASE remaining Active:** circuit permits it; runtime requires Released.
- **Transition from a Released predecessor:** circuit hashes the supplied predecessor status but does not require Active; runtime rejects before proof verification.
- **Transition at or beyond predecessor lease expiry:** circuit does no comparison; runtime rejects.

Genesis equivalents include proof-valid states with sequence nonzero, Released status, arbitrary lease expiry, a record different from the registration intent, or REVEAL outside its scheduled anchor. Runtime rejects all of them.

No expensive proof generation is needed to establish these counterexamples; they follow directly from the absence of operation selectors/comparisons in synthesis.

## 10. Proposed corrected local proof relation

### A. REVEAL/genesis

```text
ValidGenesis(
    public canonical action facts,
    public disclosed registration intent/state,
    public actual operation height,
    public protocol parameters,
    private registration-note binding witness,
    private successor-note witness,
    private bond witness
)
```

**Public/authenticated inputs**

- canonical action index and same-index `NF`, `CMX`;
- actual canonical operation height;
- canonical name id, owner, record digest/length;
- proposed initial state;
- minimum bond and lease/schedule parameters;
- optionally authenticated action `cv_net` if used for value equality.

The exact accepted COMMIT reference and replacement history remain runtime inputs, not proof claims.

**Private witness**

- successor note opening;
- successor FVK components needed for owner/recipient and future NF;
- registration hidden note/FVK material still required to preserve current same-owner genesis semantics;
- value delta or action value-commitment randomness;
- no Merkle path or canonical-history witness.

**Proven relation**

- initial name/owner/record equal the disclosed intent;
- sequence = 0;
- status = Active;
- terminal height = 0;
- lease expiry = operation height + duration;
- operation height is the scheduled REVEAL anchor;
- successor CMX equals canonical action CMX;
- successor rho equals canonical action NF;
- successor recipient belongs to the declared owner/FVK;
- successor future NF is correct;
- exact bond preservation and minimum bond;
- canonical state digest.

COMMIT preimage equality, accepted COMMIT position, maturity, TTL, name availability, and replacement remain history checks.

### B. Non-genesis transition

```text
ValidLocalTransition(
    predecessor_state,
    successor_state,
    operation,
    operation_height,
    canonical_action_facts,
    private_successor_note_witness,
    private_value_binding_witness
)
```

**Public/authenticated inputs**

- exact accepted predecessor state or state digest;
- predecessor’s stored proof-authenticated future NF;
- proposed successor state;
- UPDATE/RENEW/RELEASE;
- actual canonical block height;
- exact canonical action NF and CMX from one action index;
- `cv_net` if the zero-delta optimization is adopted;
- fixed protocol parameters.

A `StateRef` digest may remain as domain separation, but the proof must not claim that it is globally current.

**Private witness**

- successor note opening;
- successor owner FVK material required for recipient and future NF;
- action value-commitment randomness if used;
- no old Merkle path and ideally no predecessor note opening.

**Proven common relation**

- action NF equals the declared predecessor future NF;
- successor CMX opening equals action CMX;
- successor rho equals action NF;
- successor recipient/owner and future NF are correct;
- name and owner are preserved;
- sequence is exactly +1;
- predecessor is Active and operation height is before lease expiry;
- exact bond-value preservation;
- state encodings and digests are canonical.

**Operation branches**

```text
UPDATE:
  successor.record != predecessor.record
  successor.lease = predecessor.lease
  successor.status = Active
  successor.terminal = 0

RENEW:
  successor.record = predecessor.record
  operation_height is scheduled anchor(name_id)
  successor.lease = operation_height + lease_duration
  successor.lease > predecessor.lease
  successor.status = Active
  successor.terminal = 0

RELEASE:
  successor.record = predecessor.record
  successor.lease = predecessor.lease
  successor.status = Released
  successor.terminal = operation_height
```

The existing name-derived schedule uses Blake2b outside Halo2. A literal in-circuit schedule proof could be expensive. Before implementation, the specification must decide whether:

- the schedule is changed to a ZK-friendly versioned primitive;
- Blake2b is actually proven;
- or canonical statement construction supplies an authenticated expected anchor, in which case the meaning of “proof alone” must explicitly be “proof under correctly derived canonical public inputs.”

That is the largest unresolved local-semantics issue.

## 11. What remains runtime/history-only

The corrected runtime should retain:

- host-selected canonical branch and reorg handling;
- exact block, transaction, action, and carrier-message order;
- accepted current-head lookup;
- exact predecessor `StateRef`;
- action NF equals stored future NF;
- exact action CMX and canonical provenance;
- first operation claiming an action;
- COMMIT insertion, duplicates, consumption, maturity, TTL, and expiry;
- exact accepted `CommitRef`;
- name availability and claimability;
- replacement predecessor and no-predecessor reset history;
- canonical competing-spend winner;
- unmatched current-NF spend → abandonment;
- bounded FreshResolver accepted-producer authentication;
- activation and continuity;
- canonical public-byte parsing and proof-statement construction;
- proof verification and head replacement.

None requires a global Names root or proof of whole history.

## 12. Scalability impact

The corrected design preserves the intended model:

- every name retains an independent state-note lineage;
- there is no globally contended Names state root;
- competing children spend the same stored predecessor NF;
- Zcash consensus and fork choice select the canonical winner;
- compact NF/CMX observations remain sufficient for ordinary replay;
- unrelated names evolve independently;
- FreshResolver can continue authenticating only relevant accepted producers and bounded tails;
- a future v3 TRANSFER can consume a canonical v2 head directly if the future NF, note opening, name id, and sequence remain stable;
- marketplace settlement can remain an ordinary atomic Zcash transaction/PCZT layer.

A proposal would weaken this model if it introduced a global state commitment, recursive history proof, sequencer, application fork choice, trusted currentness witness, or required v2 heads to migrate before v3. None is recommended here.

## 13. Proof-size / CPV1 impact analysis

The current 4,640-byte proof is exactly 145 32-byte proof elements.

The pinned Halo2 0.3.2 cost model shows proof length depends primarily on:

- advice-column commitments and queries;
- lookup arguments;
- permutation columns/chunks;
- vanishing commitments;
- multi-opening point sets;
- the IPA polynomial-commitment opening.

It does not scale directly with the number of repeated gadget rows.

At `K=11`, the IPA tail alone contains:

```text
1 s-polynomial commitment
22 IPA round commitments
2 scalars
= 25 × 32 = 800 bytes
```

before advice, permutation, lookup, vanishing, and multi-opening material. Therefore a 636-byte/two-frame proof is impossible with the current `K=11` IPA architecture.

The relevant transition thresholds become:

| CPV1 frames | Maximum proof | Maximum 32-byte proof size | Elements that must disappear |
|---:|---:|---:|---:|
| 9 | 4,171 B | 4,160 B | 15 |
| 8 | 3,666 B | 3,648 B | 31 |
| 7 | 3,161 B | 3,136 B | 47 |
| 6 | 2,656 B | 2,656 B | 62 |
| 5 | 2,151 B | 2,144 B | 78 |
| 4 | 1,646 B | 1,632 B | 94 |
| 3 | 1,141 B | 1,120 B | 110 |
| 2 | 636 B | 608 B | 126 |

For REVEAL, the supplied 5,054-byte envelope has approximately 414 bytes of non-proof overhead. Ten frames hold 4,983 bytes, so the proof must be at most 4,569 bytes; because proof length is 32-byte granular, 4,544 bytes is the practical target. A 96-byte reduction would cross that particular threshold.

Assessment:

- Removing predecessor NoteCommit/CommitIvk/NF/`ask` can significantly reduce constraint rows and likely proving time.
- It does **not automatically reduce proof bytes**, because the successor residual binding still needs the same NoteCommit, CommitIvk, ECC, Poseidon, range, and equality configurations.
- Adding UPDATE/RENEW/RELEASE selectors and small arithmetic is cheap in rows and may add only modest proof structure.
- Dropping one `K` level saves only 64 IPA bytes; by itself that does not cross the transition 9-frame threshold and likely does not cross REVEAL’s practical 4,544-byte target.
- `<= ~3 KB`: not supported by the current static structure; conceivable only after deliberate proof-layout/configuration optimization.
- `<= ~2.5 KB`: unlikely while retaining private successor owner/future-NF binding with these Orchard gadgets.
- `<= ~2 KB`: very unlikely under the current Halo2/IPA design.
- two-frame transport: impossible at `K=11` and fundamentally unrealistic for this nontrivial relation under this proof system.
- even three frames leaves only 320 bytes beyond the fixed 800-byte IPA tail and is not realistic.

The hypothesis “remove expensive duplicated Ironwood cryptography while adding cheap Names semantics” is supported for semantic cleanliness and prover work. It is not yet supported as a meaningful proof-byte reduction claim.

## 14. Recommended correction strategy

1. Treat the current VK identities and live measurements as historical qualification evidence, not as a reason to retain the wrong semantic boundary.
2. Specify a new versioned genesis and transition statement before changing synthesis.
3. Add negative relation tests for every counterexample in section 9.
4. Make canonical action NF = stored predecessor future NF an explicit runtime prerequisite.
5. Remove the Names `ask → ak` relation.
6. For transitions, remove predecessor-note cryptography only after the stored-NF linkage is explicit.
7. Prototype the authenticated `cv_net = ValueCommit(0, rcv)` value-preservation relation before deciding whether predecessor NoteCommit can disappear completely.
8. Preserve successor CMX opening, owner/recipient, rho, bond, and future-NF bindings.
9. Add full UPDATE/RENEW/RELEASE branches.
10. Resolve scheduled-anchor proving versus canonical statement derivation explicitly.
11. Keep genesis’s registration hidden-owner binding unless a replacement is proven to preserve the exact current semantics.
12. Measure candidate circuits with Halo2’s cost model before generating proofs or VKs; optimize proof arguments, not merely row count.
13. Only after the logical relation and size are accepted should new VKs, wire bytes, vectors, and qualification be generated.

## 15. Risks / unresolved questions

- Whether the value-commitment zero-delta relation can be integrated without circular PCZT/proof construction.
- Whether the current registration-input-owner equality is essential protocol policy or only construction policy; removing it would be a semantic change.
- How scheduled-anchor membership is represented without importing an expensive Blake2b circuit.
- Whether record/name preprocessing is formally part of canonical statement construction or must be proven byte-for-byte.
- Whether a redesigned circuit can remove enough configured queries/arguments to cross even one transition frame threshold.
- Whether `K` can fall below 11 after removing predecessor rows while retaining successor binding.
- Whether the current explicit transition-binding Poseidon hash adds security beyond transcript-bound public inputs.
- Any circuit correction changes the frozen v2 VK identities and requires an explicit protocol/version decision; current v1 tags and proofs remain untouched.

## 16. GO / NO-GO recommendation for changing the circuit before release

**GO for a pre-release v2 circuit correction. NO-GO for releasing the current circuit as the intended complete local-transition proof.**

The reason is semantic, not merely performance: the current proof boundary does not satisfy its intended abstraction. Proof-size improvement is a secondary, presently uncertain benefit.

### Evidence and inspected state

Live GitHub `main`, local `main`, and tracking refs matched exactly:

- `nfl0/coppice-names`: `4db9c5e61b26261daad6f9c6f7cd8ae7a36bad65`
- `nfl0/orchard-coppice`: `bf689decb9fce94a7de01b8bdc55a1e42e1695bb`
- `nfl0/coppice`: `91c88507bd3b90631a3e5816e8ea1b9eccb99b9d`
- `nfl0/zcash-devtool`: `ee03cae6b9d2438913d5d289ebc4e1fcaf76545c`

The production dependency remains pinned to Orchard `deea5a3b499c9f4e9e30ff4d9ffca4e0f51234ca`; the two later Orchard commits change documentation and add a VK-freeze test, not circuit synthesis.

Principal files inspected:

- [`state_note_binding.rs`](/home/besudo/Git/Coppice/orchard-coppice/src/circuit/state_note_binding.rs:1)
- [`circuit.rs`](/home/besudo/Git/Coppice/orchard-coppice/src/circuit.rs:78)
- [`bundle.rs`](/home/besudo/Git/Coppice/orchard-coppice/src/bundle.rs:219)
- [`note_commit.rs`](/home/besudo/Git/Coppice/orchard-coppice/src/circuit/note_commit.rs:1)
- [`commit_ivk.rs`](/home/besudo/Git/Coppice/orchard-coppice/src/circuit/commit_ivk.rs:1)
- [`machine.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/machine.rs:1)
- [`resolver.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/resolver.rs:1)
- [`transition.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/transition.rs:1)
- [`operation.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/operation.rs:1)
- [`state.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/state.rs:1)
- [`lease.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/lease.rs:1)
- [`schedule.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/schedule.rs:1)
- [`registration.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/registration.rs:1)
- [`wire.rs`](/home/besudo/Git/Coppice/coppice-names/crates/coppice-names/src/v2/wire.rs:1)
- [`replay.rs`](/home/besudo/Git/Coppice/coppice/crates/coppice-core/src/replay.rs:121)
- [`application.rs`](/home/besudo/Git/Coppice/coppice/crates/coppice-core/src/application.rs:67)
- [`transport.rs`](/home/besudo/Git/Coppice/coppice/crates/coppice-core/src/transport.rs:41)
- [`names_v2_operation.rs`](/home/besudo/Git/Coppice/zcash-devtool/src/names_v2_operation.rs:180)
- [`names_v2_builder.rs`](/home/besudo/Git/Coppice/zcash-devtool/src/names_v2_builder.rs:319)
- [`NAMES_V2.md`](/home/besudo/Git/Coppice/coppice-names/docs/NAMES_V2.md:14)
- [`QUALIFICATION.md`](/home/besudo/Git/Coppice/coppice-names/docs/QUALIFICATION.md:135)
- pinned Halo2 0.3.2 `src/dev/cost.rs`
- relevant `Cargo.toml` and `Cargo.lock` files in Names, Orchard, and devtool

No proofs, circuits, keys, vectors, tests, or live nodes were run. All four inspected worktrees remained clean. No code or repository state was changed.

CURRENT_ZK_BOUNDARY_MATCHES_INTENT=no
CORRECTED_LOCAL_TRANSITION_ZK_ARCHITECTURE_SOUND=yes
MEANINGFUL_HALO2_PROOF_SIZE_REDUCTION_PLAUSIBLE=uncertain
PRE_RELEASE_CIRCUIT_CORRECTION_RECOMMENDED=yes
