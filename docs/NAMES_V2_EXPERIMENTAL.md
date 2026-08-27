# Coppice Names v2 experimental vertical slice

This document describes the implementation-quality experimental slice. It is
not a deployment specification and does not change the frozen Names v1
protocol, wire format, identities, vectors, or BondProof.

## Authority and scope

The experiment consumes the canonical ordered Ironwood effects emitted by
Coppice Core. Core remains application-blind, Zcash remains the only
fork-choice and double-spend authority, and no Names root or Names-specific
index is a transaction precondition.

The v2 operation family is exactly:

```text
COMMIT, REVEAL, UPDATE, RENEW, RELEASE
```

Registration remains two-stage. `COMMIT` publishes a hidden commitment;
`REVEAL` consumes a mature commitment and creates the first state note. There
is no single `REGISTER` operation and no `TRANSFER` operation in this slice.

## State and lineage invariants

1. Every accepted name has one current state-note commitment and one exact
   producer position. The position contains height, transaction index,
   transaction ID, action index, carrier-message index, commitment, and the
   proof-authenticated future nullifier of the state note.
2. `REVEAL` is the only genesis of a lineage. Its state-note commitment must
   equal the commitment of the selected canonical Ironwood action, and its
   genesis proof must authenticate the state data and note-control relation.
3. Every non-genesis operation references the exact producer position of its
   predecessor. The predecessor action commitment must equal the referenced
   commitment.
4. A transition proof binds one predecessor nullifier and one successor
   commitment to the same action index. It proves the predecessor note
   commitment, its nullifier, the successor note commitment, and
   `rho_successor = nullifier_predecessor`. It also derives the successor's
   future nullifier and proves exact predecessor/successor value preservation.
5. The transition proof binds the declared owner to the canonical Ironwood
   `ak`/SpendAuth validating-key encoding and proves the predecessor and
   successor recipients derive from the same full-viewing-key authority. The
   actual canonical Ironwood action remains the Zcash spend-authority proof.
6. Sequence and lease values use canonical unsigned integer encodings and
   checked arithmetic. An accepted transition increments sequence exactly once.
7. `UPDATE` preserves owner and lease and changes the canonical record.
   `RENEW` preserves owner and record, occurs only at the deterministic slot,
   and sets expiry from the renewal height. `RELEASE` preserves owner and
   record and creates a terminal state note.
8. No state transition consumes an application-wide root. Alice and Bob are
   independent except for ordinary canonical Zcash action ordering and
   one-time nullifier validity.

Cryptographic validity is not Names acceptance. A valid Zcash action and a
valid Names proof can create a physical note for a REVEAL that the canonical
Names replay rejects because another same-name lineage became current first.
Such a shadow note is never an accepted Names producer and cannot seed a
fresh-resolution lineage.

Within one transaction, the first carrier message that names an action index
structurally reserves that physical action. Later messages naming the same
index are rejected even if the first message is semantically invalid. This
gives malformed first claimants transaction-local priority, but the author of
the transaction controls both messages. The rule is locally decidable from the
transaction, so fresh verification never replays another name to decide action
ownership. Reordering the messages deterministically changes the first owner.

## Registration and lease invariants

1. A commitment is valid only after the commitment block and only through its
   checked TTL. A reveal in the commitment block is rejected.
2. A reveal must be at the name's deterministic anchor slot. The commitment
   carries the name, owner, record digest, and fresh secret; proof artifacts
   are not the hidden semantic preimage. There is no v2 bond tag or global
   active-bond map.
3. REVEAL spends a real registration note and creates the initial state note
   in the same Ironwood action. Its v2-only genesis proof derives the action
   input nullifier from the private registration note, proves owner control,
   proves the successor recipient belongs to the same authority, constrains
   `rho_successor = registration_nullifier`, binds the action commitment, and
   proves `registration_value = state_value >= minimum_bond_zatoshis`.
   The minimum is an experimental public parameter, not frozen economics.
4. A replacement commitment must be mined no earlier than the height at which
   the old name became claimable. This preserves the v1 anti-precommit rule.
5. Payability/currentness and lease ownership are separate. With last anchor
   `a`, a record is payable only while `height < a + refresh_deadline`. It is
   stale (never payable) until `lease_expiry`, but its owner may still make a
   scheduled RENEW before that lease boundary.
6. An expired name becomes claimable at `lease_expiry + grace_period`. An
   explicitly released name becomes claimable at `terminal_height +
   reuse_delay`; these are deliberately separate terminal policies.

## Canonical spend currentness and refunds

Every genesis and transition proof publishes the future nullifier of its
successor state note. Publishing it links the public name lineage to the later
spend; this is an intentional privacy cost of using a publicly resolvable note
as an economic bond. The nullifier is authenticated by the same proof that
binds the state commitment and is included in `StateRef`.

Replay and fresh resolution inspect the ordinary ordered Ironwood nullifiers
already present in canonical transaction effects. If the current active note's
nullifier appears and that action does not produce an accepted Names
UPDATE/RENEW/RELEASE, the lineage becomes `Abandoned` immediately and is never
payable. It becomes reclaimable at `spend_height + reuse_delay`. A proof-valid
but Names-rejected successor does not prevent abandonment. No lookup RPC or
global nullifier index is required: a fresh lookup scans the same bounded tail
used for that name.

RELEASE already creates an authenticated terminal state, so spending its note
for refund does not change release/reuse timing. Likewise, ordinary refund
spending after an active lineage is already claimable does not revive or
re-block it. UPDATE and RENEW preserve the private bond value exactly. Fees and
additional inputs/outputs remain governed by ordinary Zcash bundle value
balance; Names does not duplicate full transaction conservation.

## Experimental proof statements

The genesis proof public inputs are: `name_id`, owner `ak`, successor
commitment, sequence, record digest, lease expiry, status, terminal height,
state digest, registration-input nullifier, successor future nullifier, and
`minimum_bond_zatoshis`. Private witnesses are the real registration note
opening, its FVK/scope and spend-authorizing scalar, the successor note
opening, and the non-negative `registration_value - minimum_bond` delta.

The transition proof public inputs are: name and owner, predecessor commitment
and action nullifier, successor commitment, operation code, both sequences,
record digests, lease expiries, statuses, terminal heights, operation height,
both state digests, predecessor `StateRef` digest, transition binding, and the
successor future nullifier. Private witnesses are both real note openings, the
predecessor FVK/scope and spend-authorizing scalar. The circuit proves the
successor recipient uses the same authority, `rho_successor = NF_predecessor`,
and exact private value preservation.

## Discovery schedule

There is exactly one deterministic anchor height in every epoch:

```text
slot(name_id, epoch) = epoch * E + H_slot(name_id || epoch) mod E
```

`H_slot` uses a v2-only domain. A `REVEAL` or `RENEW` is valid only at that
exact height. The experiment requires `commit_ttl >= 2E - 1`,
`refresh_deadline >= 2E - 1`, and `lease_duration > 3E - 1`. The last
relation gives an owner that misses one slot a further scheduled renewal
opportunity before lease loss.

For consecutive slots `s_e` and `s_(e+1)`:

```text
s_(e+1) - s_e = E + offset_(e+1) - offset_e <= 2E - 1
```

Therefore the formal maximum inter-anchor gap is `2E - 1`, not `E`. An anchor
at `a` remains payable through `a + refresh_deadline - 1`; fresh candidates
are exactly those in that window. The resolver replays only this name's
visible operations in canonical block/transaction/message order across that
bounded tail. Invalid Names messages are deterministic rejections; missing or
structurally inconsistent canonical blocks remain fatal acquisition errors.

For the second following opportunity:

```text
s_(e+2) - s_e = 2E + offset_(e+2) - offset_e <= 3E - 1
```

`3E - 1` is the tight recovery bound; the earlier `2(2E - 1)` expression was
safe but unnecessarily conservative.

## Bounded reset for hidden COMMITs

Let `D` be `lease_duration`, `G` grace, and `R` reuse delay. An anchor at `a`
can leave active/grace state unavailable only until `a + D + G`. RELEASE can
be accepted no later than `a + D - 1`, then blocks only until
`a + D - 1 + R`. The reset horizon is therefore:

```text
H = max(D + G, D - 1 + R)
```

At height `C`, an anchor at or before `C - H` cannot make the name unavailable;
only a strictly newer accepted REVEAL/RENEW can. Hidden COMMIT eligibility is
evaluated at its own canonical height when REVEAL discloses the preimage.
Normal reclaim supplies the exact claimable terminal `StateRef`. A
no-predecessor REVEAL requires no accepted anchor newer than `C - H`; before a
full horizon exists, search begins at activation without a trusted snapshot.

The no-predecessor path is deliberately conservative: a released lineage
inside the horizon can require an unaware caller to wait for reset. A caller
with the authenticated terminal reference retains exact claimability timing.
Reset probes only scheduled anchor blocks and authenticates encountered
per-name predecessor chains; it never needs a global nonmembership index.
Only canonically accepted anchors count. Proof-valid shadow REVEALs or RENEWs
descending from them do not block reset eligibility.

## Authenticated predecessor-position chain

The state note does not contain its own producer transaction ID. After a
transaction becomes canonical, its `(height, tx index, txid, action index,
carrier-message index, commitment, future nullifier)` becomes the `StateRef` carried by the next
operation. Resolver lineage verification follows those references through
ordinary canonical block and transaction acquisition until it reaches an
**accepted** REVEAL and its **accepted** COMMIT.

For a referenced transition, the resolver first authenticates the accepted
predecessor producer, validates the transition, and applies it at its exact
canonical message position. Zcash's one-time nullifier rule excludes competing
canonical descendants of that accepted predecessor. REVEAL needs extra work:
independent replacements do not share a state-note nullifier. The resolver
therefore replays the bounded same-name window ending at the exact REVEAL
message and accepts it only against the name state immediately before it.

COMMIT references also include their exact carrier-message index. Fresh
verification reconstructs the finite pending-commitment set across the TTL
window, including accepted consumes, so a REVEAL cannot cite a rejected
duplicate COMMIT merely because identical bytes occur elsewhere. A replacement
producer on a reorg is absent, has different canonical position data, or fails
this accepted-producer replay on the new branch.

## Experimental wire and footprint

Operations use an explicit `CNV2 || 0x01` prefix followed by canonical compact
binary encoding. The decoder re-encodes and compares bytes, and the prefix is
disjoint from frozen v1. Generic CPV1 framing is unchanged. With the current
real 4,640-byte Halo2 proofs and a 64-byte record fixture, exact footprints are:

| operation | envelope bytes | proof bytes | CPV1 frames | Ironwood actions |
| --- | ---: | ---: | ---: | ---: |
| REVEAL | 5,056 | 4,640 | 11 | 1 |
| UPDATE | 4,950 | 4,640 | 10 | 1 |
| RENEW | 4,949 | 4,640 | 10 | 1 |

The unchanged CPV1 maximum is 16,093 bytes / 32 frames. A typical v2 state
operation therefore uses one Ironwood action and about 3% of a hypothetical
330-action block budget; 330 is instrumentation context, not a Coppice rule.
Final epoch, refresh, lease, grace, reuse, TTL, and rewind-retention values must
be selected in post-NU7 wall-clock terms if target spacing changes; this
experiment does not freeze them.

The Names-side adapter consumes ordinary `ApplicationBlockContext` and
`ApplicationTransactionContext` values: exact Core tx position, ordered
Ironwood effects, and the already-routed CA01 payload. It decodes an ordered
v2 message list and produces the same `CanonicalBlock` used by replay and the
fresh resolver. Malformed payloads produce no typed Names message but their
ordinary nullifier effects remain visible, so they can still abandon a spent
current note. This requires no Core change or Names-specific RPC.

## Transaction construction boundary

The current Orchard builder randomizes spend and output action positions and
returns their final indices in `BundleMetadata`. A memo cannot safely insert
that index after the output commitment has been finalized. The sound existing
construction is therefore an unpadded bundle with exactly one requested
Ironwood spend and one requested Ironwood output: there is exactly one action,
so the registration/state spend and successor commitment are necessarily
paired at index zero. Fees or unrelated value should use non-Ironwood inputs
and outputs for this first qualification path. General multi-action wallet
construction still needs a builder API that deliberately pairs one requested
spend/output before shuffling complete pairs, or a later protocol change to
identify a unique `(nullifier, commitment)` action pair without carrying an
index. No retry-until-random-order workaround is permitted.
