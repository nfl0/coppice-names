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
   transaction ID, action index, and commitment.
2. `REVEAL` is the only genesis of a lineage. Its state-note commitment must
   equal the commitment of the selected canonical Ironwood action, and its
   genesis proof must authenticate the state data and note-control relation.
3. Every non-genesis operation references the exact producer position of its
   predecessor. The predecessor action commitment must equal the referenced
   commitment.
4. A transition proof binds one predecessor nullifier and one successor
   commitment to the same action index. It proves the predecessor note
   commitment, its nullifier, the successor note commitment, and
   `rho_successor = nullifier_predecessor`.
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

## Registration and lease invariants

1. A commitment is valid only after the commitment block and only through its
   checked TTL. A reveal in the commitment block is rejected.
2. A reveal must be at the name's deterministic anchor slot. The commitment
   carries the name, owner, bond identity, record digest, and fresh secret;
   proof artifacts are not the hidden semantic preimage. The retained
   `FrozenV1BondProofVerifier` additionally requires `record` to be a
   canonical v1 Unified Address; an alternate experimental bond verifier may
   define a different record encoding without changing the state-note proof.
   V2 has no `active_bonds` map or bond-tag uniqueness rule: that would make
   fresh name-local resolution depend on unrelated names. The retained v1
   proof is transitional registration evidence, not a persistent v2 global
   bond state.
3. A replacement commitment must be mined no earlier than the height at which
   the old name became claimable. This preserves the v1 anti-precommit rule.
4. Payability/currentness and lease ownership are separate. With last anchor
   `a`, a record is payable only while `height < a + refresh_deadline`. It is
   stale (never payable) until `lease_expiry`, but its owner may still make a
   scheduled RENEW before that lease boundary.
5. An expired name becomes claimable at `lease_expiry + grace_period`. An
   explicitly released name becomes claimable at `terminal_height +
   reuse_delay`; these are deliberately separate terminal policies.

## Discovery schedule

There is exactly one deterministic anchor height in every epoch:

```text
slot(name_id, epoch) = epoch * E + H_slot(name_id || epoch) mod E
```

`H_slot` uses a v2-only domain. A `REVEAL` or `RENEW` is valid only at that
exact height. The experiment requires `commit_ttl >= 2E - 1`,
`refresh_deadline >= 2E - 1`, and `lease_duration > 2(2E - 1)`. The last
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

## Authenticated predecessor-position chain

The state note does not contain its own producer transaction ID. After a
transaction becomes canonical, its `(height, tx index, txid, action index,
commitment)` becomes the `StateRef` carried by the next operation. Resolver
lineage verification follows those references through ordinary canonical block
and transaction acquisition until it reaches a validated `REVEAL` and its
validated `COMMIT`. A replacement producer on a reorg is therefore absent or
has a different action commitment, making the old reference invalid on the new
canonical branch.
