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
3. A replacement commitment must be mined no earlier than the height at which
   the old name became claimable. This preserves the v1 anti-precommit rule.
4. Active state is payable only while `height < lease_expiry`. Missed renewal
   produces an explicit expired/grace result; it does not silently resolve the
   old record as active.
5. An expired name becomes claimable at `lease_expiry + grace_period`. An
   explicitly released name becomes claimable at `terminal_height +
   reuse_delay`; these are deliberately separate terminal policies.

## Discovery schedule

There is exactly one deterministic anchor height in every epoch:

```text
slot(name_id, epoch) = epoch * E + H_slot(name_id || epoch) mod E
```

`H_slot` uses a v2-only domain. A `REVEAL` or `RENEW` is valid only at that
exact height. The experiment requires `commit_ttl >= 2E - 1` and
`lease_duration > 2E - 1`.

For consecutive slots `s_e` and `s_(e+1)`:

```text
s_(e+1) - s_e = E + offset_(e+1) - offset_e <= 2E - 1
```

Therefore the formal maximum inter-anchor gap is `2E - 1`, not `E`. A fresh
resolver probes the recent scheduled slots covering that bound, authenticates
the newest valid `REVEAL` or `RENEW`, and scans only the canonical tail after
that anchor.

## Authenticated predecessor-position chain

The state note does not contain its own producer transaction ID. After a
transaction becomes canonical, its `(height, tx index, txid, action index,
commitment)` becomes the `StateRef` carried by the next operation. Resolver
lineage verification follows those references through ordinary canonical block
and transaction acquisition until it reaches a validated `REVEAL` and its
validated `COMMIT`. A replacement producer on a reorg is therefore absent or
has a different action commitment, making the old reference invalid on the new
canonical branch.
