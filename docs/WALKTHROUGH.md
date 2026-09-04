# Coppice Names Walkthrough: The Life of One Name

Status: explanatory companion to the [protocol specification](SPECIFICATION.md)
(normative) and the [whitepaper](WHITEPAPER.pdf) (design and evidence). This
document changes nothing normative; every rule cited here is stated in the
specification and illustrated here with concrete numbers.

This walkthrough follows a single name — `alice` — from key derivation through
registration, resolution by a stranger, renewal, release, cooldown, and
recovery. Each step shows what the wallet builds, what lands in the canonical
chain, what any observer can see, and which checks a resolver applies.

## 0. The illustrative deployment

All numbers use the candidate production profile from
[SPEC §3.1](SPECIFICATION.md#31-timing-profiles). The activation height and the
derived values below are **illustrative**; a real deployment freezes them in
its deployment identity.

| Quantity | Value |
| --- | --- |
| Activation height `A` | 1,000,000 (illustrative) |
| Epoch `E` | 1,152 blocks |
| Name window `W` | 24 blocks |
| COMMIT maturity `M` | 24 blocks |
| COMMIT TTL `T` | 192 blocks |
| Lease `L` | 250,000 blocks |
| Cooldown | 1,152 blocks (= one epoch) |
| Bond | exactly 1 ZEC (100,000,000 zatoshis) |

The name is `alice`. Its canonical form is the bare label `alice` (1..63 bytes
of `[a-z0-9-]`, no leading or trailing hyphen); `alice.zec` is presentation
syntax only [SPEC §2.1](SPECIFICATION.md#21-names). From the label, the wallet
derives the nonzero Pallas field element `NameId` (BLAKE2b-512 → `ToPallas`
with counter retry) and, together with the deployment identifier, the public
name route — a 43-byte index-zero Orchard receiver derived from a
BLAKE2b-separated diversifier key and incoming-viewing-key field
[SPEC §5](SPECIFICATION.md#5-publication-and-discovery).

Assume the schedule places alice's window at offset **617** inside every epoch:

```text
window(alice, e) = [A + e*1152 + 617, A + e*1152 + 617 + 24)
window(alice, 0) = [1,000,617, 1,000,641)
window(alice, 1) = [1,001,769, 1,001,793)
window(alice, 2) = [1,002,921, 1,002,945)
window(alice, 3) = [1,004,073, 1,004,097)
```

Every resolver computes exactly these windows from `(deployment_id, NameId)` —
no secret, no service [SPEC §4](SPECIFICATION.md#4-height-schedule).

## 1. Wallet setup and derivation

Alice's wallet holds a normal 64-byte BIP-39 seed. Wallet policy (non-normative
[SPEC §13](SPECIFICATION.md#13-wallet-recovery-policy-non-normative)) derives:

```text
seed ──▶ Names master ──▶ hidden per-name authority for (deployment, "alice")
                              ├──▶ epoch COMMIT secrets (one per epoch)
                              └──▶ successor note seeds (bound to canonical
                                   operation data)
```

The per-name Orchard spending authority is never published anywhere. The
epoch COMMIT secret will open the COMMIT; the successor note seeds will make
every bond note deterministic and recoverable. Nothing in this step touches
the chain.

## 2. COMMIT — hiding the intent (height 1,000,500)

At height 1,000,500 the wallet publishes a **COMMIT**:

- the bulletin is the 38-byte encoding `CNV2 ‖ 0x01 ‖ 0x00 ‖ commitment[32]`
  [SPEC §6](SPECIFICATION.md#6-operation-codec);
- the commitment opens, inside the proof system only, to
  `(deployment_id, NameId, target_epoch, hidden_owner_commitment, nonzero_secret)`
  [SPEC §8.1](SPECIFICATION.md#81-commit);
- the bulletin travels in CPV1 framing inside a CA01 envelope for
  `(coppice.names, version 2)`, carried by a **zero-value** Orchard output
  addressed to the deployment's *generic* rendezvous route
  [SPEC §5](SPECIFICATION.md#5-publication-and-discovery);
- the transaction is otherwise ordinary and pays a normal Zcash fee. In the
  performance study's synthetic transport model, COMMIT-shaped transactions
  are about 3 Orchard-family actions.

The 1 ZEC bond is **not** involved yet; carrier notes never hold the bond.

**What observers see:** an ordinary shielded transaction. No name, no owner,
no target address. A copied COMMIT reveals nothing and commits no one —
COMMIT is not a reservation.

The reducer stores `CommitRef(height 1,000,500, tx_index, txid) → Commitment`,
prunable after the TTL [SPEC §8.1](SPECIFICATION.md#81-commit).

## 3. REVEAL — registering (height 1,000,630)

Alice's wallet waits for maturity and its window. The COMMIT at `c = 1,000,500`
is usable by a REVEAL at `r` when `M ≤ r − c < T`
[SPEC §4](SPECIFICATION.md#4-height-schedule):

```text
mature from:  1,000,524   (c + M)
expired at:   1,000,692   (c + T, exclusive)
alice window (epoch 0): [1,000,617, 1,000,641)
overlap: [1,000,617, 1,000,641) ∩ [1,000,524, 1,000,692)  ✓
```

At height **1,000,630** (`r − c = 130`), inside the window, the wallet
publishes a **REVEAL**:

- the bulletin carries the canonical name `alice`, the exact `CommitRef`
  (height 1,000,500, transaction index, transaction ID), the record's UA
  (a canonical ZIP-316 Unified Address, ≤ 1,024 bytes, any receiver
  composition), the designated action index, the successor note's future
  nullifier, and the 4,704-byte Halo2 proof [SPEC §6](SPECIFICATION.md#6-operation-codec);
- the same transaction's **designated action** creates the bond note `B1`:
  exactly 1 ZEC, controlled by the hidden authority
  [SPEC §8.2](SPECIFICATION.md#82-reveal);
- the bulletin is carried by zero-value notes addressed to **alice's public
  name route** — not the generic route. Anyone who knows the name `alice` can
  derive this route and inspect her windows;
- in the performance study's synthetic transport model, REVEAL-shaped
  transactions are about 13 Orchard-family actions.

**What observers see:** the name `alice`, the UA, the schedule epoch, the
canonical references, and name-routed traffic. The spending authority, the
COMMIT secret, and all note plaintexts remain hidden.

**Checks the reducer applies, in order** (cheap before expensive
[SPEC §8.2](SPECIFICATION.md#82-reveal), [SPEC §15](SPECIFICATION.md#15-rejection-taxonomy)):

1. codec: magic, revision, tag 1, no trailing bytes, canonical embedded values;
2. transport: carrier value zero, correct application identity, **name route**
   (a REVEAL on the generic route is inert);
3. schedule: `1,000,630 ∈ window(alice, 0)` ✓;
4. reference: the `CommitRef` exists (the resolver admits the referenced
   COMMIT atomically with this block), is mature (`130 ≥ 24`) and unexpired
   (`130 < 192`) ✓;
5. shape: the declared action index exists in this transaction ✓;
6. proof: the REVEAL statement — deployment, tag, NameId, epoch, COMMIT value,
   CommitRef, UA, action index, action nullifier, action commitment,
   successor future nullifier, bond value — verifies against the
   replay-constructed facts ✓;
7. lineage: no existing head for `alice`, or it is `Claimable` ✓.

An attacker who copied Alice's bulletin byte-for-byte fails at step 6: the
proof binds *her* hidden owner and *her* successor note; substituting a
different note or owner breaks the statement. An attacker who published their
own valid REVEAL for `alice` at 1,000,635 would fail at step 7 — the head
already exists and is `Active`, not `Claimable`. Canonical order, not
commitment order, decides [SPEC §8.2](SPECIFICATION.md#82-reveal).

The accepted head is now:

```text
producer:  StateRef(1,000,630, tx_index, txid, action_index)
UA:        the published Unified Address
lease to:  1,000,630 + 250,000  = 1,250,630
epoch:     0
```

## 4. A stranger resolves `alice` (height 1,001,800)

A payer's wallet — no prior knowledge beyond the string `alice.zec` — resolves
the name [SPEC §11](SPECIFICATION.md#11-exact-name-resolution):

1. canonicalize to `alice`; derive `NameId`, the name route, and the eligible
   windows;
2. inspect only alice's windows in authenticated compact evidence. A
   synchronized wallet already holds this in its rolling cache (~143 MB for a
   six-month horizon in the measured baseline; see the whitepaper's
   performance section) — no name-specific remote query is needed;
3. try-decrypt name-route candidates: the REVEAL at 1,000,630 appears;
4. follow its `CommitRef` to the one historical COMMIT (height 1,000,500),
   fetch and authenticate it against compact effects;
5. apply the checks from step 3 above — all pass;
6. replay authenticated nullifiers through the canonical tail. The REVEAL
   published `B1`'s future nullifier; the tail shows it was spent at
   1,001,780 — so the resolver reads that block's name-route window, finds the
   REFRESH (below), and continues the lineage to `B2`, whose future nullifier
   has **not** appeared;
7. conclusion: lifecycle `Active`, head produced by the REFRESH, return the
   **current UA**.

Because the resolver ran the same deterministic rules over the same
authenticated data, an exact resolver and a full replay agree — lifecycle,
record, head, and producer [SPEC §11](SPECIFICATION.md#11-exact-name-resolution).
If the name had never been registered, step 3 would find no candidate and the
result would be `Missing` — an absence, not an error.

## 5. REFRESH — update and renewal in one operation (height 1,001,780)

Months later the wallet rotates the record's UA. Change of address and lease
renewal are deliberately **one** operation [SPEC §8.3](SPECIFICATION.md#83-refresh):

```text
window check:  1,001,780 ∈ window(alice, 1) = [1,001,769, 1,001,793)  ✓
epoch check:   inclusion epoch 1 > producer epoch 0                    ✓
lineage:       predecessor is the exact current head, Active, and the
               transaction spends B1 (its future nullifier)            ✓
proof:         B1 and B2 both exactly 1 ZEC, same hidden authority,
               statement binds predecessor StateRef, both nullifiers,
               the new UA, and the successor effects                   ✓
```

The designated action pair spends `B1` and creates `B2` (1 ZEC, same hidden
authority); the bulletin rides the name route. The head is replaced and the
lease restarts **in full** from 1,001,780 (expiry 1,251,780). A REFRESH
referencing an older, stale head would fail the exact-predecessor check; a
REFRESH inside epoch 0 would fail the strictly-later-epoch check.

**Transfer is impossible by construction:** the proof requires the *same*
hidden authority on both sides, and the authority is seed-derived — there is
no operation that hands the record to another key.

## 6. Release — an ordinary spend (height 1,002,000)

There is no `RELEASE` bulletin. Alice releases the name by spending bond note
`B2` in an ordinary Ironwood transaction that returns 1 ZEC (minus the fee) to
her own wallet [SPEC §9](SPECIFICATION.md#9-release-expiry-cooldown-and-reclaim).

- No window applies; any height works.
- The reducer observes `B2`'s future nullifier (published back in the REFRESH)
  appear in canonical history and marks the head terminal at 1,002,000. This
  is why release needs no announcement: custody of the record *is* custody of
  the note, so the spend itself is the event.
- Anyone watching alice's lineage can see the termination — that is intended.

**Cooldown** begins immediately: from 1,002,000 until
1,002,000 + 1,152 = **1,003,152**, `alice` resolves to nothing and no
replacement can be installed — not even by Alice
[SPEC §9](SPECIFICATION.md#9-release-expiry-cooldown-and-reclaim). The
interval is a visible, deterministic quarantine against abrupt impersonation,
identical for voluntary release and natural expiry (expiry would have used
`1,251,780` had she never acted).

**Reclaim by a new registrant:** claimability starts at 1,003,152. Alice's
windows in epoch 2 ([1,002,921, 1,002,945)) fall *inside* the cooldown and are
unusable; the first eligible window is epoch 3, **[1,004,073, 1,004,097)**. A
new registrant publishes a fresh COMMIT (maturity and TTL relative to their
own REVEAL), then the first canonically valid REVEAL in that window takes the
name. The former owner has no protocol priority.

## 7. Recovery — the seed is the backup

Alice's device is lost. On a new wallet [SPEC §13](SPECIFICATION.md#13-wallet-recovery-policy-non-normative):

1. restore the 64-byte seed;
2. supply the nonsecret list of owned names: `alice`;
3. the wallet re-derives the Names master, the hidden authority for
   `(deployment, "alice")`, and the epoch COMMIT secrets;
4. it scans alice's windows for her published REVEAL/REFRESH chain and
   re-derives each successor note deterministically from canonical public
   operation data;
5. it matches the derived nullifiers and note commitments against the chain to
   confirm the bond notes are unspent and marks the current one managed.

No sidecar secret, no registry snapshot, no trust in a third-party export.
Recovery is explicit wallet behavior — resolving an arbitrary name never
silently attempts it.

## 8. Failure gallery

Every rejection below is mandatory; the full taxonomy with reference variant
names is [SPEC §15](SPECIFICATION.md#15-rejection-taxonomy).

| Attempt | Outcome |
| --- | --- |
| REVEAL published on the generic route, or COMMIT on a name route | Inert at transport (`WrongRoute`); its action effects still count for spentness |
| REVEAL outside `window(alice, e)` | Rejected before any proof work (`schedule` stage) |
| REVEAL referencing an immature or expired COMMIT | Rejected (`maturity ≤ r − c < TTL`) |
| Copied REVEAL substituting a different bond note or owner | Proof fails: the statement binds the original hidden authority and note |
| Second valid REVEAL while a head is `Active` | Rejected: no head, or head `Claimable`, is required |
| REFRESH citing a stale head, or inside the predecessor's epoch | Rejected: exact current predecessor, strictly later epoch |
| Carrier note carrying value, or wrong application identity | Rejected at transport before decoding deeper |
| Trailing bytes, wrong tag, wrong proof length | Rejected at codec |
| A proof-valid 1 ZEC note spending/replacing state without a valid bulletin | Irrelevant: the reducer marks heads spent by authenticated nullifiers even when the bulletin is missing or invalid — accepted lineage, not physical notes, is the record |

## 9. The bill

| Item | Cost |
| --- | --- |
| Transactions published | 1 COMMIT + 1 REVEAL + (1 REFRESH per renewal) + 1 release, all at normal Zcash fees |
| Capital locked | Exactly 1 ZEC per active name, refundable on release; never burned, never paid to an operator |
| Registration latency | Bounded by schedule: maturity (24 blocks) + up to one epoch to the next window |
| Renewal cadence | At least once per 250,000-block lease; each REFRESH restarts the lease in full |
| Release latency | Immediate (ordinary spend); name then sits out one epoch of cooldown |
| Resolver storage | ~143 MB rolling compact evidence for a six-month horizon (measured baseline), or less with the sparse fallback; derived, reconstructible, never authority |

## 10. Where to go next

- [SPECIFICATION.md](SPECIFICATION.md) — normative rules for every step above.
- [WHITEPAPER.pdf](WHITEPAPER.pdf) / [WHITEPAPER.tex](WHITEPAPER.tex) — why the
  protocol is built this way: trust model, threat analysis, privacy, economics,
  and measured performance.
- [../test-vectors/replacement_protocol.json](../test-vectors/replacement_protocol.json)
  and its [manifest](../test-vectors/MANIFEST.md) — the frozen conformance
  artifact, with independent Rust and Python consumers.
