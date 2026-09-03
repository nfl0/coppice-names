# Coppice Names Protocol Specification

Status: implemented replacement protocol; not deployed.

This document specifies the current Coppice Names protocol implemented by
`coppice-names`. It describes the application identified by the canonical
identity `coppice.names` and CA01 application version `2`. There is no legacy
compatibility mode in this specification.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe protocol
requirements. Explanatory wallet behavior is explicitly labelled as wallet
policy and is not part of protocol validity.

## 1. Goals and boundaries

Coppice Names maps a canonical bare name to a canonical Zcash Unified Address
(UA). The protocol provides:

- shielded ownership through a hidden, per-name Orchard authority;
- an exact 1 ZEC bond that remains owned by the registrant;
- commit/reveal registration resistant to simple mempool front-running;
- deterministic, name-specific operation windows;
- address update and lease renewal through one `REFRESH` operation;
- release through an ordinary Ironwood spend, without burning ZEC;
- arbitrary exact-name resolution without a trusted global Names index; and
- deterministic replay and rollback under Zcash's canonical chain.

Zcash consensus remains the sole authority for transaction validity, ordering,
spentness, block linkage, and fork choice. Coppice authenticates the compact and
full-transaction data passed to Names. Names adds application validity; a valid
Zcash transaction or valid proof is not necessarily an accepted Names
operation.

Names does not introduce a sidechain, token, fee market, third-party resolver,
trusted publisher, global consensus root, or transparent-transaction
requirement. Zcash transaction fees are independent anti-spam fees.

## 2. Canonical values

### 2.1 Names

The protocol value is the bare label. `.zec` is presentation syntax only.

A canonical name:

- is 1 through 63 ASCII bytes;
- contains only lowercase `a` through `z`, digits, and `-`;
- does not begin or end with `-`; and
- contains no dot.

Parsers MAY accept one lowercase `.zec` suffix and MUST remove it before using
the name as protocol data. Uppercase input and `.ZEC` are not canonical.

The nonzero Pallas base-field `NameId` is derived by trying counters `0..255`:

```text
input = u8(name_length) || name_bytes || u8(counter)
candidate = ToPallas(BLAKE2b-512(personal="CoppiceN2Name", input))
```

The first nonzero candidate is the `NameId`. Exhaustion is an error.

### 2.2 Unified Addresses

A record MUST be a canonical ZIP-316 Unified Address for the deployment's
Zcash network. Re-encoding the decoded address MUST reproduce the input bytes.
The encoded address MUST be nonempty and at most 1,024 bytes.

Any canonical UA receiver composition is permitted, including a UA containing
a transparent receiver. Names does not select a receiver; the consuming wallet
applies its normal Zcash receiver policy.

### 2.3 Field elements and references

Commitments and identifiers use canonical 32-byte Pallas base-field encodings.
`NameId` and `Commitment` MUST be nonzero. Other typed field elements MAY be
zero unless a relation states otherwise.

`CommitRef` identifies exactly one canonical transaction:

```text
(height: u32, tx_index: u32, txid: [u8; 32])
```

`StateRef` identifies exactly one canonical Ironwood action:

```text
(height: u32, tx_index: u32, txid: [u8; 32], action_index: u32)
```

Integer fields are encoded big-endian. Transaction IDs are the exact canonical
bytes supplied by Coppice replay, not display-order strings.

## 3. Deployment identity

One deployment fixes:

- the validated Coppice Core runtime identity;
- Names application identity and application version;
- activation height;
- every schedule duration;
- the exact 1 ZEC bond amount;
- maximum name and UA lengths; and
- the REVEAL and REFRESH verifier identities.

The deployment preimage is exactly 173 bytes:

| Field | Encoding |
| --- | --- |
| magic | `CND2` |
| Core runtime ID | 32 bytes |
| Names application ID | 32 bytes, derived from `coppice.names` |
| application version | `u16` big-endian, value `2` |
| activation height | `u32` big-endian |
| epoch blocks | `u32` big-endian |
| window blocks | `u32` big-endian |
| COMMIT maturity | `u32` big-endian |
| COMMIT TTL | `u32` big-endian |
| lease blocks | `u32` big-endian |
| cooldown blocks | `u32` big-endian |
| bond zatoshis | `u64` big-endian, value `100000000` |
| maximum name bytes | `u8`, value `63` |
| maximum UA bytes | `u16` big-endian, value `1024` |
| REVEAL verifier ID | 32 bytes |
| REFRESH verifier ID | 32 bytes |

The deployment ID is:

```text
BLAKE2b-256(personal="CoppiceN2Dep", canonical_deployment_preimage)
```

Verifier IDs bind the verifier-suite manifest, operation tag, Halo2 parameter
exponent, fixed proof length, and generated verifying-key fingerprint. A
deployment MUST NOT accept a caller-selected verifier.

### 3.1 Timing profiles

The current profiles are:

| Parameter | Production candidate | Regtest |
| --- | ---: | ---: |
| epoch | 1,152 blocks | 32 blocks |
| name window | 24 blocks | 4 blocks |
| COMMIT maturity | 24 blocks | 4 blocks |
| COMMIT TTL | 192 blocks | 24 blocks |
| lease | 250,000 blocks | 128 blocks |
| cooldown | 1,152 blocks | 32 blocks |

The production values target approximately daily operation opportunities and
a roughly six-month lease under current Ironwood block timing. Regtest is
deliberately accelerated. Because all durations are deployment-ID inputs,
Regtest and production messages are cryptographically separated.

Valid schedules satisfy:

```text
0 < window <= maturity < TTL < epoch < lease
cooldown == epoch
```

## 4. Height schedule

For activation height `A`, epoch size `E`, window size `W`, deployment `D`, and
name identifier `N`:

```text
epoch(h) = floor((h - A) / E), for h >= A
epoch_start(e) = A + e * E
offset(N) = LE64(BLAKE2b-256(personal="CoppiceN2Off", D || N)[0..8])
            mod (E - W + 1)
window(N, e) = [epoch_start(e) + offset(N),
                epoch_start(e) + offset(N) + W)
```

Intervals are half-open. A REVEAL or REFRESH for `N` is eligible only when its
canonical inclusion height is in `window(N, epoch(height))`.

A COMMIT included at `c` is usable by a REVEAL included at `r` only when:

```text
c >= activation_height
maturity <= r - c < TTL
```

Thus the TTL endpoint is exclusive. COMMITs are pruned when their age reaches
the TTL.

## 5. Publication and discovery

All Names bulletins use Coppice CPV1 framing inside a CA01 application envelope
for `(Names application ID, version 2)`.

Every carrier note MUST have value zero. The 1 ZEC bond is a distinct,
designated Ironwood action; carrier notes never hold or burn the bond.

Routes are fixed by operation type:

- `COMMIT` uses the deployment's validated generic Coppice rendezvous. It does
  not reveal which name it targets.
- `REVEAL` and `REFRESH` use a public route derived from `(deployment_id,
  NameId)`. Anyone resolving an exact name can derive this route without a
  secret or service.

The name route derives a BLAKE2b-separated Orchard diversifier key and nonzero
incoming-viewing-key field, then uses the index-zero Orchard receiver. Exact
derivation is implemented by `NameRoute::derive` and frozen by the conformance
vectors.

A complete replay may inspect Core-authenticated full transaction bytes at both
the generic route and every name route. An exact-name resolver need not acquire
unrelated traffic at the generic route: it first discovers a REVEAL in the
requested name's deterministic window, then follows that REVEAL's bounded
`CommitRef` to the one historical compact transaction it names. The referenced
full transaction is authenticated against that compact transaction's txid and
Ironwood effects before its COMMIT is admitted to the reducer. The referenced
COMMIT is semantically identical to observing it during forward replay.

Exactly one correctly routed Names operation may survive inspection. Ambiguous,
malformed, unauthenticated, nonzero-value, or wrong-route bulletins are inert as
Names operations. Their authenticated Ironwood action effects MUST remain
visible to spentness processing. A resolver MUST NOT trust an unauthenticated
transaction locator or COMMIT cache.

## 6. Operation codec

Every operation begins with:

```text
"CNV2" || revision=1 || operation_tag
```

The tags are `0=COMMIT`, `1=REVEAL`, and `2=REFRESH`.

Variable-length values use `u8` name length or `u16` UA length followed by the
exact bytes. Integers are big-endian. Trailing bytes are forbidden. Proof
lengths are fixed by the deployment; the current REVEAL and REFRESH proofs are
both 4,704 bytes.

```text
COMMIT = commitment[32]

REVEAL = name
       || commit_height:u32 || commit_tx_index:u32 || commit_txid[32]
       || ua
       || designated_action_index:u32
       || successor_future_nullifier[32]
       || reveal_proof[deployment.reveal_proof_bytes]

REFRESH = name
        || predecessor_height:u32 || predecessor_tx_index:u32
        || predecessor_txid[32] || predecessor_action_index:u32
        || ua
        || designated_action_index:u32
        || successor_future_nullifier[32]
        || refresh_proof[deployment.refresh_proof_bytes]
```

## 7. Canonical replay model

The reducer begins immediately before the activation block with the
independently authenticated activation-parent hash. It MUST apply every block
in increasing height order, require exact previous-hash continuity, require
strictly increasing transaction indexes, and require action indexes `0..n-1`
inside each transaction.

Transactions are processed in canonical block order. Before each transaction,
and once after the block, heads whose lease has reached expiry are marked
terminal. This ordering defines conflicts: the first canonically ordered valid
operation that changes a name can make later conflicting operations invalid.

For each transaction the reducer:

1. records which current heads are spent by any authenticated action
   nullifier;
2. attempts to apply its decoded Names operation; and
3. marks each still-current pre-transaction head from step 1 terminal at the
   block height.

Step 3 is applied even when the bulletin is missing, malformed, ambiguous, or
invalid. A proof-valid physical note can never replace accepted Names state by
itself.

## 8. Operations

### 8.1 COMMIT

A COMMIT publishes only a nonzero commitment. If its transaction is canonically
ordered and correctly routed, the reducer stores:

```text
CommitRef -> Commitment
```

It remains available until its TTL expires. COMMIT does not reserve a name and
does not create a name head.

The commitment opens to:

```text
(deployment_id, NameId, target_epoch, hidden_owner_commitment, nonzero_secret)
```

The owner commitment binds the hidden Orchard owner key material. The name,
owner, target epoch, and secret are not disclosed by COMMIT.

### 8.2 REVEAL

A REVEAL is accepted only if all of the following hold:

- there is no existing head, or the existing head is `Claimable`;
- inclusion is in the name's operation window;
- the exact referenced `CommitRef` exists and is mature but not expired;
- the declared action index exists in the same canonical transaction;
- the deployment-selected REVEAL proof verifies over the replay-constructed
  statement; and
- the statement and proof bind the designated action and successor bond.

The proof establishes knowledge of the hidden owner authority and nonzero
COMMIT secret, recomputes the referenced commitment, proves the successor note
is controlled by that authority, proves its value is exactly 1 ZEC, and binds
its action nullifier/rho, note commitment, and future nullifier to the public
statement.

An accepted REVEAL creates a new head whose producer is its exact `StateRef`,
whose lease expires at `inclusion_height + lease_blocks`, and whose producer
epoch is the inclusion epoch.

### 8.3 REFRESH

`UPDATE` and `RENEW` are wallet/UI names for the same protocol operation:
`REFRESH`. An unchanged UA renews; a different canonical UA updates and renews.

A REFRESH is accepted only if all of the following hold:

- the referenced predecessor is the exact current accepted head;
- that predecessor is `Active` at inclusion;
- inclusion is in the name's operation window;
- inclusion is in an epoch strictly later than the predecessor's producer
  epoch;
- the declared action exists and spends the predecessor's future nullifier;
- the deployment-selected REFRESH proof verifies; and
- the proof binds the predecessor and successor notes to the same hidden
  authority and to the canonical statement.

The proof establishes that both predecessor and successor are exactly 1 ZEC,
the predecessor commitment and nullifier match accepted state, the transaction
spends that predecessor, the successor is controlled by the same hidden owner,
and the successor commitment and future nullifier match the designated action.

An accepted REFRESH replaces the head and starts a full new lease from its
canonical inclusion height. A stale REFRESH cannot replace a newer head.
Transfer to a different hidden authority is not supported.

## 9. Release, expiry, cooldown, and reclaim

There is no `RELEASE` bulletin. The owner releases a name by making an ordinary
valid Ironwood spend of the current hidden 1 ZEC bond. The reducer recognizes
the canonical nullifier and sets `terminal_height` to the spend's block height.
The wallet normally returns the bond, minus the normal transaction fee, to an
internal receiver under the user's wallet authority.

A head is:

- `Active` before a terminal height;
- `Cooldown` from its terminal height, inclusive, until
  `terminal_height + cooldown_blocks`;
- `Claimable` at and after that claimable height; or
- `Missing` if no accepted head has ever existed.

Natural expiry uses `expiry_height` as the terminal height. During cooldown no
party, including the former owner, can REFRESH or install a replacement
REVEAL. Once claimable, the first canonically ordered valid REVEAL may replace
the old head. The former owner has no special protocol priority.

Cooldown is a uniform anti-impersonation quarantine, not an ownership grace
period. Its purpose is to force a visible non-resolving interval before a
recently terminated name can begin resolving to a different address. The same
rule applies whether termination resulted from natural expiry or an explicit
bond spend.

Resolution returns the UA only for `Active`. Cooldown and claimable results may
include head metadata for auditing but MUST NOT return it as a payable current
record.

## 10. Public proof statements

Each Halo2 proof exposes one Pallas field: a Poseidon-folded digest of typed
public facts reconstructed by replay.

The REVEAL statement binds, in order:

```text
deployment, operation tag, NameId, inclusion epoch, COMMIT value,
CommitRef, UA, action index, action nullifier, action commitment,
successor future nullifier, exact bond value
```

The REFRESH statement binds, in order:

```text
deployment, operation tag, NameId, predecessor StateRef,
predecessor commitment, predecessor future nullifier, predecessor epoch,
inclusion epoch, UA, action index, action nullifier, action commitment,
successor future nullifier, exact bond value
```

Byte strings and references are length-framed and domain-separated before
conversion to fields. REVEAL and REFRESH use distinct fold domains. The
current circuits use Halo2 IPA over Pasta with `k=11`; proof encoding and
verifying-key fingerprints are deployment-bound.

## 11. Exact-name resolution

`ExactResolver` applies the same reducer rules for one requested name. It:

- discovers candidate REVEAL/REFRESH bulletins only in the requested name's
  deterministic windows;
- authenticates the exact historical COMMIT referenced by a candidate REVEAL,
  provided the reference is older than the REVEAL and still within the bounded
  COMMIT TTL, and admits that evidence atomically with the REVEAL block;
- decodes and verifies REVEAL/REFRESH only for the requested name; and
- retains every authenticated Ironwood action nullifier because an otherwise
  unrelated transaction may spend the requested name's current bond.

Therefore exact replay and complete replay MUST produce the same lifecycle,
UA, head, and producer for the requested name at the same canonical tip.

The deterministic name schedule bounds expensive name-route trial decryption
and full-transaction acquisition to the name's short windows. A compact-block
ring covering the COMMIT TTL is sufficient to authenticate referenced COMMITs;
it is derived, nonsecret state and may instead be reconstructed with a bounded
historical compact-block request. Implementations SHOULD reject impossible
schedule, reference, transaction-shape, and lineage cases before invoking a
proof verifier.

The schedule does not make canonical-tail spentness disappear: action
nullifiers remain necessary to know whether the accepted head is current. A
compact nullifier journal or fast lookup index may accelerate this work, but it
MUST remain bound to the wallet's canonical scan and reorganization handling;
neither is an independent or trusted source of truth.

## 12. Reorganizations and cached state

Snapshots contain derived reducer state and rollback journals. They are not a
Zcash consensus commitment. A host restoring a snapshot MUST independently
bind it to the deployment, requested name, network, canonical height, and
canonical block hash, and MUST integrity-protect it or replay from an
authenticated checkpoint.

Applying a block with the wrong height or previous hash fails. Rollback removes
exactly the expected current tip and restores all COMMIT, head, terminal, and
branch-linkage changes recorded for that block. Journals MAY be discarded only
through a height independently finalized by the host.

An on-demand referenced COMMIT MUST be inserted in the same atomic reducer
transition as the block containing its candidate REVEAL. A failed block leaves
no referenced evidence behind, and rolling back that block removes evidence
that was not already present from forward replay.

## 13. Wallet recovery policy (non-normative)

The companion wallet crate implements a simple recoverable policy:

- derive a Names master from the 64-byte BIP-39 seed;
- derive a deployment- and name-separated Orchard spending key;
- derive the epoch COMMIT secret deterministically from that key; and
- derive each successor note from canonical public operation data.

Consequently a seed plus a nonsecret list of owned names can reconstruct the
hidden authority and candidate bond openings. No fragile sidecar secret is
required. These derivations are wallet policy, not alternative on-chain
validity rules.

Wallets SHOULD lock the managed 1 ZEC note against accidental ordinary sends,
track its authenticated commitment-tree position, and compose Names state and
wallet-tree changes atomically across scans and reorgs. The user always owns
the bond; the lock is local safety behavior.

## 14. Privacy properties and leakage

The owner Orchard key is never published. COMMIT hides the target name and
uses the shared generic Coppice route. REVEAL and REFRESH necessarily publish
the name, current UA, exact canonical references, schedule epoch, and
name-derived rendezvous traffic. Repeated operations for one name are publicly
linkable through the name and predecessor chain.

The protocol does not require a transparent output or transparent bond. A UA
may itself contain a transparent receiver because receiver composition is a
record-owner choice, not a Names ownership signal.

## 15. Conformance

`test-vectors/replacement_protocol.json` is the normative positive
conformance artifact for the current implementation. It freezes deployment,
verifier suite, route derivation, schedule, statements, real proofs, operation
encoding, and resolved heads. Its manifest records the vector-set digest and
the Rust and independent Python consumers.

Implementations MUST also reject malformed encodings, wrong routes, wrong
networks, stale predecessors, immature or expired COMMITs, wrong action
indexes, proof/statement substitution, wrong bond values, noncanonical chain
order, and wrong-branch snapshots. Passing proof verification alone is never
sufficient for Names acceptance.
