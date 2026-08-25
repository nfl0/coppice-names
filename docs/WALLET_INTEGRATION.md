# Wallet integration

`coppice-librustzcash` is the host/wallet adapter. It connects a Zcash wallet
and a canonical CompactBlock source to Coppice Core and Coppice Names v1 while
keeping wallet databases, accounts, note selection, and locks outside the
deterministic protocol state.

## Canonical-chain contract

The wallet or host is the sole fork-choice authority. The adapter reads the
host-selected canonical tip and freezes that height/hash for a reconciliation
pass. Mutation-capable workflows require an exact height and block-hash match;
a matching height with a different same-height block is not sufficient.

The adapter scans one shared Core/Names runtime for the wallet's canonical
history. Account-specific ownership and pending intent data are filtered at the
wallet boundary, so multiple accounts can share replay while retaining
independent `WalletAccountId` ownership and bond locks.

## Activation, candidates, and rebuild

Start from the configured activation checkpoint. Compact actions are first
classified against both the public rendezvous IVK and the exact configured
rendezvous receiver. Only a matching candidate causes a full transaction fetch.
Full extraction repeats the exact receiver check, then validates the full
transaction ID and its Ironwood commitments/nullifiers against the compact
record before CPV1/CA01 routing.

If a required full transaction is unavailable or inconsistent, the runtime
must not advance past the block. A shallow reorg rewinds Core and Names to the
retained common ancestor and replays the replacement history. A reorg older
than the retained horizon returns a rebuild requirement; the wallet rebuilds
from activation rather than inventing a local fork choice.

## Snapshots and progress

The composed runtime snapshot contains independently validated Core and Names
snapshots plus shared tip, identity, Ironwood-root, and Names-root metadata.
The host replaces it atomically after each successful block or rewind boundary.
Snapshot loading checks identities, tips, roots, retention, and application
compatibility. The old development-only monolithic snapshot format is rebuilt
from activation.

Wallet-local pending registrations and lock metadata are separate from replay
state. Pending records contain secret-bearing intent and account ownership and
must be treated as private local data; they are not a source of truth for
canonical Names replay.

## Registration, bonds, and locks

The registration workflow selects an owned Ironwood note that satisfies the
current freshness and value policy, derives its canonical `bond_tag`, and
records a pending registration for the owning account. It locks the selected
output before handing off the exact `COMMIT` carrier. After canonical COMMIT,
the wallet resolves the commit and prepares a fresh REVEAL proof against a
canonical Ironwood anchor. After canonical REVEAL, it must complete or abandon
the local pending intent; stale pending metadata can make later bond recovery
fail closed.

Lock reconciliation reconstructs desired locks from canonical active bond tags,
wallet-owned unspent Ironwood notes, and account-scoped pending intents. A
missing pending bond note is an explicit error, not a reason to silently drop a
lock. Ordinary input selection excludes protected locks; the explicit Break
Bond workflow uses the exact bond tag and owner-scoped lock to select the one
intended bond note.

## Protection modes

The adapter exposes three host-facing modes:

- `Enabled`: Names management, replay/resolution, lock reconciliation, and
  ordinary-spend protection;
- `GuardOnly`: replay/resolution and ordinary-spend protection, without
  management UI/workflows;
- `Off`: Coppice does not participate in that spend path; the ordinary wallet
  path is not given Coppice protection.

`Enabled` and `GuardOnly` compare the exact host tip and reconcile locks before
proposal construction, including locks cleared by an external generic wallet
operation. Protection is a fail-closed boundary. A wallet must not claim a
protected spend is safe while its canonical tip, inventory, account, or lock
state is unavailable.

## Resolution and payments

Resolution first requires an exact host/runtime tip match, normalizes optional
`.zec` presentation, and accepts only an `Active` canonical Names record. It
then validates the stored destination under the deployment's address rules.
Released, cooling-down, available, and bond-spent records are not payable.

## Viewing-key capability boundaries

Bond reconstruction requires local nullifier derivation. Full viewing and
spending capabilities can supply it; an incoming-only capability cannot and
must fail closed before it mutates inventory or locks. Wallets must derive and
retain note/nullifier facts locally rather than sending private identifiers to
remote indexers. A capability that can discover incoming outputs is not by
itself sufficient to classify or protect Coppice bonds.

See [`NAMES_V1.md`](NAMES_V1.md) for the application model and
[`IMPLEMENTATION.md`](IMPLEMENTATION.md) for the implemented adapter surfaces.
