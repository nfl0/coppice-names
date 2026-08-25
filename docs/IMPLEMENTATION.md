# Coppice implementation guide

This document maps the implemented production-authoritative architecture.
Normative protocol
bytes and state transitions are governed by `PROTOCOL_SPEC.md` and the files in
`test-vectors/`. The generic runtime boundary is defined by the Coppice Core
repository; this document defines only Names application implementation.
boundaries.

This code path is qualified locally; it is not a public Coppice Testnet or
Mainnet deployment, and no independent security audit has been completed.

## Workspace dependency direction

```text
coppice-core
    generic identities, CPV1, CA01, canonical replay, Core persistence

coppice
    depends on coppice-core
    Coppice Names v1 protocol, state, cryptography, application composition

coppice-librustzcash
    depends on coppice-core and coppice
    CompactBlock adapter, canonical reconciliation, wallet construction/policy
```

`coppice-core` must never depend on either other crate. The Names crate may
consume immutable Core contexts, but Core never imports an application state,
root, operation, policy parameter, or persistence type.

## Identity and activation model

Three non-interchangeable identities are used:

- `CoreRuntimeId` binds generic runtime version, Zcash network/domain, runtime
  activation, CPV1 context, and the validated rendezvous IVK/receiver pair.
- `ApplicationId + application_version` routes a CA01 payload.
- `NamesDeploymentId` is the unchanged historical Names deployment hash used
  by Names commitments, owner derivation/signatures, bond statements, and
  Names state roots.

`CoreRuntimeParameters::validate()` must succeed before a `CoreRuntimeId` can
be derived. Validation includes a cryptographic correspondence check between
the rendezvous IVK and receiver. Candidate classification and full extraction
also require the decrypted recipient to equal the exact configured receiver;
IVK-only decryptability is not enough. Names policy values are absent from the
Core preimage.

Runtime activation belongs to Core. Application activation belongs to the
application descriptor and may be later than runtime activation. Names v1
intentionally freezes the current relationship in which both heights are
equal; `validate_names_v1_core_compatibility` enforces that application-specific
constraint without deriving either identity from the other.

## Core transport and routing

Production transport is:

```text
CPV1 START binding = CoreRuntimeId
CPV1 payload        = CA01 || application_id || u16be(version) || payload
```

`coppice-core::transport` owns CPV1 framing and strict reconstruction.
`coppice-core::application` owns the strict CA01 envelope. The maximum CPV1
payload is 16,093 bytes and the maximum application payload is 16,055 bytes.

`CoreRuntime` decrypts frames only at its validated exact receiver, reconstructs
one CPV1 message, decodes the CA01 route, and emits an immutable message status.
Unknown routes remain structurally valid but are not reinterpreted. Malformed
transport or envelopes never fall back to naked Names decoding.

## Canonical Core replay

`CoreReplay` owns only Zcash-derived deterministic state:

- canonical tip and predecessor validation;
- canonical transaction ordering and transaction IDs;
- candidate/full-transaction consistency;
- ordered validated Ironwood nullifiers and commitments;
- Ironwood frontier, root, tree size, and retained checkpoints;
- block-atomic application;
- bounded Core rewind metadata.

Each accepted block emits `CoreBlockContext`. Each transaction context contains
the height, block hash, transaction index and ID, ordered Ironwood effects, and
candidate/full-transaction status. `CoreRuntime` pairs this with the routed
application message status. Core does not interpret application payload bytes.

Fatal input failures leave the Core tip, frontier, checkpoints, and journal
unchanged. Core does not select forks: the host provides an already selected
canonical sequence.

## Coppice Names v1 application

`NamesApplication` implements `CoppiceApplication` over the
application-scoped `ApplicationBlockContext`; Core metadata and routed effects
are withheld until the descriptor's activation height.
It owns:

- canonical Names records and pending commitments;
- active-bond and recent-spent semantics;
- COMMIT, REVEAL, UPDATE, RELEASE, expiry, pruning, and rejection rules;
- the Names state root;
- Names-specific undo history.

Canonical Ironwood nullifiers are native Core effects. Names consumes the
ordered nullifiers from the immutable transaction context and invalidates any
matching bond before interpreting that transaction's routed Names operation.
No Names state is copied into Core.

`NamesRuntime` is the production single-application composition. For block
application it stages a clone of Core, obtains a complete immutable runtime
context, applies Names, and publishes the staged Core only after Names
succeeds. A fatal error in either layer is block-atomic across both layers.
Names protocol rejections are deterministic application outcomes rather than
fatal Core failures.

## Rewind and replay

Core and Names retain independent undo journals over the same canonical block
positions. `NamesRuntime::rewind_to`:

1. proves and stages the Core rewind;
2. rewinds the Names application to the same height;
3. commits the staged Core only after both operations succeed.

Retained tips must agree by height and block hash. The Core retention horizon
is explicit generic configuration. Names v1 calculates its required horizon
from Names policy and passes that value into Core construction; Core does not
import the policy.

If the host reorg is older than the retained common ancestor, reconciliation
returns a rebuild requirement. The adapter rebuilds from the configured
activation checkpoint along the host-selected canonical chain. Fresh replay,
rewind followed by replay, and persisted restoration must converge on the same
Core frontier and Names root.

## Persistence

Persistence has independently validated layers:

- `CoreReplay` snapshot: Core tip, frontier/checkpoints, and Core undo journal;
- `CoreRuntime` snapshot: runtime identity plus opaque Core replay snapshot;
- `NamesApplication` snapshot: Names identity, state/root, tip, and Names undo;
- `NamesRuntime` manifest: opaque Core/application snapshots plus the shared
  tip, Ironwood root/tree size, route, runtime identity, and Names state root.

Snapshot loading validates version and identity at every layer, reconstructs
the independently owned state, verifies every retained Names root against the
corresponding Core checkpoint, and rejects mismatched tips or roots. Wallet
integration atomically replaces the composite manifest after each successful
block or rewind boundary. The development-only monolithic snapshot is not
accepted; the host rebuilds it from activation.

## librustzcash adapter

`coppice-librustzcash` is the only bridge between host wallet facts and the
runtime. It provides:

- strict CompactBlock conversion into `CoreCanonicalBlockInput`;
- exact-receiver rendezvous candidate detection before full-transaction
  fetching;
- full transaction fetching only for candidates;
- host-tip-frozen reconciliation, shallow rewind, and deep rebuild signaling;
- normal librustzcash proposal/construction for CPV1/CA01 Names carriers;
- wallet-local owned-note inventory, witnesses, bond proofs, pending intents,
  advisory locks, owner operations, and protected-spend guards.

The adapter never performs independent fork choice. It validates exact host
tip height and hash before mutation-capable wallet operations. Candidate data,
network responses, and persistence are treated as hostile inputs.

## Wallet boundary

The public integration layers are:

```text
generic Coppice runtime
        -> Coppice Names v1 application
        -> wallet-facing Names workflows and policy
```

Names presentation normalization, account selection, user confirmation,
pending metadata, note locks, and protection mode are wallet concerns. The
current modes are:

- `Enabled`: replay, Names management, and protected-spend guards;
- `GuardOnly`: replay/resolution and guards without management workflows;
- `Off`: no Coppice replay state or guards; ordinary Zcash behavior is
  unchanged.

UIVK-only wallets fail closed where nullifier derivation is required. UFVK
wallets can classify owned bonds; spending wallets can construct management
transactions.

## Stable public APIs

Long-term public surfaces are:

- `coppice-core::{identity, application, transport, replay, runtime}`;
- `coppice::{names_application, names_runtime}` plus frozen Names protocol
  modules;
- `coppice-librustzcash` adapter traits and wallet workflow functions.

Callers use typed `CoreRuntimeId`, `ApplicationId`, `ApplicationKey`, and
`NamesDeploymentId`. The production Names composition exposes
`names_deployment_id()`; it does not expose a raw runtime-level
`deployment_id()` alias that could be mistaken for Core identity.

Internal snapshot layouts and wallet filesystem paths are versioned integration
details, not protocol identifiers. Wallet-specific database and RPC types do
not enter `coppice-core` or the Names state machine.

## Required invariants

Every change must preserve:

- Zcash as the sole ordering and fork-choice layer;
- canonical transaction order and block atomicity;
- exact candidate/full-transaction validation;
- candidate-only full transaction fetching;
- deterministic Ironwood frontier/checkpoint tracking;
- independent Core and application roots/undo state;
- deterministic rewind/replay and fresh reconstruction;
- unchanged Names operation, commitment, owner, authorization, bond, and state
  root vectors unless a new protocol version explicitly changes them;
- no application-to-application mutable state;
- no WASM, arbitrary contracts, gas, or second consensus layer.

## Qualification

The final qualification record spans the real Zakura -> patched Zaino ->
`zcash-devtool` stack in Phases 1-5 and 7, with the deterministic retained/deep
reorg companion in Phase 6. It covers ordinary Ironwood transactions, the full
Names lifecycle, restart and fresh same-seed recovery, shallow reorgs,
multi-account isolation, protection modes, wallet/PCZT spend boundaries, and
resolution/lock invariants.

Phase 7 placed a Names transition on an abandoned branch, advanced that branch
131 blocks beyond the configured 121-block retention horizon, mined an
equal-length replacement, and verified canonical rebuild. It then initialized
an independent same-seed wallet from activation and compared the resulting
runtime snapshot and Names outcomes. This is local development/regtest
qualification evidence, not a security audit, public deployment, or guarantee
for future operational environments.
