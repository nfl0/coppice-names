# Coppice Protocol Specification

**Status:** Normative v1 specification; production-authoritative code path; pre-release
**Protocol version:** 1  
**Wire version:** 1  
**Last architecture decision:** 2026-08-24

## 1. Purpose and authority

This document is the normative interoperability specification for Coppice v1.

A conforming implementation MUST derive the same application state from the
same canonical Zcash history and validated parameters. For Coppice Names v1,
that application state is Names state; Core state is the generic canonical
replay, Ironwood-effect, transport, and checkpoint context. Implementation
details that do not affect these results are outside this document.

Precedence for v1 development is:

```text
PROTOCOL_SPEC.md
    >
normative machine-readable test vectors
    >
IMPLEMENTATION.md
    >
all historical Coppice documents and code behavior
```

Historical `PROTOCOL.md`, `REFERENCE.md`, `SYSTEM_DESIGN*.md`, and existing
application behavior MUST NOT override this specification.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Protocol model

Coppice Core is an adminless deterministic runtime over the host application's
accepted canonical Zcash chain. Coppice Names v1 is the first application
composed with that runtime and derives Names state from the Core context.

It has:

- no administrator or operator key;
- no protocol treasury;
- no smart contract;
- no separate blockchain or fork-choice rule;
- no trusted remote registry authority;
- no Zcash consensus change.

The host selects canonical Zcash history. Core consumes that history and emits
canonical Ironwood effects and routed application context. Names v1 consumes
that context and derives Names state.

Coppice Names v1 has exactly four explicit application operations:

```text
COMMIT
REVEAL
UPDATE
RELEASE
```

There is no TRANSFER, REBOND, RENEW, or administrative operation.

## P-SCOPE-001 — Ironwood-only shielded protocol scope

Coppice v1 is an Ironwood-only protocol.

Only Ironwood notes/actions may carry Coppice carrier frames, supply Coppice
bonded notes, or contribute shielded effects to Coppice canonical state.
Sapling notes/actions and notes/actions from the pre-Ironwood Orchard protocol
are not valid Coppice carriers. They MUST NOT serve as Coppice bonded notes and
MUST NEVER be interpreted as Coppice protocol state, including Names
operations, commitments, nullifiers, or bond effects.

Coppice-aware wallets MAY continue to hold, receive, and spend Sapling and
pre-Ironwood Orchard funds through their normal Zcash wallet behavior. Those
funds are outside Coppice and MUST NOT be selected for Coppice bond
construction, carrier construction, or Coppice protection.

The Rust `orchard` crate and its Orchard-named types are used for Ironwood
cryptographic and wallet machinery. That implementation naming does not expand
the Coppice v1 protocol scope to the pre-Ironwood Orchard protocol.

## 3. Conformance rule

For every protocol rule, byte serialization, hash domain, validation condition,
and state-transition order in this document, an implementation MUST behave
exactly as specified.

Unknown or malformed Names v1 operations are deterministic application
rejections,
not reasons to reinterpret bytes using an implementation-specific fallback.

Fatal block-input errors are different: when canonical Zcash input required to
evaluate a candidate transaction is missing or inconsistent, Core MUST not
advance beyond that block.

## 4. Numeric and byte conventions

Unless a rule explicitly says otherwise:

- fixed-width protocol integers are unsigned;
- `_u16`, `_u32`, and `_u64` encodings use big-endian byte order;
- byte strings are concatenated without separators other than lengths explicitly
  shown by the encoding;
- hashes are raw 32-byte values, never display hex;
- Zcash block hashes and transaction IDs use their canonical internal 32-byte
  representation, never a human-facing reversed display representation;
- arithmetic that can overflow MUST use checked or explicitly saturating
  arithmetic exactly where specified.

## P-CRYPTO-001 — Byte-oriented cryptographic hash suite

Coppice v1 does not use SHA-256 for its application-level byte hashes.

For byte strings, Coppice uses personalized BLAKE2b-256, following the same
general domain-separation pattern used by modern Zcash transaction digests.

Define:

```text
H(label, message) =
    BLAKE2b-256(
        personalization = P(label),
        input = message
    )
```

where `P(label)` is the ASCII encoding of `label` followed by zero bytes until
the personalization is exactly 16 bytes. Every label below is at most 16 ASCII
bytes. No terminating zero is included before this right-padding rule is
applied.

The v1 personalization labels are:

| Purpose | label | exact 16-byte personalization (hex) |
|---|---|---|
| Core runtime identifier | `CoppiceRuntime1` | `436f707069636552756e74696d653100` |
| application identifier | `CoppiceAppIdV1` | `436f7070696365417070496456310000` |
| Names deployment identifier | `CoppiceDeployV1` | `436f70706963654465706c6f79563100` |
| name identifier | `CoppiceNameV1` | `436f70706963654e616d655631000000` |
| record hash | `CoppiceRecordV1` | `436f70706963655265636f7264563100` |
| registration commitment | `CoppiceCommitV1` | `436f7070696365436f6d6d6974563100` |
| Unified Address digest | `CoppiceAddrV1` | `436f7070696365416464725631000000` |
| pending commitment root | `CoppiceCSetV1` | `436f7070696365435365745631000000` |
| registration context digest | `CoppiceRegV1` | `436f7070696365526567563100000000` |
| RecentSpent root | `CoppiceSpentV1` | `436f70706963655370656e7456310000` |
| NameTree empty leaf | `CoppiceNEmptyV1` | `436f70706963654e456d707479563100` |
| NameTree record leaf | `CoppiceNLeafV1` | `436f70706963654e4c65616656310000` |
| NameTree internal node | `CoppiceNNodeV1` | `436f70706963654e4e6f646556310000` |
| Coppice state root | `CoppiceStateV1` | `436f7070696365537461746556310000` |
| carrier payload digest | `CoppicePayloadV1` | `436f70706963655061796c6f61645631` |
| BondProof verifier identity | `CoppiceBondV1` | `436f7070696365426f6e645631000000` |

Unless another construction in this ZIP explicitly specifies keyed mode,
`BLAKE2b-256` means unkeyed sequential BLAKE2b with digest length 32 bytes,
fanout 1, depth 1, an all-zero salt, and the exact personalization above.

All `H(...)` outputs in this ZIP are exactly 32 bytes.

Poseidon is reserved for relations that are naturally constrained over Pasta
fields inside `CoppiceBondCircuit`, including `bond_tag` derivation and the
field-valued deployment/context/owner bindings. Implementations MUST NOT replace
a specified BLAKE2b hash with Poseidon, or a specified Poseidon relation with
BLAKE2b, without changing the protocol version.

## P-IDENTITY-001 — Three independent identity domains

The general Coppice runtime separates three identities:

```text
CoreRuntimeId
    generic runtime and CPV1 transport binding

ApplicationId || application_version
    application-envelope routing

NamesDeploymentId
    Coppice Names v1 cryptography and application state
```

These values are not interchangeable. In particular, the existing
`CoppiceDeployV1` value is `NamesDeploymentId`; it is not `CoreRuntimeId`.

Throughout the Names v1 sections below, the historical field name
`deployment_id` means `NamesDeploymentId` unless a Core runtime section
explicitly says otherwise. Historical Names encodings retain that field name
so existing protocol bytes remain unchanged; runtime-facing APIs use the typed
`NamesDeploymentId` wrapper.

## P-RUNTIME-ID-001 — Generic Core runtime identifier

`CoreRuntimeId` is the unkeyed BLAKE2b-256 output:

```text
H(
    "CoppiceRuntime1",
    runtime_protocol_id_len_u16 || runtime_protocol_id ||
    runtime_protocol_version_u16 ||
    zcash_network_domain_len_u16 || zcash_network_domain ||
    zcash_network_type_code_u8 ||
    runtime_activation_height_u32 ||
    carrier_protocol_id_len_u16 || carrier_protocol_id ||
    rendezvous_ivk_len_u16 || rendezvous_ivk ||
    rendezvous_receiver_len_u16 || rendezvous_receiver
)
```

All integers are unsigned big-endian. Variable-length fields use exact bytes;
Core performs no textual normalization. Protocol ID, protocol version, network
domain, activation height, and carrier protocol ID MUST be nonzero or nonempty
as appropriate. Lengths MUST fit `u16`.

Raw `CoreRuntimeParameters` are not identity authority. Before deriving an ID,
Core MUST:

1. validate every structural constraint above;
2. parse the 64-byte rendezvous IVK as an Ironwood incoming viewing key;
3. parse the 43-byte rendezvous receiver as an Ironwood address; and
4. require the receiver to correspond to the incoming viewing key.

Successful validation produces `ValidatedCoreRuntimeParameters`. Only that
validated type may expose the canonical preimage or derive `CoreRuntimeId`.
Invalid raw parameters MUST NOT produce a runtime identity.

The qualification vector freezes:

```text
runtime_protocol_id       = "coppice.runtime"
runtime_protocol_version  = 1
zcash_network_domain      = "coppice-runtime-regtest-v1"
zcash_network_type        = Regtest / 0x03
runtime_activation_height = 10
carrier_protocol_id       = "CPV1"
CoreRuntimeId             = 6d9370bb8eb3f6cf28fc2c1a943196b6
                            30233eb89d03625877910a49320a8cb0
```

The shared rendezvous IVK and receiver are the exact bytes in
the Coppice Core repository's `test-vectors/core_runtime_id.json`.

Application IDs, application versions, application activation heights, and all
application policy parameters are excluded from this preimage. Adding or
activating an application therefore cannot change `CoreRuntimeId`.

## P-RUNTIME-ACTIVATION-001 — Runtime and application activation

`runtime_activation_height` is the first height processed by the Core runtime
and is bound into `CoreRuntimeId`.

Every enabled application separately declares an
`application_activation_height`. It MUST be greater than or equal to the
runtime activation height. It is not an input to `CoreRuntimeId`.

Before an application's activation, Core may ingest and authenticate canonical
Zcash history for other active applications, but MUST NOT deliver native
effects or explicit messages to that inactive application. Coppice Names v1
initially uses the runtime activation height. Future applications may activate
later without changing the runtime identity or the state of an existing
application.

Coppice Names v1 performs an application-side compatibility check against a
validated Core context. It independently validates `NamesDeploymentId`, then
requires the frozen Core runtime protocol/version, Zcash network and runtime
network domain, CPV1 carrier context, exact rendezvous bytes, Names application
key, and activation relationship to agree. It MUST NOT derive `CoreRuntimeId`
from Names parameters or `NamesDeploymentId` from Core parameters.

Names v1 currently requires:

```text
names_application_activation_height == names_activation_height
names_application_activation_height == runtime_activation_height
```

This is a Names v1 compatibility rule, not a generic Core restriction. A future
application may activate strictly after the runtime activation height.

## P-APPLICATION-ID-001 — Deterministic application identity

Each application family freezes one exact, nonempty canonical identity byte
string. Core performs no Unicode normalization, case folding, or aliasing.

```text
ApplicationId = H("CoppiceAppIdV1", canonical_application_identity)
```

The application version is not part of `ApplicationId`; it is a separate
unsigned 16-bit routing field. Versions of one application family therefore
share an `ApplicationId` and have distinct `(ApplicationId, version)` keys.

Coppice Names freezes:

```text
canonical_application_identity = ASCII "coppice.names"
ApplicationId = 285357b331c4120e22409b577f21ca6d
                702a3cdb6a2eaae0788a67f7aa022303
Names v1 application_version = 1
```

## P-APPLICATION-ENVELOPE-001 — CA01 application envelope

The runtime application envelope is exactly:

```text
magic[4]("CA01") ||
application_id[32] ||
application_version_u16be ||
application_payload[remaining bytes]
```

The header is exactly 38 bytes. There is no payload-length field because CPV1
already authenticates the exact outer payload length and digest. An empty
application payload is structurally canonical; a recognized application may
reject it under its own protocol rules.

The complete envelope MUST fit CPV1's 16,093-byte payload limit, so the maximum
application payload is 16,055 bytes. Truncated headers, a magic other than
`CA01`, and oversized envelopes are malformed. Unknown application IDs or
versions are structurally valid and unsupported; they MUST NOT be decoded as a
different application or cause application-state mutation.

`coppice-core` owns `MAX_CPV1_PAYLOAD_LEN = 16_093` and derives
`MAX_APPLICATION_PAYLOAD_LEN = 16_093 - 38 = 16_055`. No application or wallet
adapter may maintain an independent numeric definition.

For the general runtime carrier, the CPV1 START binding field is
`CoreRuntimeId`, and the CPV1 payload digest authenticates the complete CA01
envelope. `NamesDeploymentId` remains inside Names cryptographic and state
domains and is not an envelope field.

The general runtime format is authoritative at every processed height beginning
with `runtime_activation_height`: START binds `CoreRuntimeId`, and the payload
is exactly one CA01 envelope. Coppice Names v1 accepts only its frozen
`ApplicationId || application_version` route and then decodes the unchanged
Names operation payload. There is no naked-Names fallback or dual parser.

The Testnet and Regtest deployments are qualification/development deployments
with no announced public history. Existing pre-cutover local snapshots are a
development persistence format and MUST be rebuilt from the configured
activation checkpoint. The unchanged `carrier.json` vectors remain normative
for the parameterized CPV1 framing algorithm; `application_envelopes.json`
freezes the production Names v1 routing bytes.

## P-DEP-001 — Names deployment parameters

Coppice Names v1 protocol logic is parameterized by a validated Names
deployment.

The repository's Testnet and Regtest values are qualification/development
parameters; no public Coppice Testnet or Mainnet deployment has been
announced.

Recommended Rust shape:

```rust
pub struct Rendezvous {
    /// Raw Ironwood incoming viewing key encoding, provided by the `orchard` crate.
    pub orchard_ivk: [u8; 64],
    /// Raw Ironwood payment-address encoding, provided by the `orchard` crate.
    pub orchard_receiver: [u8; 43],
}

pub struct DeploymentParameters { // Names v1 deployment parameters
    pub network_id: Vec<u8>,
    pub address_network: zcash_protocol::consensus::NetworkType,
    pub activation_height: u32,

    pub minimum_bond_value: u64,
    pub commit_ttl_blocks: u32,
    pub reuse_delay_blocks: u32,
    pub bond_note_max_age_blocks: u32,

    pub rendezvous: Rendezvous,
}
```

For `deployment_id` serialization, Coppice defines:

```text
network_type_code(Main)    = 0x01
network_type_code(Test)    = 0x02
network_type_code(Regtest) = 0x03
```

The rendezvous validation MUST parse the 64-byte raw Ironwood IVK and 43-byte
raw Ironwood receiver using the `orchard` crate and require that
`ivk.diversifier_index(&receiver)` is `Some(_)`.

Validation MUST enforce:

```text
1 <= network_id.len <= 64
activation_height > 0
minimum_bond_value > 0
commit_ttl_blocks >= 2
reuse_delay_blocks >= 1
bond_note_max_age_blocks >= 1
bond_note_max_age_blocks + commit_ttl_blocks does not overflow u32
rendezvous incoming key valid
rendezvous receiver valid
rendezvous receiver corresponds to the configured incoming capability
```

The public 1 ZEC candidate uses:

```text
minimum_bond_value = 100_000_000 zatoshis
```

The implementation MUST keep this a deployment parameter so the local Regtest
and Zcash Testnet qualification environments can be configured separately.

## P-DEP-002 — Names deployment identifier

Every Names deployment has a deterministic 32-byte `NamesDeploymentId`. The
historical Names-facing convenience method remains named `deployment_id()`;
typed architecture APIs expose `NamesDeploymentId`.

It MUST be computed from the complete canonical deployment parameters.

Use:

```text
NamesDeploymentId = H(
    "CoppiceDeployV1",
    network_id_len_u16 || network_id ||
    network_type_code_u8 ||
    activation_height_u32 ||
    minimum_bond_value_u64 ||
    commit_ttl_blocks_u32 ||
    reuse_delay_blocks_u32 ||
    bond_note_max_age_blocks_u32 ||
    rendezvous_ivk_len_u16 || rendezvous_ivk_bytes ||
    rendezvous_receiver_len_u16 || rendezvous_receiver_bytes
)
```

All integers are unsigned big-endian.

This ID is Names-specific cryptographic domain data.

It is included in:

- registration commitments;
- owner signatures;
- BondProof protocol binding;
- Names state roots.

A Names configuration mismatch therefore cannot silently produce compatible
Names protocol state. It does not identify the generic Core runtime.

## P-CHAIN-001 — Activation checkpoint

To begin replay at `activation_height`, the host MUST supply an authenticated Ironwood chain state from the end of:

```text
activation_height - 1
```

The checkpoint contains at least:

```rust
pub struct ActivationCheckpoint {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub ironwood_frontier: IronwoodFrontier,
    pub ironwood_tree_size: u32,
}
```

Requirements:

```text
checkpoint.height == activation_height - 1
frontier tree size == ironwood_tree_size
frontier root is internally valid
checkpoint belongs to the host-accepted canonical chain
```

No pre-activation Ironwood nullifier scan is required by this v1 design.

The initial freshness position floor is the checkpoint's `ironwood_tree_size`.

## P-CHAIN-002 — Pre-activation nullifier exclusion

A registration at COMMIT height `C` gets a deterministic freshness-floor height:

```text
freshness_floor_height =
    max(
        activation_height - 1,
        C.saturating_sub(bond_note_max_age_blocks)
    )
```

Let:

```text
position_floor =
    Ironwood tree size at end of freshness_floor_height
```

The BondProof privately proves:

```text
note_position >= position_floor
```

Therefore a note created before the freshness floor cannot qualify.

For an early deployment COMMIT whose computed floor would precede activation, the floor clamps to the activation checkpoint.

Therefore no pre-Coppice note can qualify.

Any spend of an eligible note before REVEAL must occur after its creation and therefore lies inside the bounded recent-spend window defined later.

## P-NAME-001 — Canonical names

A canonical name:

- contains 1 through 63 bytes;
- is ASCII only;
- uses only `[a-z0-9-]`;
- does not begin with `-`;
- does not end with `-`.

No Unicode normalization exists in v1.

Uppercase is invalid.

The canonical string is the exact accepted byte sequence.

The standardized `.zec` suffix is presentation-only. Wallets and frontends
SHOULD display the canonical label `alice` as `alice.zec` and MAY accept either
form from users. They MUST remove one terminal `.zec` before applying the
canonical-name rules. The suffix MUST NOT appear in commitments, signatures,
operation bytes, NameTree keys, hashes, or stored protocol/wallet records.
Consequently, `alice` and `alice.zec` always identify the same canonical name;
they MUST NOT create distinct Coppice state.

Name ID:

```text
name_id =
    H(
        "CoppiceNameV1",
        canonical_name_bytes
    )
```

The 32-byte `name_id` is the sparse NameTree key.

## P-NAME-002 — Canonical Unified Addresses

A record points to exactly one canonical Zcash Unified Address.

The protocol stores the canonical textual Unified Address encoding as ASCII bytes.

Replay MUST:

1. parse the supplied address for the deployment's configured `address_network`;
2. require it to be a valid Unified Address, not an arbitrary address string;
3. re-encode it canonically;
4. require the canonical re-encoding to be byte-for-byte equal to the supplied bytes.

The protocol constant is:

```text
MAX_ADDRESS_LEN = 512 bytes
```

An invalid network, invalid UA, noncanonical encoding, non-ASCII byte, or oversized address rejects the operation.

## P-OWNER-001 — Owner verification keys

Each active registration has one 32-byte owner verification key.

Use the canonical RedPallas:

```text
VerificationKey<SpendAuth>
```

encoding.

Noncanonical keys are invalid. The parsed RedPallas verification key MUST also be non-identity.

Owner authorization is independent from the carrier transaction's Zcash spend authority.

The BondProof binds the registration to the chosen owner key.

## P-OWNER-002 — Recommended deterministic owner-key derivation

The protocol permits any valid owner public key.

For interoperability between Coppice-aware software wallets, the librustzcash adapter SHOULD provide a deterministic default owner key derived from the account's Ironwood spending authority (the Orchard-named key component used by the `orchard` crate).

This solves an important restore problem:

```text
restore same seed/account
+ replay active name
+ read name + bond_tag
-> derive same owner key
-> retain UPDATE / RELEASE authority
```

The default software-wallet derivation uses keyed personalized BLAKE2b-512.

Define the exact 16-byte personalization:

```text
ASCII:  "CoppiceOwnerKDF1"
hex:    436f70706963654f776e65724b444631
```

Let:

```text
key =
    orchard_account_spending_key_bytes[32]

message(counter) =
    deployment_id[32] ||
    name_id[32] ||
    bond_tag[32] ||
    counter_u32_be
```

Starting with `counter = 0`, compute:

```text
okm =
    BLAKE2b-512(
        key = key,
        personalization = "CoppiceOwnerKDF1",
        salt = [0; 16],
        input = message(counter)
    )
```

This is sequential keyed BLAKE2b with digest length 64 bytes, fanout 1, and
depth 1.

Map the exact 64 output bytes, without byte reversal, to a Pallas scalar using
the `ff::FromUniformBytes<64>` reduction implemented for `pallas::Scalar`.

If the resulting scalar is zero, increment `counter` with checked arithmetic
and repeat. The probability of requiring a retry is negligible, but the retry
rule is normative.

Serialize the nonzero scalar with its canonical `PrimeField::to_repr()`
encoding and construct the RedPallas `SigningKey<SpendAuth>` from that scalar.
The corresponding `VerificationKey<SpendAuth>` is the default Coppice owner
public key.

Use of keyed BLAKE2b here is a KDF/PRF construction and is distinct from the
unkeyed `H(...)` function used for public protocol hashes.

Security requirements:

- never persist the derived scalar unless the wallet's normal key-storage policy permits it;
- never expose the Ironwood spending key to untrusted code;
- hardware/external signers SHOULD implement this derivation internally;
- UFVK-only wallets cannot derive this signing key and therefore cannot UPDATE or RELEASE.

An application MAY instead supply an external owner signer.

The public protocol does not distinguish the derivation method.

## P-STATE-001 — Name record

Canonical state stores:

```rust
pub struct NameRecord {
    pub owner_pk: [u8; 32],
    pub bond_tag: [u8; 32],
    pub sequence: u64,
    pub address: String,
    pub status: NameStatus,
}
```

Where:

```rust
pub enum NameStatus {
    Active,
    Released { terminal_height: u32 },
    BondSpent { terminal_height: u32 },
}
```

The terminal height is part of authenticated state.

The address remains in the terminal record for deterministic historical state, but terminal records MUST NOT resolve as payment destinations.

## P-STATE-002 — Name-record encoding

Canonical record bytes:

```text
owner_pk[32] ||
bond_tag[32] ||
sequence_u64 ||
status_u8 ||
terminal_height_u32 ||
address_len_u16 ||
address_bytes
```

Status codes:

```text
0x01 Active
0x02 Released
0x03 BondSpent
```

For Active:

```text
terminal_height == 0
```

For terminal statuses:

```text
terminal_height > 0
```

Record hash:

```text
previous_record_hash =
    H(
        "CoppiceRecordV1",
        record_bytes
    )
```

## P-STATE-003 — Claimability and reuse delay

Define:

```text
claimable_from_height(name)
```

as follows.

### Never registered

If no record exists:

```text
claimable_from_height = activation_height
```

### Active

Active names are not claimable.

### Released

If:

```text
Released { terminal_height = T }
```

then:

```text
claimable_from_height = T + reuse_delay_blocks
```

### BondSpent

If:

```text
BondSpent { terminal_height = T }
```

then:

```text
claimable_from_height = T + reuse_delay_blocks
```

All additions MUST be overflow-checked.

A new REVEAL for a terminal name is valid only if:

```text
matching_commit.block_height >= claimable_from_height
```

Thus a hidden COMMIT created before the new claim epoch cannot later win the name.

## P-CHAIN-003 — Canonical chain positions

Operations have an authenticated chain position supplied by canonical block ordering:

```rust
pub struct ChainPosition {
    pub block_height: u32,
    pub tx_index: u32,
}
```

Blocks are ascending by height.

Transactions are ascending by `tx_index`.

The first valid state transition encountered in canonical order wins any race.

## P-WIRE-001 — Protocol operations

Coppice v1 defines exactly:

```rust
pub enum Operation {
    Commit {
        commitment: [u8; 32],
    },

    Reveal {
        name: String,
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
        bond_anchor_height: u32,
        bond_anchor: [u8; 32],
        bond_proof: Vec<u8>,
        address: String,
        secret: [u8; 32],
    },

    Update {
        name: String,
        sequence: u64,
        address: String,
        signature: [u8; 64],
    },

    Release {
        name: String,
        sequence: u64,
        signature: [u8; 64],
    },
}
```

No transfer/rebond variant exists.

## P-WIRE-002 — Operation byte encoding

All integers are unsigned big-endian.

All variable-length byte strings are:

```text
length_u16 || bytes
```

Trailing bytes are invalid.

Operation tags:

```text
0x01 COMMIT
0x02 REVEAL
0x03 UPDATE
0x04 RELEASE
```

Encodings:

```text
COMMIT =
    0x01 ||
    commitment[32]
```

```text
REVEAL =
    0x02 ||
    name_bytestring ||
    owner_pk[32] ||
    bond_tag[32] ||
    bond_anchor_height_u32 ||
    bond_anchor[32] ||
    secret[32] ||
    bond_proof_bytestring ||
    address_bytestring
```

```text
UPDATE =
    0x03 ||
    name_bytestring ||
    next_sequence_u64 ||
    address_bytestring ||
    signature[64]
```

```text
RELEASE =
    0x04 ||
    name_bytestring ||
    next_sequence_u64 ||
    signature[64]
```

Parser limits MUST be applied before allocation.

## P-REG-001 — Registration commitment

The commitment binds the semantic registration but deliberately excludes proof artifacts.

```text
address_digest =
    H("CoppiceAddrV1", address_bytes)

commitment =
    H(
        "CoppiceCommitV1",
        deployment_id[32] ||
        name_id[32] ||
        owner_pk[32] ||
        bond_tag[32] ||
        address_digest[32] ||
        secret[32]
    )
```

The following are intentionally excluded:

- `bond_anchor_height`;
- `bond_anchor`;
- `bond_proof`.

Rationale:

The anchor and proof demonstrate validity but do not define the resulting name record.

Excluding them lets the wallet:

1. select and lock the bond note;
2. derive `bond_tag`;
3. publish COMMIT;
4. wait for COMMIT to mine;
5. generate a fresh proof against a recent canonical Ironwood anchor;
6. publish REVEAL.

This greatly reduces stale-anchor and reorg friction.

## P-REG-002 — Registration secret

`secret` is 32 bytes from a cryptographically secure RNG.

It prevents dictionary recognition of a hidden COMMIT.

Wallets MUST NOT reuse a registration secret for a new registration attempt.

The secret becomes public when REVEAL is mined.

It is not retained in `NameRecord`.

## P-REG-003 — Pending commitment state

The Names application stores:

```rust
BTreeMap<[u8; 32], ChainPosition>
```

A duplicate still-live commitment is rejected.

A successful REVEAL removes exactly its matching commitment.

A rejected REVEAL leaves the commitment intact until expiry.

## P-REG-004 — COMMIT maturity and expiry

Let:

```text
C = commit block height
R = reveal block height
TTL = commit_ttl_blocks
```

A REVEAL is time-valid only if:

```text
R >= C + 1
R <= C + TTL
```

Therefore same-block COMMIT/REVEAL is invalid.

At the end of processing block `H`, remove any still-pending commitment satisfying:

```text
C + TTL <= H
```

This means a REVEAL in the deadline block is still processed before expiry.

Expiry itself is deterministic protocol state.

## P-REG-005 — Pending commitment root

Pending commitments are sorted lexicographically by commitment bytes.

```text
PendingCommitmentRoot =
    H(
        "CoppiceCSetV1",
        count_u32 ||
        entry_0 ||
        entry_1 ||
        ...
    )
```

Each entry:

```text
commitment[32] ||
block_height_u32 ||
tx_index_u32
```

## P-BOND-001 — Private ZEC bond

A registration bond is one wallet-controlled Ironwood note.

The full note is reserved.

If the minimum is 1 ZEC and the selected note is 20 ZEC:

```text
actual bonded wallet value = 20 ZEC
```

The protocol only proves:

```text
note_value >= minimum_bond_value
```

It does not split the note logically.

## P-BOND-003 — Bond-tag derivation

For every canonical Ironwood nullifier:

1. decode its 32-byte canonical representation as a Pallas base-field element;
2. reject noncanonical encodings;
3. compute the protocol tag.

Define the exact 16-byte ASCII domain:

```text
"CoppiceBondTagV1"
```

Interpret those 16 bytes as a little-endian `u128`, inject into the Pallas base field without reduction, and compute:

```text
tag_field =
    Poseidon<P128Pow5T3, ConstantLength<2>>(
        domain_field,
        nullifier_field
    )
```

The public `bond_tag` is:

```text
tag_field.to_repr()
```

No hashing or encoding variant may silently replace this relation.

## P-BOND-002 — BondProof statement

`BondProof` is produced by a purpose-built `CoppiceBondCircuit`.

The circuit MUST prove exactly the Coppice bond statement; it MUST NOT require
the prover to instantiate an Orchard/Ironwood Action, dummy output note, value
commitment, action flags, binding-signature artifact, or any other transaction
semantics that are irrelevant to a Coppice bond.

The circuit MAY and SHOULD reuse the established Orchard/Ironwood cryptographic
gadgets and primitive definitions needed to prove the actual Ironwood note
relations, including note commitment, Sinsemilla Merkle membership, nullifier
derivation, spend-authority key relations, and Pasta-field range/comparison
gadgets.

A valid BondProof proves knowledge of a private Ironwood note and spending
authority satisfying all of:

1. the witness encodes a valid Ironwood/V3 note under the Zcash protocol;
2. the note commitment is a member of the public `bond_anchor`;
3. the prover knows the spending authorization material required for that note;
4. the spending authorization material is correctly related to the full-viewing-key authorization material used in the note/nullifier relation;
5. `note_value >= minimum_bond_value`;
6. the note's canonical Ironwood nullifier maps to the public `bond_tag` by the exact Poseidon relation specified in this ZIP;
7. the private note commitment-tree position is at least the supplied public `position_floor`;
8. the proof is bound to the deployment;
9. the proof is bound to the canonical name;
10. the proof is bound to the exact initial canonical Unified Address;
11. the proof is bound to the external Coppice owner public key.

The proof MUST NOT reveal:

- note commitment;
- canonical nullifier;
- exact value;
- commitment-tree position;
- receiver;
- spending key;
- full viewing key.

The private witness is conceptually:

```rust
pub struct BondWitness {
    pub note: IronwoodNote,
    pub full_viewing_key: OrchardFullViewingKey,
    pub spend_authorizing_key: SpendAuthorizingKey,
    pub merkle_path: IronwoodMerklePath,
}
```

The concrete Rust types MAY differ, but the witness MUST be sufficient to
reconstruct and constrain the exact Zcash Ironwood note commitment, nullifier,
spend-authority relation, and Merkle path. No weaker surrogate relation is
permitted.

## P-BOND-004 — BondProof v1 proving system and canonical public inputs

The v1 proof-system choice is **Halo2 IPA over the Pasta cycle**, using Vesta as
the commitment curve and Pallas base-field elements as circuit instances. No
trusted setup is required.

The selected v1 circuit architecture is the dedicated **parallel-Merkle
`CoppiceBondCircuit`**, which reuses the existing Orchard/Ironwood gadgets but
does not synthesize Orchard Action-only output/value-commitment machinery.

The selected circuit parameter is:

```text
BOND_K = 11
```

The single instance column contains exactly seven Pallas base-field elements in
this order:

```text
0 anchor
1 minimum_value
2 position_floor
3 protocol_binding
4 context_binding
5 owner_binding
6 bond_tag
```

Their interpretation is exact:

```text
anchor =
    canonical Pallas-base encoding of the accepted end-of-block
    Ironwood anchor root

minimum_value =
    pallas::Base::from(minimum_bond_value_u64)

position_floor =
    pallas::Base::from(position_floor_u32)

protocol_binding =
    field value defined by P-BOND-005

context_binding =
    field value defined by P-BOND-006

owner_binding =
    field value defined by P-BOND-007

bond_tag =
    canonical Pallas-base field element defined by P-BOND-003
```

The v1 proof transcript is the Halo2 `Blake2bRead` / `Blake2bWrite` transcript
with `Challenge255`, matching `halo2_proofs` 0.3.2 semantics. Verification uses
the ordinary single-proof verifier strategy.

The IPA parameter construction is deterministic:

```rust
Params::<vesta::Affine>::new(11)
```

The benchmarked canonical candidate proof is **4,960 bytes** and proved in
approximately 393 ms on the benchmark host. Proof byte length is engineering
evidence until the final verification-key artifact is frozen below.

### F-001 — BondProof interoperability freeze — CLOSED

The v1 BondProof verifier identity is frozen to the durable dedicated
parallel-Merkle circuit introduced by source commit:

```text
a9521cdf995ffcfd2627ddfdd750253512172d73
```

The vector/final working-tree HEAD reported for the freeze is:

```text
0c2c177487bb868c848eae4eef33b1b58d59fcfe
```

The canonical v1 proof parameters are:

```text
halo2_proofs       = 0.3.2
commitment scheme  = Halo2 IPA / Vesta
parameters         = Params::<vesta::Affine>::new(11)
transcript         = Blake2bWrite / Blake2bRead with Challenge255
proof length       = 4960 bytes
BOND_VK_ID          = a16074cfadabc4c24bf58732389a4f2d574e25c43f169239ec21da852f5f7adc
```

`BOND_VK_ID` is the protocol-stable verifier identifier. It was derived as:

```text
H("CoppiceBondV1", verifier_artifact)
```

where the freeze artifact is the UTF-8 Debug byte representation of
`halo2_proofs::plonk::VerifyingKey::pinned()` emitted by the frozen reference
implementation. The complete artifact is retained in the normative
`test-vectors/coppice_bond_v1.json` file for audit and reproducibility.

Conforming implementations MUST compare/use the exact 32-byte `BOND_VK_ID`
above. They are NOT required to reproduce Rust Debug formatting as part of
normal protocol operation.

The canonical deterministic proof vector uses:

```text
ChaCha20Rng::from_seed([42; 32])
```

for vector reproducibility only. Production provers MUST use cryptographically
secure proof randomness appropriate to the Halo2 proving API.

The normative BondProof vector confirms:

- one accepted 4,960-byte proof;
- rejection after mutation of each of the seven public inputs;
- `position == position_floor` passes;
- `position == position_floor - 1` fails.

The parser resource cap remains:

```text
MAX_BOND_PROOF_LEN = 8192
```

This cap is intentionally larger than the measured proof and is not itself the
canonical proof length.

## P-BOND-005 — BondProof deployment binding

Define helper:

```text
bind32(domain, x[32]) =
    Poseidon(
        field(domain),
        Poseidon(
            little_endian_u128(x[0..16]),
            little_endian_u128(x[16..32])
        )
    )
```

where `field(domain)` is permitted only for domain strings no longer than 16 bytes, padded with zero bytes on the high end and injected as a little-endian `u128`.

Deployment binding:

```text
protocol_binding =
    bind32(
        "CoppiceProtoV1",
        deployment_id
    )
```

## P-BOND-006 — Registration-context binding

```text
registration_digest =
    H(
        "CoppiceRegV1",
        name_id[32] ||
        address_len_u16 ||
        address_bytes
    )
```

Then:

```text
context_binding =
    bind32(
        "CoppiceCtxV1",
        registration_digest
    )
```

## P-BOND-007 — Owner binding

```text
owner_binding =
    bind32(
        "CoppiceOwnerV1",
        owner_pk
    )
```

The verifier reconstructs `protocol_binding`, `context_binding`, and `owner_binding`.

They are not caller-selected opaque values.

## P-BOND-008 — Bond freshness floor

For a REVEAL whose matching COMMIT was mined at height `C`:

```text
floor_height =
    max(
        activation_height - 1,
        C.saturating_sub(bond_note_max_age_blocks)
    )
```

Core supplies the canonical checkpoint for this height. Names v1 consumes it
to obtain:

```text
position_floor =
    ironwood_tree_size_at_end_of(floor_height)
```

The BondProof MUST prove privately:

```text
note_position >= position_floor
```

The proof therefore demonstrates that the note was created after the freshness floor.

Implementation guidance:

- the Merkle path already contains the private 32-bit note position;
- constrain `note_position` as a canonical private `u32`;
- constrain `position_floor` as a canonical public `u32`;
- constrain `delta` as a canonical private `u32`;
- constrain `note_position = position_floor + delta` as an integer relation;
- constrain the sum so it cannot wrap modulo the Pallas field;
- use a reviewed 32-bit range/comparison gadget and include boundary tests.

## P-BOND-009 — Bond anchor rules

REVEAL contains:

```text
bond_anchor_height
bond_anchor
```

Let `C` be the matching COMMIT height and `R` the REVEAL height.

The anchor MUST satisfy:

```text
C <= bond_anchor_height < R
```

Core MUST independently derive from canonical Zcash history:

```text
Ironwood root at end of bond_anchor_height
```

Names v1 MUST validate the caller-supplied `bond_anchor` against the
corresponding Core-derived checkpoint, and it MUST equal that checkpoint's
root.

A proof against an arbitrary caller-supplied root is invalid.

Because `R <= C + commit_ttl_blocks`, the anchor can always be validated from a bounded recent checkpoint window.

## P-BOND-010 — Ironwood checkpoint retention

Core tracks the canonical Ironwood checkpoint sequence:

```rust
pub struct IronwoodCheckpoint {
    pub height: u32,
    pub root: [u8; 32],
    pub tree_size: u32,
}
```

Names v1 requires Core to retain enough history to answer both:

- anchor lookup for current REVEALs;
- freshness position-floor lookup for current REVEALs.

Required protocol window:

```text
checkpoint_retention_blocks =
    bond_note_max_age_blocks + commit_ttl_blocks + 1
```

Names v1 consumes these Core-derived checkpoints for freshness-floor and
bond-anchor validation. It does not own or independently derive the canonical
Ironwood frontier or checkpoint sequence.

The implementation MAY retain more.

It MUST NOT retain less.

The activation checkpoint supplies the first checkpoint.

## P-SPENT-001 — RecentSpent state

The Names application sees every canonical Ironwood nullifier in every canonical block from activation onward.

For each nullifier:

```text
tag = bond_tag(nullifier)
```

The Names application maintains a bounded map:

```rust
BTreeMap<[u8; 32], u32>   // tag -> first_seen_height
```

This is `RecentSpent`.

## P-SPENT-002 — RecentSpent retention theorem

Let:

```text
F = bond_note_max_age_blocks
TTL = commit_ttl_blocks
```

A valid REVEAL at height `R` has COMMIT height:

```text
C >= R - TTL
```

An eligible note was created after:

```text
C - F
```

Therefore any spend of that eligible note before REVEAL must have occurred no earlier than the oldest block in the last:

```text
F + TTL
```

blocks.

Thus retaining recent spent tags for:

```text
recent_spent_retention_blocks =
    F + TTL
```

is sufficient for rejecting all already-spent notes that could satisfy the freshness proof.

No older unrelated global spent tag is needed.

## P-SPENT-003 — RecentSpent pruning

At end of block `H`, define:

```text
retention = bond_note_max_age_blocks + commit_ttl_blocks

oldest_retained_height =
    max(
        activation_height,
        (H + 1).saturating_sub(retention)
    )
```

Remove entries whose:

```text
first_seen_height < oldest_retained_height
```

Use checked arithmetic.

The exact pruning result is canonical protocol state.

## P-SPENT-004 — RecentSpent root

Sort entries lexicographically by `bond_tag`.

```text
RecentSpentRoot =
    H(
        "CoppiceSpentV1",
        oldest_retained_height_u32 ||
        count_u32 ||
        entries
    )
```

Each entry:

```text
bond_tag[32] ||
first_seen_height_u32
```

No sparse Merkle tree is required for RecentSpent in v1.

## P-SPENT-005 — Active-bond index

Maintain a derived index:

```rust
BTreeMap<[u8; 32], String>  // active bond_tag -> name
```

It is not an independently authoritative state object.

It MUST be exactly reconstructible from all `NameRecord`s whose status is `Active`.

On load, rebuild it and reject state containing duplicate active bond tags.

## P-SPENT-006 — Processing Ironwood nullifiers

For every canonical nullifier in a transaction, before applying any Names v1
operation from that transaction:

1. derive `bond_tag`;
2. insert it into RecentSpent if not already present;
3. if `active_bond_index[bond_tag]` exists:
   - fetch the active record;
   - change status to `BondSpent { terminal_height = current_block_height }`;
   - remove the tag from the active bond index.

The name becomes inactive immediately in canonical transaction order.

## P-SPENT-007 — Long-lived active bonds

Suppose a bond remains active for years.

Coppice does not need to remember all unrelated nullifiers from those years.

Every new nullifier is streamed through:

```text
new nullifier
-> bond_tag
-> active_bond_index lookup
```

The one matching nullifier, if it ever appears, changes the record to `BondSpent`.

That terminal status is persistent authenticated name state.

The recent spent entry may later be pruned without losing the fact that the name's bond died.

## P-OP-REVEAL-001 — REVEAL validation

REVEAL SHOULD apply cheap deterministic checks before Halo2 verification.

Recommended order:

1. canonical name;
2. canonical owner key;
3. canonical Unified Address;
4. proof length/resource bounds;
5. recompute commitment;
6. matching COMMIT exists;
7. COMMIT is mature;
8. COMMIT not expired;
9. current name is claimable;
10. matching COMMIT height is at or after the current claim epoch;
11. proposed `bond_tag` is not in RecentSpent;
12. proposed `bond_tag` is not already used by another Active name;
13. anchor height range valid;
14. canonical anchor root known and equal;
15. deterministic freshness `position_floor` found;
16. verify BondProof against exact reconstructed public inputs.

Only then mutate Names application state.

## P-OP-REVEAL-002 — Successful REVEAL

A valid REVEAL:

1. removes the matching pending commitment;
2. replaces an absent or terminal claimable record with:

```rust
NameRecord {
    owner_pk,
    bond_tag,
    sequence: 0,
    address,
    status: Active,
}
```

3. inserts:

```text
active_bond_index[bond_tag] = name
```

If another valid reveal for the same name appears later in canonical order, it sees the Active record and is rejected.

## P-OP-UPDATE-001 — UPDATE transition

UPDATE requires:

- existing name;
- status Active;
- current bond remains active;
- `current.sequence.checked_add(1) == Some(next_sequence)`;
- canonical new Unified Address;
- valid owner signature.

On success:

```text
record.sequence = next_sequence
record.address  = new_address
```

Owner and bond do not change.

## P-OP-RELEASE-001 — RELEASE transition

RELEASE requires:

- existing name;
- status Active;
- current bond remains active;
- `current.sequence.checked_add(1) == Some(next_sequence)`;
- valid owner signature.

On success:

```text
record.sequence = next_sequence
record.status =
    Released {
        terminal_height = current_block_height
    }
```

Remove its tag from `active_bond_index`.

The private ZEC note itself is not spent.

A Coppice-aware wallet will unlock it after canonical reconciliation.

## P-OP-001 — No transfer or rebond

There is no operation that changes:

```text
owner_pk
```

on an Active record.

There is no operation that replaces an Active bond without terminating the registration.

To move a name:

```text
current owner RELEASE
-> wait deterministic reuse delay
-> new claimant COMMIT
-> REVEAL with new owner and bond
```

This is slower than transfer but significantly reduces v1 state-machine and authorization complexity.

## P-SIG-001 — Owner-signature domain

Prefix:

```text
"CoppiceOwnerSigV1" ||
deployment_id[32]
```

UPDATE message:

```text
prefix ||
0x03 ||
name_id[32] ||
previous_record_hash[32] ||
previous_sequence_u64 ||
next_sequence_u64 ||
H("CoppiceAddrV1", new_address_bytes)[32]
```

RELEASE message:

```text
prefix ||
0x04 ||
name_id[32] ||
previous_record_hash[32] ||
previous_sequence_u64 ||
next_sequence_u64
```

Signatures use canonical RedPallas `Signature<SpendAuth>` encoding.

Signature length is exactly 64 bytes.

Verification always uses the owner key in the current authenticated record.

## P-TREE-001 — NameTree

Coppice uses a 256-depth sparse Merkle tree keyed by `name_id`.

Traverse key bits most-significant bit first.

Domains:

```text
"CoppiceNameEmptyV1"
"CoppiceNameLeafV1"
"CoppiceNameNodeV1"
```

Define:

```text
empty[0] =
    H("CoppiceNEmptyV1", [])
```

and:

```text
empty[i + 1] =
    H(
        "CoppiceNNodeV1",
        empty[i] ||
        empty[i]
    )
```

Leaf:

```text
leaf(record) =
    H(
        "CoppiceNLeafV1",
        H("CoppiceRecordV1", record_bytes)
    )
```

Node:

```text
node(left, right) =
    H(
        "CoppiceNNodeV1",
        left[32] ||
        right[32]
    )
```

A proof contains exactly 256 sibling hashes bottom-up.

## P-RESOLVE-001 — Resolution

Core API SHOULD expose:

```rust
pub enum Resolution {
    Active {
        address: String,
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
        sequence: u64,
    },

    CoolingDown {
        reason: TerminalReason,
        terminal_height: u32,
        claimable_from_height: u32,
    },

    Available {
        previous_reason: TerminalReason,
    },

    Absent,
}
```

For a terminal record:

```text
current_height < claimable_from -> CoolingDown
current_height >= claimable_from -> Available
```

`Available` still has no payment destination.

Only `Active` is payable.

## P-CARRIER-001 — Public transport rendezvous

Every Core runtime configuration defines one public incoming capability and one
matching receiver.

All CPV1 carrier outputs target that exact configured receiver using Ironwood
note encryption. Decryptability under the public incoming IVK alone is
insufficient: an output is a carrier only when its decrypted recipient bytes
equal the configured receiver bytes.

Properties:

- incoming viewing capability is public;
- it provides no protocol authority;
- outputs are zero-valued;
- clients can trial-decrypt compact outputs;
- full transactions are fetched only for matching candidate transactions.

If Coppice is later deployed, its rendezvous capability SHOULD be generated
through a transparent no-known-spending-key procedure, but protocol correctness
does not depend on a secret spending key because bulletin outputs are
zero-valued and authorization comes from Coppice cryptography/state.

The integration suite MUST include a Zebra/Z3 test proving that a zero-valued
Ironwood rendezvous output with a correctly calculated conventional ZIP-317 fee
is accepted and mined. Carrier construction MUST use the host wallet's normal
fee calculation; fee cost scales with the number of Ironwood logical actions.

## P-CARRIER-002 — Carrier memo format

This section specifies the Core-owned CPV1 transport. START binds
`CoreRuntimeId` and carries the CA01 application envelope specified by
P-APPLICATION-ENVELOPE-001. A naked application payload or Names-bound START is
not accepted at any runtime height.

Coppice v1 targets the currently deployed NU6.3/v6 Ironwood note-encryption
format, in which each Ironwood output carries exactly 512 bytes of memo
plaintext.

Every Coppice memo uses the ZIP-302 arbitrary-data namespace:

```text
byte 0 = 0xFF
```

The four-byte v1 carrier magic is:

```text
"CPV1"
```

Immediately after the magic is a one-byte frame type:

```text
0x00 = START
0x01 = CONT
```

The exact v1 transport constants are:

```text
frame size          = 512 bytes
magic               = "CPV1"
START type          = 0x00
CONT type           = 0x01
frame_index         = u8
valid frame indices = 0..31
START index         = 0
MAX_FRAMES          = 32
```

Immediately after the frame type is a one-byte `frame_index`.

All frames of one routed application message MUST occur in the same Zcash transaction.
Rendezvous outputs MAY occur in any Ironwood Action order. Canonical carrier
order is reconstructed exclusively by ascending `frame_index`; transaction
builders MAY freely randomize Action positions.

There is exactly one START frame. It has `frame_index = 0` and carries all
carrier-level metadata.

### START frame

```text
zip302_arbitrary_u8(0xFF) ||
magic[4]("CPV1") ||
frame_type_u8(0x00) ||
frame_index_u8(0x00) ||
core_runtime_id[32] ||
frame_count_u8 ||
payload_length_u16 ||
payload_digest[32] ||
start_chunk[0..438] ||
zero_padding
```

START header size:

```text
1 + 4 + 1 + 1 + 32 + 1 + 2 + 32 = 74 bytes
```

START chunk capacity:

```text
512 - 74 = 438 bytes
```

`payload_digest` is:

```text
H("CoppicePayloadV1", payload)
```

### CONT frame

```text
zip302_arbitrary_u8(0xFF) ||
magic[4]("CPV1") ||
frame_type_u8(0x01) ||
frame_index_u8(1..31) ||
continuation_chunk[0..505] ||
zero_padding
```

CONT header size:

```text
1 + 4 + 1 + 1 = 7 bytes
```

CONT chunk capacity:

```text
512 - 7 = 505 bytes
```

CONT frames have indices `1..=31`. Index `0` is reserved for START. No frame
index may be greater than or equal to `MAX_FRAMES`.

Define:

```text
START_CHUNK_CAP = 438
CONT_CHUNK_CAP  = 505
MAX_FRAMES      = 32

MAX_PAYLOAD_LEN =
    START_CHUNK_CAP +
    (MAX_FRAMES - 1) * CONT_CHUNK_CAP
  = 16_093 bytes
```

For a payload of length `L > 0`, the required frame count is:

```text
required_frames(L) =
    1                                      if L <= 438
    1 + ceil((L - 438) / 505)              otherwise
```

`frame_count` MUST equal `required_frames(payload_length)`. Non-final chunks
MUST therefore be full-capacity. The final chunk length is determined exactly
from `payload_length`; no per-frame chunk-length field exists.

All memo bytes after the canonical chunk length MUST be zero.

The decoder MUST operate on the raw 512-byte memo array. It MUST NOT use an API
that strips trailing zero bytes before frame parsing because binary payload data
may legitimately end in `0x00`.

No transport nonce exists. Reconstruction is scoped to rendezvous frames from
one Zcash transaction; frames from different transactions are never merged.
The START payload length and payload digest authenticate the indexed
reconstruction within that transaction, so no cross-transaction nonce is
needed.

No txid grinding exists.

Application routing is inside the authenticated CA01 payload. CPV1 itself
permits exactly one logical application envelope per carrier transaction.

With the current v1 protocol maxima, the largest REVEAL payload is 8,906 bytes.
It therefore requires:

```text
1 START + 17 CONT = 18 frames
```

This is below the 32-frame limit. A typical transaction funding those 18
zero-valued bulletin outputs and returning one Ironwood change output uses
approximately 19 Ironwood Actions, whose Ironwood component is on the order of
61 KiB under the current v6 encoding.

This 512-byte framing is a property of the currently deployed Ironwood
transaction format, not an eternal Zcash assumption. If a future network
upgrade changes memo transport, existing v1 history remains replayable but new
carrier transactions MUST use an explicitly versioned transport adaptation
rather than silently changing this frame format.

## P-CARRIER-003 — Frame validation

For a transaction whose compact Ironwood data indicates one or more outputs
decryptable to the exact configured rendezvous receiver, all matching
full-transaction frames are parsed independently and reordered by `frame_index`.

Decryptability under the runtime rendezvous IVK for another diversified
receiver does not make a transaction a candidate for this runtime.

A valid Coppice carrier for this runtime requires:

- exactly one START frame;
- START to have `frame_index = 0`;
- every CONT to have `1 <= frame_index < 32`;
- `core_runtime_id` in START to equal this runtime;
- `1 <= frame_count <= 32`;
- `0 < payload_length <= MAX_PAYLOAD_LEN`;
- `frame_count == required_frames(payload_length)`;
- exactly one frame for every index in `0..frame_count`;
- no duplicate, missing, or out-of-range frame index;
- no supplied index greater than or equal to `frame_count`;
- every Coppice frame to begin with `0xFF || "CPV1"`;
- no second START frame;
- every non-final chunk to use its complete canonical capacity;
- every byte after the final canonical chunk in each memo to be zero;
- concatenated payload length to equal `payload_length`;
- `H("CoppicePayloadV1", payload)` to equal `payload_digest`.

If the recognized START frame has a different `core_runtime_id`, the
transaction is not a carrier for this runtime and is ignored by this runtime.

Any ambiguity after a START identifying this runtime is malformed transport.
It is delivered as a deterministic application rejection only to the routed
application lifecycle; the transaction's ordinary Ironwood nullifier and
commitment effects still apply.

## P-CARRIER-004 — One logical routed message per transaction

A transaction may have multiple exact-receiver rendezvous outputs because one
payload spans multiple frames.

It MUST reconstruct to at most one logical routed application message.

If the transaction contains:

- two different complete payload digestes;
- duplicated conflicting frame sets;
- multiple complete operations;

the candidate is rejected as malformed.

Chain Ironwood effects still apply.

## P-CARRIER-005 — Compact candidate discovery

For every compact Ironwood action:

1. construct the Ironwood compact note-encryption domain;
2. trial-decrypt the compact ciphertext with the Core runtime's public
   rendezvous Ironwood IVK (provided by the `orchard` crate);
3. compare the decrypted recipient to the exact configured rendezvous receiver;
4. only if both decryption and receiver comparison succeed, mark the
   transaction as requiring full retrieval.

A transaction with no exact-receiver matching action requires no full transaction
fetch for Coppice Core.

## P-CARRIER-006 — Full candidate verification

Before decoding a fetched full transaction:

1. parse it with the correct Zcash consensus branch for its height;
2. verify full transaction `txid` equals compact `txid`;
3. extract the complete Ironwood nullifier and commitment effects and verify
   that they exactly equal the compact effects for that transaction;
4. only after Core effect validation succeeds, inspect the full transaction
   for CPV1 transport: decrypt/extract only outputs addressed to the exact
   configured rendezvous receiver, then perform CPV1/CA01 routing.

Never hardcode one historical branch ID for all future heights.

Use host consensus parameters / branch selection for the actual block height.

A mismatch is a fatal block-input error, not merely a rejected Names application
operation.

## P-CARRIER-007 — Candidate unavailability

If compact discovery says a full transaction is required but the host cannot fetch that full transaction:

```text
DO NOT ADVANCE THE COPPICE RUNTIME PAST THAT BLOCK
```

Do not silently treat it as no routed application message.

The adapter may retry.

This is required for deterministic replay completeness.

## P-REDUCE-001 — Canonical block input

Core Runtime SHOULD consume a wallet-neutral representation similar to:

```rust
pub struct CanonicalBlockInput {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub prev_block_hash: [u8; 32],
    pub transactions: Vec<CanonicalTxInput>,
}

pub struct CanonicalTxInput {
    pub tx_index: u32,
    pub txid: [u8; 32],

    pub ironwood_nullifiers: Vec<[u8; 32]>,
    pub ironwood_commitments: Vec<[u8; 32]>,

    pub candidate_full_tx: Option<Vec<u8>>,
}
```

The librustzcash adapter is responsible for building this from actual CompactBlock data.

## P-REDUCE-002 — Fatal input errors and protocol rejections

This distinction is mandatory.

### Fatal block-input error

Examples:

- wrong next height;
- predecessor mismatch;
- non-increasing tx indexes;
- malformed commitment bytes from supposed canonical source;
- required candidate full tx missing;
- full tx txid mismatch;
- full/compact Ironwood effects mismatch.

Result:

```text
entire block NOT applied
tip NOT advanced
```

### Names application operation rejection

Examples:

- malformed memo frames;
- invalid operation encoding;
- invalid name;
- unavailable name;
- expired COMMIT;
- invalid owner signature;
- spent proposed bond;
- unknown anchor;
- invalid BondProof.

Result:

```text
ordinary canonical Ironwood effects DO apply
invalid Names application operation is a deterministic no-op
tip advances
typed rejection is emitted
```

## P-REDUCE-003 — Atomic block application

`apply_block` MUST be atomic with respect to fatal errors.

Recommended implementation:

1. clone or transactionally stage mutable state;
2. validate top-level block continuity;
3. process all transactions;
4. perform end-of-block pruning/expiry;
5. compute roots and final checkpoint;
6. commit staged state only if no fatal error occurred.

Operation rejections are collected in audit outcomes and do not abort the block.

## P-REDUCE-004 — Per-transaction reduction order

For each transaction in ascending `tx_index`:

1. validate supplied compact/full consistency;
2. process all Ironwood nullifiers;
3. derive RecentSpent tags;
4. terminate any matching active bonds;
5. append all Ironwood commitments to the frontier;
6. decode/reconstruct the optional Core carrier and CA01 route;
7. deliver canonical effects plus the routed message to each active,
   independently owned application;
8. apply at most one Names operation when the route is Coppice Names v1.

The key rule is:

> **Bond spends become visible before a Names v1 operation in the same transaction.**

Therefore an UPDATE or RELEASE cannot rescue a bond that the same transaction already spends.

## P-REDUCE-005 — End-of-block reduction order

After all transactions in block `H`:

1. compute the canonical end-of-block Ironwood root and tree size;
2. append `IronwoodCheckpoint(H, root, size)`;
3. expire pending commitments whose final valid REVEAL block is `H`;
4. prune RecentSpent according to the deterministic rolling window;
5. prune old Ironwood checkpoints outside required retention;
6. compute NameTree root;
7. compute pending commitment root;
8. compute RecentSpent root;
9. compute the Names application state root;
10. atomically advance the Names application tip to `(H, block_hash)`;
11. commit the already-staged Core tip/frontier/checkpoint and application
    state together at the runtime boundary.

## P-REDUCE-006 — Replay tip

```rust
pub struct CoreReplayTip {
    pub height: u32,
    pub block_hash: [u8; 32],
}
```

The block hash MUST be the real host-accepted Zcash block identifier.

Whenever a block hash or transaction ID is serialized into Coppice protocol
state, use the exact underlying 32-byte wire/internal representation supplied by
the corresponding librustzcash `BlockHash` / `TxId` type. Human-facing reversed
display hex is never protocol input. Test vectors MUST freeze this byte order.

No synthetic fixture ID is permitted in production APIs.

Tests MAY use a separate explicit fixture mode.

## P-STATE-ROOT-001 — Coppice state root

At the end of block `H`:

```text
CoppiceStateRoot =
    H(
        "CoppiceStateV1",
        deployment_id[32] ||
        height_u32 ||
        block_hash[32] ||
        ironwood_tree_size_u32 ||
        ironwood_root[32] ||
        NameTreeRoot[32] ||
        PendingCommitmentRoot[32] ||
        RecentSpentRoot[32]
    )
```

Independent implementations at the same canonical tip MUST produce the same root.

## P-REORG-001 — Reorg authority

Coppice does not independently decide which fork is canonical.

The host sync coordinator decides.

The integration contract is conceptually:

```text
host:
    accepted blocks H+1 ... N

Coppice:
    apply them

host:
    detects reorg
    chooses common ancestor R

Coppice:
    rewind_to(R)

host:
    supplies replacement canonical blocks R+1 ...
```

Coppice MAY retain cheap predecessor/height checks as integration assertions.

Those checks do not constitute an independent fork-choice policy.

## P-LIMIT-001 — Resource bounds

Protocol constants:

```text
MAX_NAME_LEN          = 63
MAX_ADDRESS_LEN       = 512
MAX_FRAMES            = 32
START_FRAME_HEADER    = 74
START_CHUNK_CAP       = 438
CONT_FRAME_HEADER     = 7
CONT_CHUNK_CAP        = 505
MAX_PAYLOAD_LEN       = 16_093
MAX_BOND_PROOF_LEN    = 8_192
MAX_TRANSACTION_LEN   = 2_000_000
```

All length checks MUST occur before large allocation.

Proof verification should be attempted only after cheap validation passes.

`MAX_BOND_PROOF_LEN = 8192` is the frozen v1 parser/resource cap. The selected
parallel-Merkle candidate measures 4,960 bytes, leaving substantial margin.
The exact accepted proof serialization remains subject only to freeze gate
F-001.

Under the v1 START/CONT carrier framing, the maximum syntactically valid REVEAL
payload under the resource caps is 8,906 bytes and uses 18 of 32 available
frames.

## P-SEC-001 — Spam and denial-of-service considerations

The public rendezvous can be spammed.

This is unavoidable because it is public.

Mitigations:

- compact trial decryption before full tx fetch;
- Zcash transaction fees paid by spammer;
- one logical routed message per transaction;
- hard frame/payload/proof limits;
- bounded COMMIT TTL;
- bounded RecentSpent state;
- cheap checks before Halo2 verification;
- malformed input is deterministic and non-panicking.

A valid-looking invalid proof still costs verification CPU.

That is accepted in v1 and should be measured.

## P-PRIV-001 — Public and hidden information

Publicly visible after REVEAL:

- name;
- owner public key;
- bond tag;
- address;
- proof bytes;
- proof anchor;
- registration secret.

Still hidden:

- actual bond note commitment;
- nullifier until spend;
- exact value;
- note position;
- receiver;
- spending key;
- wallet account;
- link from bond tag to a particular on-chain note.

A wallet's note/tag matching is local.

Do not query remote services with private note identifiers/nullifiers.

## P-PRIV-002 — Owner-key unlinkability

The default deterministic owner key is name-and-bond specific.

Different names backed by different bond tags derive different owner keys.

This avoids publishing one account-wide owner key across all names.

The KDF relation is not externally visible.

## P-PRIV-003 — Carrier visibility

Coppice carrier outputs are intentionally publicly decryptable by anyone with
the configured rendezvous incoming capability, but only outputs addressed to
the exact configured receiver are carrier inputs for this runtime.

Therefore routed Names v1 operation contents are public protocol data once their
transaction is visible.

Commit/reveal hides the registration preimage only until REVEAL.

Coppice v1 does not claim long-term privacy for names or destination addresses.

## P-SEC-002 — COMMIT/REVEAL front-running property

An observer can copy an entire REVEAL transaction payload after seeing it.

But the commitment binds:

- name;
- owner;
- bond tag;
- destination;
- secret.

A copied valid REVEAL therefore produces the same desired record.

The attacker cannot change ownership or destination without breaking the commitment/BondProof.

The copy may cause the attacker's transaction to be the first canonical carrier, but it does not steal the name.

## P-ERROR-001 — Typed protocol rejections

Core SHOULD expose a stable typed audit enum, including at least:

```rust
InvalidName
InvalidAddress
InvalidOwnerKey
DuplicateCommitment
UnknownCommitment
CommitmentNotMature
CommitmentExpired
NameUnavailable
CommitPredatesClaimEpoch
InvalidSequence
InvalidSignature
BondAlreadyInUse
BondRecentlySpent
InvalidBondAnchorHeight
UnknownBondAnchor
InvalidBondProof
OversizedProof
MalformedCarrier
MalformedOperation
```

These are audit outcomes.

They are not fatal chain-input errors.

## P-VECTOR-001 — Normative test vectors

`test-vectors/` SHOULD contain deterministic vectors for:

- every BLAKE2b personalization constant;
- `NamesDeploymentId`;
- name ID;
- address digest;
- record encoding/hash;
- deterministic owner-key KDF, including counter 0 and a synthetic retry vector;
- owner signature messages;
- registration commitment;
- START frame encoding;
- CONT frame encoding;
- payload digest;
- multi-frame canonical packing;
- bond tag from canonical nullifier;
- BondProof public inputs;
- NameTree root/proofs;
- PendingCommitmentRoot;
- RecentSpentRoot;
- CoppiceStateRoot;
- complete operation encodings.

Use machine-readable JSON with hex strings.

Vectors are normative interoperability material.

## P-INVARIANT-001 — Formal invariants

### Invariant A — chain authority

```text
Coppice never chooses a chain fork independently of the host wallet.
```

### Invariant B — replay independence

```text
Coppice activation is not an account birthday.
```

### Invariant C — deterministic state

```text
same deployment
+ same canonical Zcash history
= same Coppice state root
```

### Invariant D — active bond uniqueness

```text
one bond_tag backs at most one Active name
```

### Invariant E — bond freshness

```text
every accepted registration bond note position
>= deterministic position floor from its COMMIT epoch
```

### Invariant F — spent completeness

For any note capable of satisfying a current REVEAL freshness proof:

```text
every possible prior spend of that note
is represented in RecentSpent
```

### Invariant G — active liveness

```text
new nullifier tag == active bond tag
-> record becomes BondSpent before same-tx Names operation processing
```

### Invariant H — claim epoch

```text
a COMMIT predating the current name claim epoch
can never claim that name
```

## Appendix A — Frozen architecture summary

The intended v1 architecture is:

```text
Zcash canonical chain
    |
    v
public rendezvous candidate discovery
    |
    v
full-transaction validation
    |
    +--> stream every Ironwood nullifier
    |       |
    |       +--> RecentSpent
    |       +--> active bond termination
    |
    +--> append every Ironwood commitment
    |
    +--> reconstruct at most one routed application message
            |
            v
       deterministic application state machine
            |
            v
        Names application state
```

Bond registration uses a private Ironwood note and a native Pasta/Halo2 proof.
Wallet note protection is intentionally outside the consensus-independent
protocol and is specified in `IMPLEMENTATION.md`.

## Appendix B — Items intentionally not in v1

The following are not unspecified features. They do not exist in v1:

- ownership transfer;
- rebonding an active name;
- renewal or expiration;
- auctions;
- governance;
- protocol fees or treasury;
- subnames;
- delegation;
- multisignature owner policies;
- private names;
- remote registry authority.

Adding any of these requires a new protocol version.
