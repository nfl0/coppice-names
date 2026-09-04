# Names v2 authority matrix

Status: internal assurance evidence for the undeployed Names v2 protocol.

This document identifies the authority for every acceptance rule used by
REVEAL and REFRESH. It is an audit map, not an independent audit report. The
normative rules remain in `SPECIFICATION.md`; source paths below identify the
current implementation evidence.

## Authority classes

| Class | Meaning |
| --- | --- |
| Zcash consensus | A fact established by validation of the containing canonical Zcash transaction or block. Names does not re-prove it. |
| Authenticated host fact | Data the host must bind to canonical compact or full transaction effects before admission to the reducer. |
| Reducer rule | Deterministic Names state-transition logic evaluated during canonical replay. |
| Public proof input | A replay-constructed fact included in the operation-specific Poseidon statement digest. |
| Private circuit constraint | A relation established by the Names Halo2 circuit from hidden witness material. |

No single class replaces another. Proof validity does not authenticate a block,
make a stale predecessor current, validate an operation window, or establish
canonical ordering.

## Common transaction and replay authority

| ID | Requirement | Primary authority | Required supporting authority | Implementation evidence |
| --- | --- | --- | --- | --- |
| C-01 | Block and transaction belong to the selected canonical Zcash branch. | Zcash consensus | Authenticated host fact | `publication.rs`, `reducer.rs` |
| C-02 | Full transaction bytes match authenticated compact effects. | Authenticated host fact | Zcash consensus | `transport.rs` (`UnauthenticatedFullTransaction`) |
| C-03 | Blocks have exact height and previous-hash continuity. | Reducer rule | Authenticated host fact | `reducer.rs` (`WrongHeight`, `WrongPreviousHash`) |
| C-04 | Transactions and actions have canonical indexes. | Reducer rule | Authenticated host fact | `reducer.rs` (`NonCanonicalTransactionIndex`, `NonCanonicalActionIndex`) |
| C-05 | Bulletin is canonical, correctly framed, and published on its operation route. | Reducer rule | Authenticated host fact | `codec.rs`, `transport.rs`, `publication.rs` |
| C-06 | Carrier note has zero value. | Zcash consensus | Authenticated host fact and reducer rule | `transport.rs` (`NonZeroCarrierValue`) |
| C-07 | Deployment and proof verifier identities are the selected identities. | Reducer rule | Public proof input | `deployment.rs`, `proof.rs` |
| C-08 | Current-head spends remain visible even when the bulletin is absent or rejected. | Reducer rule | Authenticated action nullifiers | `reducer.rs`; independent trace corpus; Lean `rejected_bulletin_does_not_hide_spend` |
| C-09 | The first canonically ordered eligible operation wins a conflict. | Reducer rule | C-01 through C-04 | `reducer.rs`; independent trace corpus; Lean `first_canonical_valid_unique` |

## REVEAL

| ID | Requirement | Primary authority | Public proof input | Private circuit constraint | Implementation evidence |
| --- | --- | --- | --- | --- | --- |
| R-01 | Name and UA are canonical for the deployment network. | Reducer rule | `NameId`, canonical UA | Statement digest equality | `protocol.rs`, `statement.rs` |
| R-02 | Name has no head or its head is Claimable. | Reducer rule | No | No | `reducer.rs`; Lean `revealEligible` |
| R-03 | Inclusion height is in the deterministic name window. | Reducer rule | Inclusion epoch | Statement digest equality only | `schedule.rs`, `reducer.rs` |
| R-04 | Exact `CommitRef` exists on the canonical branch. | Authenticated host fact | `CommitRef` and COMMIT value | Statement digest equality | `resolver.rs`, `reducer.rs` |
| R-05 | Referenced COMMIT precedes REVEAL and is mature. | Reducer rule | `CommitRef`, inclusion epoch | No | `reducer.rs` |
| R-06 | Referenced COMMIT is not expired. | Reducer rule | `CommitRef`, inclusion epoch | No | `reducer.rs` |
| R-07 | Declared action index exists in this transaction. | Authenticated host fact | Action index | Statement digest equality | `reducer.rs` |
| R-08 | Designated action nullifier/rho matches the action. | Authenticated host fact | Action nullifier | Successor rho equality | `proof.rs`; `state_note_binding/v2.rs` |
| R-09 | Designated action commitment matches the action. | Authenticated host fact | Action commitment | Successor extracted commitment equality | Same as R-08 |
| R-10 | Successor future nullifier matches the successor bond note. | Authenticated host fact | Successor future nullifier | Successor nullifier derivation equality | Same as R-08 |
| R-11 | Prover knows the hidden owner spending authority. | Private circuit constraint | Owner is hidden | Spend-authorizing key knowledge | `state_note_binding/v2.rs` |
| R-12 | Successor note is controlled by that hidden authority. | Private circuit constraint | UA does not establish bond ownership | Successor recipient derived from the same FVK | Same as R-11 |
| R-13 | COMMIT secret is nonzero and known. | Private circuit constraint | Secret is hidden | Nonzero inverse gate and witnessed secret | Same as R-11 |
| R-14 | COMMIT opens to deployment, name, epoch, hidden owner, and secret. | Private circuit constraint | Deployment, NameId, epoch, COMMIT value | Owner and secret opening recomputation | `statement.rs`; `state_note_binding/v2.rs` |
| R-15 | Successor bond value is exactly 100,000,000 zatoshis. | Private circuit constraint | Exact bond constant in statement digest | Note value equals constrained bond constant | Same as R-14 |
| R-16 | REVEAL proof verifies under the deployment-selected verifier. | Reducer rule | Complete REVEAL statement digest | All R-08 through R-15 | `proof.rs`, `deployment.rs`, `reducer.rs` |
| R-17 | Accepted producer and lease derive only from canonical inclusion data. | Reducer rule | No | No | `reducer.rs`; Lean model |

## REFRESH

| ID | Requirement | Primary authority | Public proof input | Private circuit constraint | Implementation evidence |
| --- | --- | --- | --- | --- | --- |
| F-01 | Name and UA are canonical for the deployment network. | Reducer rule | `NameId`, canonical UA | Statement digest equality | `protocol.rs`, `statement.rs` |
| F-02 | Referenced predecessor `StateRef` is the exact current accepted head. | Reducer rule | Predecessor `StateRef` | Statement digest equality | `reducer.rs`; Lean `stale_lineage_rejected` |
| F-03 | Predecessor is Active at inclusion. | Reducer rule | Predecessor epoch and inclusion epoch | No | `reducer.rs`; Lean lifecycle lemmas |
| F-04 | Inclusion height is in the deterministic name window. | Reducer rule | Inclusion epoch | Statement digest equality only | `schedule.rs`, `reducer.rs` |
| F-05 | Inclusion epoch is strictly later than the predecessor producer epoch. | Reducer rule | Both epochs | Statement digest equality | `reducer.rs`; Lean `same_epoch_refresh_rejected` |
| F-06 | Declared action index exists in this transaction. | Authenticated host fact | Action index | Statement digest equality | `reducer.rs` |
| F-07 | Action spends the accepted predecessor future nullifier. | Authenticated host fact and reducer rule | Action nullifier and predecessor future nullifier | Predecessor nullifier equality | `reducer.rs`, `proof.rs` |
| F-08 | Predecessor commitment matches accepted state. | Reducer rule | Predecessor commitment | Predecessor extracted commitment equality | `reducer.rs`; `state_note_binding/v2.rs` |
| F-09 | Prover knows the predecessor hidden owner authority. | Private circuit constraint | Owner is hidden | Spend-authorizing key knowledge | `state_note_binding/v2.rs` |
| F-10 | Successor uses the same hidden authority; transfer is rejected. | Private circuit constraint | Owner is hidden | Shared predecessor/successor recipient derivation | Same as F-09 |
| F-11 | Predecessor bond value is exactly 100,000,000 zatoshis. | Private circuit constraint | Exact bond constant in statement digest | Predecessor note value equals constrained bond | Same as F-09 |
| F-12 | Successor bond value is exactly 100,000,000 zatoshis. | Private circuit constraint | Exact bond constant in statement digest | Successor note value equals the same constrained bond | Same as F-09 |
| F-13 | Successor rho equals the predecessor nullifier. | Private circuit constraint | Action nullifier | Successor rho and predecessor nullifier equality | Same as F-09 |
| F-14 | Successor action commitment matches the successor note. | Authenticated host fact | Action commitment | Successor extracted commitment equality | `proof.rs`; `state_note_binding/v2.rs` |
| F-15 | Successor future nullifier matches the successor note. | Authenticated host fact | Successor future nullifier | Successor nullifier derivation equality | Same as F-14 |
| F-16 | REFRESH proof verifies under the deployment-selected verifier. | Reducer rule | Complete REFRESH statement digest | All F-07 through F-15 | `proof.rs`, `deployment.rs`, `reducer.rs` |
| F-17 | Replacement starts a new lease and stale-lineage spend processing cannot terminate it. | Reducer rule | No | No | `reducer.rs`; Lean `accepted_replacement_survives_old_spend` |

## Mutation coverage map

| Mutation | Required rejection evidence |
| --- | --- |
| Owner or spending key | Circuit witness mutation fails; a successor under a different owner cannot satisfy the relation. |
| Predecessor reference, commitment, epoch, or future nullifier | Statement mutation fails verification; stale-lineage reducer tests reject before proof authority can replace state. |
| Predecessor or successor bond value | Circuit witness with a non-exact note value fails. |
| Deployment | Public statement mutation fails verification; mismatched deployment/verifier identity is rejected by configuration. |
| Action index | Public statement mutation fails verification and missing action index fails reducer validation. |
| Action commitment | Public statement mutation fails verification and authenticated action mismatch fails acceptance. |
| Action or successor nullifier | Public statement mutation fails verification and authenticated spend mismatch fails acceptance. |
| Whole statement or operation tag | Digest mutation and REVEAL/REFRESH cross-verifier substitution fail. |
| Verifier or verifying-key identity | Cross-operation verifier use fails; deployment ID changes when verifier fingerprints change. |

## Assurance boundary

The Lean Names model proves reducer properties under authenticated-input and
proof-verdict assumptions. The Rust circuit tests and real-proof mutations are
implementation-agreement evidence. Ironwood's checked-in Rust-to-Lean fixtures
are also concrete implementation-agreement evidence only. None of these is a
proof of Halo2, IPA, transcript, curve, hash, compiler, or hardware soundness.

All PR-02 results are internally reviewed. They MUST NOT be described as an
independent audit, external audit, or independent cryptographic assurance.
