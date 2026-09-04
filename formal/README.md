# Coppice Names formal semantic model

This is the pinned consumer for the internally reviewed Lean 4 model of the
normative Names state semantics. The authoritative sources live in the
[`nfl0/ironwood`](https://github.com/nfl0/ironwood) fork under
`Zcash/Coppice/Names/` at commit
`57004513532fea990ae760ce573497bcade02312`, based on upstream
`zcash/ironwood` commit
`ad4a6ad8f75a64368bae4186006480410a687cce`.

The model is derived from `docs/SPECIFICATION.md`, not from Rust control flow.
It is isolated from the Ironwood circuit model and is included in Ironwood's
normal `Zcash` build target. Every public theorem is also pinned by
`Zcash.Meta.AxiomCheck.assert_axioms` in `Zcash/TrustBoundary.lean`.

The toolchain is pinned by `lean-toolchain` to
`leanprover/lean4:v4.30.0`. With `elan` available, build from this directory
with:

```sh
lake update
lake build --wfail
```

The model covers one name's accepted head, lifecycle,
first-canonical-valid selection, REVEAL/REFRESH eligibility, authenticated
action-nullifier spentness, exact-name filtering, replay, and rollback. The
proofs establish:

- relational step determinism;
- uniqueness and ordering of first-canonical-valid selection;
- terminal, last-cooldown, first-Missing, and exact compaction behavior;
- stale-predecessor and same-epoch REFRESH rejection;
- ordinary-spend termination even for an inert bulletin;
- protection of a newly accepted replacement from the old-head spend pass;
- rollback and deterministic reapply equivalence; and
- full/exact replay equivalence for a requested name under authenticated-input
  assumptions.

The model normalizes state at block start and proves that a terminal head is
retained through the final cooldown block, deleted at the first Missing block,
and observationally equivalent for payable resolution before and after the
representation change.

## Assurance boundary

This model assumes its events already contain canonical chain order,
authenticated action effects, canonical decoded values, admissible referenced
COMMIT evidence, and a proof-verification verdict. It does not prove BLAKE2b,
Poseidon, Pallas, Orchard, Halo2, or Zcash consensus soundness. The concrete
Rust mutation tests and verifier fixtures establish implementation agreement
at those boundaries, not a proof of Halo2 soundness.

These results are internal formal assurance. They are not an independent or
external audit.
