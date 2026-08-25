# Internal Codex Session Orientation

This is an internal agent/development document, not the public contribution
entry point. Human contributors should start with `../README.md` and
`../CONTRIBUTING.md`.

It records the current Coppice v1 design contract.

The repository already contains a functioning Coppice implementation. Do **not**
start a clean-room rewrite unless a later task explicitly requires one.

For every task:

1. Read `docs/PROTOCOL_SPEC.md` for normative behavior.
2. Read only the relevant parts of `docs/IMPLEMENTATION.md`.
3. Treat `test-vectors/` as interoperability oracles.
4. Inspect the current implementation before editing.
5. Reuse the existing vendored `orchard` cryptographic work used by Ironwood.
6. Make only the bounded change requested by the current task.
7. If the requested change conflicts with the frozen protocol or exposes a
   design flaw, stop and report the issue instead of improvising.
8. Run relevant focused checks. Run the full Coppice workspace tests when an
   executable or normative/generated change warrants them; documentation-only
   work uses lightweight validation.
9. Commit and push successful work when the task prompt explicitly requests it.

Authority order:

```text
docs/PROTOCOL_SPEC.md
    >
test-vectors/
    >
docs/IMPLEMENTATION.md
    >
superseded Coppice behavior/docs
```

Frozen BondProof anchors include:

```text
source circuit commit:
a9521cdf995ffcfd2627ddfdd750253512172d73

vector/final HEAD:
cf9f7102ddec7f6fb6133b2299a11e71e9ffc8ce

Halo2:
0.3.2 / IPA Vesta / k=11 / Blake2b+Challenge255

BOND_VK_ID:
a16074cfadabc4c24bf58732389a4f2d574e25c43f169239ec21da852f5f7adc
```

The intended development process is incremental: one narrowly scoped task per
Codex session step, followed by human/model review before the next change.
