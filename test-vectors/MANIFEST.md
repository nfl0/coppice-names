# Coppice Names normative vector manifest

The current repository carries the frozen CNV2 wire vectors only:

```text
names_v2_wire.json
```

`names_v2_wire.json` freezes canonical encodings for `COMMIT`, `REVEAL`,
`UPDATE`, `RENEW`, and `RELEASE`, including explicit replacement and reset
shapes. The corrected release uses CNV2 revision `0x02` and vector-set
identity
`0379bf3bf665d3d0ce3a8c9b3a82bf6b67c01a33dc11a26b1b44bd1cd013a556`.

The conformance harness is
`crates/coppice-names/tests/names_v2_wire_vectors.rs`; it only asserts the
checked-in bytes. The ignored regeneration test in that file is the sole
regeneration path for a future protocol-version decision and must never
silently replace the frozen vector file.
