# Coppice Names normative vector manifest

The current repository carries the frozen CNV1 wire vectors only:

```text
names_v1_wire.json
```

`names_v1_wire.json` freezes canonical encodings for `COMMIT`, `REVEAL`,
`UPDATE`, `RENEW`, and `RELEASE`, including explicit replacement and reset
shapes. The reset uses CNV1 revision `0x01`; its vector-set identity is
`dff01501326305709dc1eda3241a92458ce17a3461b6dd254c7f8f841a6932b1`.

The conformance harness is
`crates/coppice-names/tests/names_v1_wire_vectors.rs`; it only asserts the
checked-in bytes. The ignored regeneration test in that file is the sole
regeneration path for a future protocol-version decision and must never
silently replace the frozen vector file.
