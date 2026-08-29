# Coppice Names normative vector manifest

The current repository carries the frozen Names v1 CNV1 wire artifact:

```text
names_v1_wire.json
```

`names_v1_wire.json` freezes canonical encodings for `COMMIT`, `REVEAL`,
`UPDATE`, `RENEW`, and `RELEASE`, including explicit replacement and reset
shapes. The reset uses CNV1 revision `0x01`; its vector-set identity is
`dff01501326305709dc1eda3241a92458ce17a3461b6dd254c7f8f841a6932b1`.
The checked-in file SHA-256 is
`0aeb8795386c47f235375a648b0a3c512e75c8f3d9a5b40ae8c224d0807ef40a`.

The associated frozen state-note verifying-key identities are:

- transition: `5ed1a1385f15e0e13e284cf1a7c319449d42b4902abc57b5ebefb60d04995cc1`
- genesis: `81aa1ade09b0ca86eb80c021a66e2cf629875ecab258a99a4a2ecd0df2c7f5ae`

These identities and vectors were regenerated against the current
Zakura-backed source (`orchard-coppice-zakura` `zakura-port` at
`0e09398970130b9510ce5011129acafc5039e79f`) and reproduced the checked-in
bytes exactly. The file SHA-256 is
`0aeb8795386c47f235375a648b0a3c512e75c8f3d9a5b40ae8c224d0807ef40a`.

The conformance harness is
`crates/coppice-names/tests/names_v1_wire_vectors.rs`; it only asserts the
checked-in bytes. The ignored regeneration test in that file is the sole
regeneration path for a future protocol-version decision and must never
silently replace the frozen vector file.
