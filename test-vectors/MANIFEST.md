# Coppice v1 Normative Vector Manifest

This directory manifest defines the normative vector set for the frozen v1
protocol. All required files are present. Do not populate expected values by
hand from guesses. Generate any future vector for a new protocol version from
the reference implementation, independently cross-check the primitive where
practical, and commit the JSON as immutable protocol evidence.

Required files:

```text
hashes.json
deployment.json
application_envelopes.json
names.json
owner_keys.json
bond_tags.json
operations.json
carrier.json
records.json
name_tree.json
pending.json
recent_spent.json
state_roots.json
transitions.json
reorg.json
coppice_bond_v1.json
```

`carrier.json` freezes the indexed CPV1 transport: one-byte frame indices,
438/505-byte chunk capacities, permutation-independent reconstruction, and the
16,093-byte maximum payload.

`deployment.json` freezes the existing Names-specific deployment identity. Its
`CoppiceDeployV1` output is the byte-for-byte `NamesDeploymentId`; it is not the
generic runtime identity.

The application vectors reference the generic `CoreRuntimeId` vector owned by
the Coppice Core repository. Names does not copy or redefine that identity.

`application_envelopes.json` freezes the `CoppiceAppIdV1` derivation for the
exact `coppice.names` application identity, Names routing version 1, the CA01
envelope, and the production CPV1 frame bound to `CoreRuntimeId`.
`carrier.json` remains unchanged because it freezes the parameterized CPV1
framing algorithm rather than assigning semantic ownership to its sample
32-byte binding value.

`application_envelopes.json`, `carrier.json`, and `reorg.json` are retained
here as Names interoperability oracles because their frozen samples bind
NamesDeploymentId, `coppice.names`, or Names operation outcomes. The generic
CPV1/CA01 mechanics and replay property are specified and versioned by Coppice
Core.

Every vector entry SHOULD contain:

```json
{
  "id": "stable-human-readable-id",
  "requirement_ids": ["P-..."],
  "inputs": {},
  "expected": {},
  "valid": true
}
```

Invalid vectors additionally contain:

```json
{
  "expected_error": "TypedProtocolError"
}
```

The frozen `coppice_bond_v1.json` freeze gate F-001 includes:

- exact circuit/source identifier;
- `k = 11`;
- IPA parameter construction identifier;
- transcript identifier;
- canonical verifier/VK identifier;
- all seven public inputs as canonical 32-byte field encodings;
- accepted proof bytes;
- proof byte length;
- one mutation failure for every public input;
- `position == floor`;
- `position == floor - 1`;
- below-minimum-value failure;
- bad Merkle path/root failure;
- wrong spend-authority failure.

The conformance harness MUST consume these files without regenerating expected
values during the test run.

## Names v2 wire vectors

`names_v2_wire.json` freezes the experimental Names v2 CNV2 canonical
encodings for the full operation family: `commit`,
`reveal_first_registration`, `reveal_explicit_replacement`,
`reveal_no_predecessor_reset_shaped` (byte-identical to the first
registration encoding by construction), `update`, `renew`, and `release`.
The frozen inputs, per-vector envelope bytes, and the SHA-256 vector-set
identity are recorded in the file. The conformance harness is
`crates/coppice-names/tests/names_v2_wire_vectors.rs`; it only asserts. The
ignored `generate_names_v2_wire_vectors` test in the same file is the sole
regeneration path for a future protocol-version bump and must never silently
replace the frozen file.
