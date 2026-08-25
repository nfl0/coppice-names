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
core_runtime_id.json
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

`core_runtime_id.json` freezes the application-independent `CoreRuntimeId`,
including runtime activation and shared CPV1 rendezvous context.

`application_envelopes.json` freezes the `CoppiceAppIdV1` derivation for the
exact `coppice.names` application identity, Names routing version 1, the CA01
envelope, and the production CPV1 frame bound to `CoreRuntimeId`.
`carrier.json` remains unchanged because it freezes the parameterized CPV1
framing algorithm rather than assigning semantic ownership to its sample
32-byte binding value.

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
