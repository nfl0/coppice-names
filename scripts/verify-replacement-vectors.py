#!/usr/bin/env python3
"""Independent replacement Names vector consumer (standard library only)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PALLAS_BASE_MODULUS = int(
    "40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16
)


def h(person: bytes, data: bytes, size: int = 32) -> bytes:
    return hashlib.blake2b(data, digest_size=size, person=person).digest()


def wide(person: bytes, data: bytes) -> bytes:
    return (int.from_bytes(h(person, data, 64), "little") % PALLAS_BASE_MODULUS).to_bytes(
        32, "little"
    )


def framed_digest(parts: list[bytes]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def verifier_id(person: bytes, tag: int, suite: bytes, k: int, proof_bytes: int, fp: bytes) -> bytes:
    manifest = b"CNV2V" + bytes([1, tag]) + suite + bytes([k]) + proof_bytes.to_bytes(2, "big") + fp
    assert len(manifest) == 74
    return h(person, manifest)


def parse_operation(raw: bytes, reveal_proof_bytes: int, refresh_proof_bytes: int) -> dict:
    assert raw[:4] == b"CNV2" and raw[4] == 1
    tag = raw[5]
    if tag == 0:
        assert len(raw) == 38 and int.from_bytes(raw[6:], "little") not in (0,) and int.from_bytes(raw[6:], "little") < PALLAS_BASE_MODULUS
        return {"tag": tag, "commitment": raw[6:]}

    cursor = 6
    name_len = raw[cursor]
    cursor += 1
    name = raw[cursor : cursor + name_len]
    cursor += name_len
    assert 1 <= name_len <= 63
    assert name[0] != 45 and name[-1] != 45
    assert all(97 <= byte <= 122 or 48 <= byte <= 57 or byte == 45 for byte in name)
    height = int.from_bytes(raw[cursor : cursor + 4], "big")
    cursor += 4
    tx_index = int.from_bytes(raw[cursor : cursor + 4], "big")
    cursor += 4
    txid = raw[cursor : cursor + 32]
    cursor += 32
    predecessor_action = None
    if tag == 2:
        predecessor_action = int.from_bytes(raw[cursor : cursor + 4], "big")
        cursor += 4
    else:
        assert tag == 1
    ua_len = int.from_bytes(raw[cursor : cursor + 2], "big")
    cursor += 2
    ua = raw[cursor : cursor + ua_len]
    cursor += ua_len
    assert 1 <= ua_len <= 1024 and ua.startswith(b"uregtest1")
    action_index = int.from_bytes(raw[cursor : cursor + 4], "big")
    cursor += 4
    future_nf = raw[cursor : cursor + 32]
    cursor += 32
    proof = raw[cursor:]
    assert len(proof) == (reveal_proof_bytes if tag == 1 else refresh_proof_bytes)
    return {
        "tag": tag,
        "name": name,
        "height": height,
        "tx_index": tx_index,
        "txid": txid,
        "predecessor_action": predecessor_action,
        "ua": ua,
        "action_index": action_index,
        "future_nf": future_nf,
        "proof": proof,
    }


def encode_operation(operation: dict) -> bytes:
    out = bytearray(b"CNV2\x01" + bytes([operation["tag"]]))
    if operation["tag"] == 0:
        out += operation["commitment"]
        return bytes(out)
    out += bytes([len(operation["name"])]) + operation["name"]
    out += operation["height"].to_bytes(4, "big")
    out += operation["tx_index"].to_bytes(4, "big") + operation["txid"]
    if operation["tag"] == 2:
        out += operation["predecessor_action"].to_bytes(4, "big")
    out += len(operation["ua"]).to_bytes(2, "big") + operation["ua"]
    out += operation["action_index"].to_bytes(4, "big") + operation["future_nf"]
    out += operation["proof"]
    return bytes(out)


def main() -> None:
    default = Path(__file__).resolve().parents[1] / "test-vectors" / "replacement_protocol.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    fixture = json.loads(path.read_text())
    identity = fixture["identity"]
    params = fixture["parameters"]
    name = fixture["name"]
    fields = fixture["fields"]

    application_id = h(b"CoppiceAppIdV1\0\0", b"coppice.names")
    assert application_id.hex() == identity["names_application_id_hex"]
    suite_manifest = identity["verifier_suite_manifest_utf8"].encode()
    suite = h(b"CoppiceN2VrfS", suite_manifest)
    assert suite.hex() == identity["verifier_suite_id_hex"]
    reveal_fp = bytes.fromhex(identity["reveal_key_fingerprint_hex"])
    refresh_fp = bytes.fromhex(identity["refresh_key_fingerprint_hex"])
    reveal_id = verifier_id(
        b"CoppiceN2ReVr", 1, suite, identity["circuit_k"], identity["reveal_proof_bytes"], reveal_fp
    )
    refresh_id = verifier_id(
        b"CoppiceN2RfVr", 2, suite, identity["circuit_k"], identity["refresh_proof_bytes"], refresh_fp
    )
    assert reveal_id.hex() == identity["reveal_verifier_id_hex"]
    assert refresh_id.hex() == identity["refresh_verifier_id_hex"]

    manifest_path = Path(__file__).resolve().parents[1] / "ruleset" / "names-v2.json"
    manifest = json.loads(manifest_path.read_text())
    canonical_manifest = json.dumps(
        manifest, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode()
    assert manifest["ruleset_revision"] == identity["ruleset_revision"]
    ruleset_fingerprint = h(b"CoppiceN2Rule", canonical_manifest)
    assert ruleset_fingerprint.hex() == identity["ruleset_fingerprint_hex"]

    preimage = (
        b"CND2"
        + bytes([identity["deployment_preimage_revision"]])
        + bytes.fromhex(identity["core_runtime_id_hex"])
        + application_id
        + fixture["application_version"].to_bytes(2, "big")
        + ruleset_fingerprint
        + params["activation_height"].to_bytes(4, "big")
        + params["epoch_blocks"].to_bytes(4, "big")
        + params["window_blocks"].to_bytes(4, "big")
        + params["commit_maturity_blocks"].to_bytes(4, "big")
        + params["commit_ttl_blocks"].to_bytes(4, "big")
        + params["lease_blocks"].to_bytes(4, "big")
        + params["cooldown_blocks"].to_bytes(4, "big")
        + params["bond_zatoshis"].to_bytes(8, "big")
        + bytes([63])
        + (1024).to_bytes(2, "big")
        + reveal_id
        + refresh_id
    )
    assert len(preimage) == 206 and preimage.hex() == identity["deployment_preimage_hex"]
    deployment_id = h(b"CoppiceN2Dep", preimage)
    assert deployment_id.hex() == identity["deployment_id_hex"]

    canonical_name = name["canonical"].encode()
    name_id = wide(b"CoppiceN2Name", bytes([len(canonical_name)]) + canonical_name + b"\0")
    assert name_id.hex() == name["name_id_hex"] and int.from_bytes(name_id, "little") != 0
    route_common = deployment_id + name_id
    route_ivk = h(b"CoppiceN2RteD", route_common) + wide(b"CoppiceN2RteI", route_common + b"\0")
    assert route_ivk.hex() == name["route_ivk_hex"]

    span = params["epoch_blocks"] - params["window_blocks"] + 1
    offset = int.from_bytes(h(b"CoppiceN2Off", route_common)[:8], "little") % span
    for epoch_key, window_key in (("reveal_epoch", "reveal_window"), ("refresh_epoch", "refresh_window")):
        epoch = fixture["schedule"][epoch_key]
        start = params["activation_height"] + epoch * params["epoch_blocks"] + offset
        assert fixture["schedule"][window_key] == [start, start + params["window_blocks"]]

    operations = {}
    encoded = []
    for vector in fixture["operations"]:
        raw = bytes.fromhex(vector["hex"])
        assert len(raw) == vector["bytes"]
        parsed = parse_operation(raw, identity["reveal_proof_bytes"], identity["refresh_proof_bytes"])
        assert encode_operation(parsed) == raw
        if "proof_hex" in vector:
            assert parsed["proof"].hex() == vector["proof_hex"]
        operations[vector["id"]] = parsed
        encoded.append(raw)

    commit = operations["commit"]
    reveal = operations["reveal"]
    refresh = operations["refresh"]
    schedule = fixture["schedule"]
    assert commit["commitment"].hex() == fields["commitment_hex"]
    assert reveal["height"] == schedule["commit_height"] and reveal["txid"] == bytes([10]) * 32
    assert schedule["reveal_height"] - reveal["height"] == params["commit_maturity_blocks"]
    assert reveal["name"] == canonical_name and reveal["future_nf"].hex() == fields["reveal_future_nullifier_hex"]
    assert refresh["height"] == schedule["reveal_height"] and refresh["txid"] == bytes([20]) * 32
    assert refresh["predecessor_action"] == reveal["action_index"] == 0
    assert refresh["name"] == canonical_name and refresh["future_nf"].hex() == fields["refresh_future_nullifier_hex"]
    assert schedule["refresh_epoch"] > schedule["reveal_epoch"]

    reducer = fixture["reducer"]
    assert reducer["lifecycle"] == "Active" and reducer["resolved_ua"] == name["ua"]
    assert reducer["head_height"] == schedule["refresh_height"]
    assert reducer["head_txid_hex"] == (bytes([30]) * 32).hex()
    assert reducer["head_action_index"] == refresh["action_index"]
    assert reducer["head_commitment_hex"] == fields["refresh_action_commitment_hex"]
    assert reducer["head_future_nullifier_hex"] == fields["refresh_future_nullifier_hex"]
    assert reducer["expiry_height"] == schedule["refresh_height"] + params["lease_blocks"]

    digest_parts = [
        preimage,
        route_ivk,
        bytes.fromhex(name["route_receiver_hex"]),
        bytes.fromhex(fields["reveal_statement_digest_hex"]),
        bytes.fromhex(fields["refresh_statement_digest_hex"]),
        *encoded,
    ]
    assert framed_digest(digest_parts) == fixture["vector_set_sha256"]
    print(f"independent replacement vectors verified: {fixture['vector_set_sha256']}")


if __name__ == "__main__":
    main()
