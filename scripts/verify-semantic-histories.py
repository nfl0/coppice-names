#!/usr/bin/env python3
"""Specification-derived Coppice Names semantic history checker.

This standard-library-only model intentionally does not import, invoke, or
translate Rust implementation code. Cryptographic proof validity is an
authenticated boolean input; statement construction and proof-system soundness
belong to the separate cryptographic assurance workstream.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

PALLAS_BASE_MODULUS = int(
    "40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16
)


class SemanticError(Exception):
    pass


def parse_field(value: int | str) -> int:
    if isinstance(value, str):
        encoded = bytes.fromhex(value)
        if len(encoded) != 32:
            raise SemanticError("field hex must encode 32 bytes")
        value = int.from_bytes(encoded, "little")
    if not isinstance(value, int):
        raise SemanticError("field must be an integer or little-endian hex string")
    if value < 0 or value >= PALLAS_BASE_MODULUS:
        raise SemanticError("non-canonical field")
    return value


def field_hex(value: int | str) -> str:
    value = parse_field(value)
    return value.to_bytes(32, "little").hex()


def parse_name(value: str) -> str:
    bare = value[:-4] if value.endswith(".zec") else value
    encoded = bare.encode("ascii", errors="strict")
    if (
        not encoded
        or len(encoded) > 63
        or encoded[0] == 45
        or encoded[-1] == 45
        or any(not (97 <= byte <= 122 or 48 <= byte <= 57 or byte == 45) for byte in encoded)
    ):
        raise SemanticError("invalid name")
    return bare


def name_id(name: str) -> bytes:
    encoded = parse_name(name).encode()
    for counter in range(256):
        digest = hashlib.blake2b(
            bytes([len(encoded)]) + encoded + bytes([counter]),
            digest_size=64,
            person=b"CoppiceN2Name",
        ).digest()
        candidate = int.from_bytes(digest, "little") % PALLAS_BASE_MODULUS
        if candidate:
            return candidate.to_bytes(32, "little")
    raise SemanticError("name hash exhausted")


def block_hash(branch_byte: int, height: int) -> str:
    if not 0 <= branch_byte <= 255 or not 0 <= height <= 0xFFFFFFFF:
        raise SemanticError("invalid block hash template")
    return (bytes([branch_byte]) * 28 + height.to_bytes(4, "big")).hex()


def bytes32(value: str) -> bytes:
    encoded = bytes.fromhex(value)
    if len(encoded) != 32:
        raise SemanticError("expected 32-byte hex value")
    return encoded


def validate_ua(value: str, network: str = "regtest") -> None:
    prefixes = {"main": "u1", "test": "utest1", "regtest": "uregtest1"}
    if not isinstance(value, str) or not 0 < len(value.encode()) <= 1024:
        raise SemanticError("invalid UA length")
    if not value.startswith(prefixes[network]):
        raise SemanticError("wrong UA network")


def ref_key(reference: dict[str, Any]) -> tuple[int, int, str]:
    return (reference["height"], reference["tx_index"], reference["txid_hex"])


def state_ref(height: int, transaction: dict[str, Any], action_index: int) -> dict[str, Any]:
    return {
        "height": height,
        "tx_index": transaction["tx_index"],
        "txid_hex": transaction["txid_hex"],
        "action_index": action_index,
    }


def validate_parameters(parameters: dict[str, Any]) -> None:
    window = parameters["window_blocks"]
    maturity = parameters["commit_maturity_blocks"]
    ttl = parameters["commit_ttl_blocks"]
    epoch = parameters["epoch_blocks"]
    if not (
        window > 0
        and window <= maturity
        and maturity < ttl
        and ttl < epoch
        and parameters["lease_blocks"] > epoch
        and parameters["cooldown_blocks"] == epoch
    ):
        raise SemanticError("invalid parameters")


class Reducer:
    def __init__(self, parameters: dict[str, Any], activation_parent_hash: str):
        validate_parameters(parameters)
        self.parameters = copy.deepcopy(parameters)
        self.next_height = parameters["activation_height"]
        self.tip: dict[str, Any] | None = None
        self.previous_hash = activation_parent_hash
        self.commits: dict[tuple[int, int, str], int] = {}
        self.heads: dict[str, dict[str, Any]] = {}
        self.history: list[dict[str, Any]] = []

    def clone(self) -> "Reducer":
        return copy.deepcopy(self)

    def operation_window(self, name: str, height: int) -> bool:
        p = self.parameters
        if height < p["activation_height"]:
            return False
        epoch = (height - p["activation_height"]) // p["epoch_blocks"]
        epoch_start = p["activation_height"] + epoch * p["epoch_blocks"]
        identity = name_id(name)
        deployment = bytes.fromhex(p["deployment_id_hex"])
        digest = hashlib.blake2b(
            deployment + identity, digest_size=32, person=b"CoppiceN2Off"
        ).digest()
        span = p["epoch_blocks"] - p["window_blocks"] + 1
        start = epoch_start + int.from_bytes(digest[:8], "little") % span
        return start <= height < start + p["window_blocks"]

    def lifecycle(self, head: dict[str, Any], height: int) -> str:
        terminal = head["terminal_height"]
        if terminal is None and height >= head["expiry_height"]:
            terminal = head["expiry_height"]
        if terminal is None:
            return "Active"
        if height >= terminal + self.parameters["cooldown_blocks"]:
            return "Claimable"
        return "Cooldown"

    def resolve(self, name: str, height: int) -> dict[str, Any]:
        canonical = parse_name(name)
        head = self.heads.get(name_id(canonical).hex())
        if head is None:
            return {"lifecycle": "Missing", "ua": None, "head": None}
        lifecycle = self.lifecycle(head, height)
        public_head = {key: copy.deepcopy(value) for key, value in head.items() if key != "future_nf"}
        return {
            "lifecycle": lifecycle,
            "ua": head["ua"] if lifecycle == "Active" else None,
            "head": public_head,
        }

    def apply(self, block: dict[str, Any], referenced: list[dict[str, Any]]) -> dict[str, Any]:
        error = self._validate_block(block, referenced)
        if error is not None:
            return {"error": error, "operations": self._not_evaluated(block)}

        before = {
            "next_height": self.next_height,
            "tip": copy.deepcopy(self.tip),
            "previous_hash": self.previous_hash,
            "commits": copy.deepcopy(self.commits),
            "heads": copy.deepcopy(self.heads),
        }
        height = block["height"]
        self._prune_commits(height)
        for evidence in referenced:
            self.commits[ref_key(evidence["reference"])] = parse_field(evidence["commitment"])

        accepted: list[str] = []
        decisions: list[dict[str, Any]] = []
        for transaction in block.get("transactions", []):
            self._mark_expired(height)
            decision = self._apply_transaction(height, transaction)
            decisions.append(decision)
            if decision["accepted"]:
                accepted.append(decision["kind"].title())
        self._mark_expired(height)
        self.next_height = height + 1 if height < 0xFFFFFFFF else None
        self.tip = {"height": height, "hash_hex": block["hash_hex"]}
        self.previous_hash = block["hash_hex"]
        self.history.append(before)
        return {"ok": accepted, "operations": decisions}

    def _validate_block(
        self, block: dict[str, Any], referenced: list[dict[str, Any]]
    ) -> str | None:
        bytes32(block["hash_hex"])
        bytes32(block["prev_hash_hex"])
        for transaction in block.get("transactions", []):
            bytes32(transaction["txid_hex"])
            for action in transaction.get("actions", []):
                parse_field(action["nullifier"])
                parse_field(action["commitment"])
            operation = transaction.get("operation")
            if operation is not None:
                if operation["type"] == "commit":
                    if parse_field(operation["commitment"]) == 0:
                        raise SemanticError("COMMIT value must be nonzero")
                elif operation["type"] in ("reveal", "refresh"):
                    parse_name(operation["name"])
                    validate_ua(operation["ua"])
                    parse_field(operation["successor_future_nf"])
                    if not isinstance(operation["proof_valid"], bool):
                        raise SemanticError("proof_valid must be boolean")
                    reference = operation.get("commit") or operation.get("predecessor")
                    bytes32(reference["txid_hex"])
                else:
                    raise SemanticError(f"unknown operation {operation['type']}")
        for evidence in referenced:
            bytes32(evidence["reference"]["txid_hex"])
            if parse_field(evidence["commitment"]) == 0:
                raise SemanticError("referenced COMMIT value must be nonzero")
        if self.next_height != block["height"]:
            return "WrongHeight"
        if block["prev_hash_hex"] != self.previous_hash:
            return "WrongPreviousHash"
        previous_index: int | None = None
        for transaction in block.get("transactions", []):
            index = transaction["tx_index"]
            if previous_index is not None and index <= previous_index:
                return "NonCanonicalTransactionIndex"
            previous_index = index
            for position, action in enumerate(transaction.get("actions", [])):
                if action["action_index"] != position:
                    return "NonCanonicalActionIndex"

        reveal_refs = {
            ref_key(tx["operation"]["commit"])
            for tx in block.get("transactions", [])
            if tx.get("operation") is not None and tx["operation"].get("type") == "reveal"
        }
        supplied: dict[tuple[int, int, str], int] = {}
        for evidence in referenced:
            key = ref_key(evidence["reference"])
            reference_height = evidence["reference"]["height"]
            if (
                key not in reveal_refs
                or reference_height < self.parameters["activation_height"]
                or reference_height >= block["height"]
                or block["height"] - reference_height >= self.parameters["commit_ttl_blocks"]
            ):
                return "InvalidReferencedCommit"
            evidence_commitment = parse_field(evidence["commitment"])
            if key in supplied and supplied[key] != evidence_commitment:
                return "ConflictingReferencedCommit"
            if key in self.commits and self.commits[key] != evidence_commitment:
                return "ConflictingReferencedCommit"
            supplied[key] = evidence_commitment
        return None

    @staticmethod
    def _not_evaluated(block: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {
                "tx_index": tx["tx_index"],
                "kind": tx["operation"]["type"] if tx.get("operation") is not None else "inert",
                "accepted": None,
            }
            for tx in block.get("transactions", [])
        ]

    def _prune_commits(self, height: int) -> None:
        ttl = self.parameters["commit_ttl_blocks"]
        self.commits = {
            key: value for key, value in self.commits.items() if height - key[0] < ttl
        }

    def _mark_expired(self, height: int) -> None:
        for head in self.heads.values():
            if head["terminal_height"] is None and height >= head["expiry_height"]:
                head["terminal_height"] = head["expiry_height"]

    def _apply_transaction(self, height: int, transaction: dict[str, Any]) -> dict[str, Any]:
        operation = transaction.get("operation")
        kind = operation["type"] if operation else "inert"
        spent = [
            (identity, copy.deepcopy(head["producer"]))
            for identity, head in self.heads.items()
            if any(parse_field(action["nullifier"]) == head["future_nf"] for action in transaction.get("actions", []))
        ]
        accepted = False
        if kind == "commit":
            reference = (height, transaction["tx_index"], transaction["txid_hex"])
            self.commits[reference] = parse_field(operation["commitment"])
            accepted = True
        elif kind == "reveal":
            accepted = self._apply_reveal(height, transaction, operation)
        elif kind == "refresh":
            accepted = self._apply_refresh(height, transaction, operation)
        elif kind != "inert":
            raise SemanticError(f"unknown operation {kind}")

        for identity, producer in spent:
            head = self.heads.get(identity)
            if head is not None and head["producer"] == producer and head["terminal_height"] is None:
                head["terminal_height"] = height
        return {"tx_index": transaction["tx_index"], "kind": kind, "accepted": accepted}

    def _apply_reveal(
        self, height: int, transaction: dict[str, Any], operation: dict[str, Any]
    ) -> bool:
        canonical = parse_name(operation["name"])
        identity = name_id(canonical).hex()
        current = self.heads.get(identity)
        if current is not None and self.lifecycle(current, height) != "Claimable":
            return False
        commit = operation["commit"]
        age = height - commit["height"]
        if (
            not self.operation_window(canonical, height)
            or commit["height"] < self.parameters["activation_height"]
            or age < self.parameters["commit_maturity_blocks"]
            or age >= self.parameters["commit_ttl_blocks"]
        ):
            return False
        commitment = self.commits.get(ref_key(commit))
        if commitment is None:
            return False
        action_index = operation["action_index"]
        actions = transaction.get("actions", [])
        if action_index >= len(actions) or actions[action_index]["action_index"] != action_index:
            return False
        if not operation["proof_valid"]:
            return False
        action = actions[action_index]
        epoch = (height - self.parameters["activation_height"]) // self.parameters["epoch_blocks"]
        self.heads[identity] = {
            "name": canonical,
            "ua": operation["ua"],
            "producer": state_ref(height, transaction, action_index),
            "commitment_hex": field_hex(action["commitment"]),
            "future_nf": parse_field(operation["successor_future_nf"]),
            "future_nf_hex": field_hex(operation["successor_future_nf"]),
            "producer_epoch": epoch,
            "expiry_height": height + self.parameters["lease_blocks"],
            "terminal_height": None,
        }
        return True

    def _apply_refresh(
        self, height: int, transaction: dict[str, Any], operation: dict[str, Any]
    ) -> bool:
        canonical = parse_name(operation["name"])
        identity = name_id(canonical).hex()
        predecessor = self.heads.get(identity)
        if predecessor is None:
            return False
        epoch = (height - self.parameters["activation_height"]) // self.parameters["epoch_blocks"]
        if (
            self.lifecycle(predecessor, height) != "Active"
            or predecessor["producer"] != operation["predecessor"]
            or predecessor["producer_epoch"] >= epoch
            or not self.operation_window(canonical, height)
        ):
            return False
        action_index = operation["action_index"]
        actions = transaction.get("actions", [])
        if action_index >= len(actions):
            return False
        action = actions[action_index]
        if (
            action["action_index"] != action_index
            or parse_field(action["nullifier"]) != predecessor["future_nf"]
        ):
            return False
        if not operation["proof_valid"]:
            return False
        self.heads[identity] = {
            "name": canonical,
            "ua": operation["ua"],
            "producer": state_ref(height, transaction, action_index),
            "commitment_hex": field_hex(action["commitment"]),
            "future_nf": parse_field(operation["successor_future_nf"]),
            "future_nf_hex": field_hex(operation["successor_future_nf"]),
            "producer_epoch": epoch,
            "expiry_height": height + self.parameters["lease_blocks"],
            "terminal_height": None,
        }
        return True

    def rollback(self, expected_hash: str) -> str | None:
        if not self.history:
            return "BeyondRetention" if self.tip is not None else "NoAppliedBlock"
        if self.tip is None or self.tip["hash_hex"] != expected_hash:
            return "WrongTipHash"
        previous = self.history.pop()
        self.next_height = previous["next_height"]
        self.tip = previous["tip"]
        self.previous_hash = previous["previous_hash"]
        self.commits = previous["commits"]
        self.heads = previous["heads"]
        return None


class ExactResolver:
    def __init__(self, parameters: dict[str, Any], parent_hash: str, name: str):
        self.name = parse_name(name)
        self.identity = name_id(self.name).hex()
        self.reducer = Reducer(parameters, parent_hash)

    def apply(self, block: dict[str, Any], referenced: list[dict[str, Any]]) -> dict[str, Any]:
        filtered = copy.deepcopy(block)
        for transaction in filtered.get("transactions", []):
            operation = transaction.get("operation")
            if operation and operation["type"] in ("reveal", "refresh"):
                if name_id(operation["name"]).hex() != self.identity:
                    transaction["operation"] = None
        return self.reducer.apply(filtered, referenced)


def materialize_block(step: dict[str, Any], previous_hash: str) -> dict[str, Any]:
    block = copy.deepcopy(step["block"])
    block["hash_hex"] = block_hash(block["branch_byte"], block["height"])
    block["prev_hash_hex"] = block.get("prev_hash_hex", previous_hash)
    return block


def snapshot(reducer: Reducer, tracked_names: list[str], known_refs: list[dict[str, Any]]) -> dict[str, Any]:
    height = reducer.tip["height"] if reducer.tip is not None else reducer.parameters["activation_height"] - 1
    pending = []
    for reference in known_refs:
        value = reducer.commits.get(ref_key(reference))
        pending.append({"reference": reference, "commitment_hex": field_hex(value) if value is not None else None})
    return {
        "tip": copy.deepcopy(reducer.tip),
        "resolutions": {name: reducer.resolve(name, height) for name in tracked_names},
        "pending_commits": pending,
    }


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    parameters = case["parameters"]
    parent = case["activation_parent_hash_hex"]
    bytes32(parent)
    bytes32(parameters["deployment_id_hex"])
    names = [parse_name(name) for name in case["tracked_names"]]
    known_refs = case.get("known_commit_refs", [])
    full = Reducer(parameters, parent)
    exact = {name: ExactResolver(parameters, parent, name) for name in names}
    trace: list[dict[str, Any]] = []

    def record(label: str, full_result: dict[str, Any], exact_results: dict[str, Any]) -> None:
        full_state = snapshot(full, names, known_refs)
        exact_state = {
            name: snapshot(resolver.reducer, [name], known_refs)
            for name, resolver in exact.items()
        }
        for name in names:
            if full_state["resolutions"][name] != exact_state[name]["resolutions"][name]:
                raise SemanticError(f"{case['id']}:{label}: full/exact resolution divergence for {name}")
        trace.append(
            {
                "label": label,
                "full_result": full_result,
                "exact_results": exact_results,
                "full_state": full_state,
                "exact_state": exact_state,
            }
        )

    for step in case["steps"]:
        kind = step["kind"]
        if kind == "advance_empty":
            full_results = []
            exact_results: dict[str, list[dict[str, Any]]] = {name: [] for name in names}
            while full.next_height is not None and full.next_height <= step["through_height"]:
                block = {
                    "height": full.next_height,
                    "branch_byte": step["branch_byte"],
                    "hash_hex": block_hash(step["branch_byte"], full.next_height),
                    "prev_hash_hex": full.previous_hash,
                    "transactions": [],
                }
                full_results.append(full.apply(block, []))
                for name, resolver in exact.items():
                    exact_results[name].append(resolver.apply(block, []))
            record(step["label"], {"advance": full_results}, {name: {"advance": values} for name, values in exact_results.items()})
        elif kind == "apply":
            block = materialize_block(step, full.previous_hash)
            referenced = step.get("referenced_commits", [])
            full_result = full.apply(block, referenced)
            exact_results = {
                name: resolver.apply(block, referenced) for name, resolver in exact.items()
            }
            record(step["label"], full_result, exact_results)
        elif kind == "rollback":
            expected = step.get("expected_hash_hex") or block_hash(step["branch_byte"], step["height"])
            full_error = full.rollback(expected)
            exact_errors = {name: resolver.reducer.rollback(expected) for name, resolver in exact.items()}
            record(
                step["label"],
                {"ok": full_error is None, "error": full_error},
                {name: {"ok": error is None, "error": error} for name, error in exact_errors.items()},
            )
        else:
            raise SemanticError(f"unknown step kind {kind}")
    return {"id": case["id"], "trace": trace}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "test-vectors" / "semantic_histories.json",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    fixture = json.loads(args.path.read_text())
    if fixture.get("format") != "coppice-names-semantic-history-v1":
        raise SemanticError("unsupported corpus format")
    output = {"format": "coppice-names-semantic-trace-v1", "cases": [run_case(case) for case in fixture["cases"]]}
    print(json.dumps(output, sort_keys=True, indent=2 if args.pretty else None, separators=None if args.pretty else (",", ":")))


if __name__ == "__main__":
    main()
