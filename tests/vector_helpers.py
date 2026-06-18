import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

Vector = Mapping[str, Any]


def load_json_vectors(base_path: Path, name: str) -> list[dict[str, Any]]:
    return json.loads((base_path / name).read_text())


def bytes_from_fields(vector: Vector, *fields: str) -> bytes:
    return bytes.fromhex("".join(str(vector[field]) for field in fields))


def tiny_proof_bytes(vector: Vector) -> bytes:
    return bytes_from_fields(vector, "gamma", "proof_c", "proof_s")


def thin_proof_bytes(vector: Vector) -> bytes:
    return bytes_from_fields(vector, "gamma", "proof_r", "proof_s")


def pedersen_proof_bytes(vector: Vector) -> bytes:
    return bytes_from_fields(vector, "gamma", "proof_pk_com", "proof_r", "proof_ok", "proof_s", "proof_sb")


def ring_proof_bytes(vector: Vector) -> bytes:
    return bytes_from_fields(vector, "gamma", "proof_pk_com", "proof_r", "proof_ok", "proof_s", "proof_sb", "ring_proof")
