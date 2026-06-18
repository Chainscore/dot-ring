# phases.py
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from dot_ring.ring_proof.transcript.serialize import serialize
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript

__all__ = [
    "derive_challenges_after_vk",
    "phase1_alphas",
    "phase1_alphas_after_vk",
    "phase2_eval_point",
    "phase3_nu_vector",
]


def phase1_alphas(
    t: FiatShamirTranscript,
    vk: Any,
    result_point: Any,
    witness_commitments: Sequence[Any],
) -> Any:
    """Append phase‑1 data and return 7 constraint‑aggregation coefficients."""
    t.add_serialized_bytes(b"vk", serialize(vk))
    t.add_serialized_bytes(b"instance", serialize(result_point))
    t.add_serialized_bytes(b"committed_cols", serialize(witness_commitments))
    return t, t.get_constraints_aggregation_coeffs(7)


def phase1_alphas_after_vk(
    t: FiatShamirTranscript,
    result_point: Any,
    witness_commitments: Sequence[Any],
) -> Any:
    """Append phase-1 data after the verifier key has already been absorbed."""
    t.add_serialized_bytes(b"instance", _serialize_instance(result_point))
    t.add_serialized_bytes(b"committed_cols", _serialize_commitments(witness_commitments))
    return t, t.get_constraints_aggregation_coeffs(7)


def phase2_eval_point(t: FiatShamirTranscript, C_q_commitment: Any) -> Any:
    """Append quotient commitment and derive evaluation point ζ."""
    t.add_serialized_bytes(b"quotient", _serialize_bytes_or_fallback(C_q_commitment))
    return t, t.get_evaluation_point(1)[0]


def phase3_nu_vector(
    t: FiatShamirTranscript,
    rel_poly_evals: list[int] | bytes,
    agg_poly_eval: int,
) -> list[int]:
    """Append evaluation bundle and linearisation eval, return 8 ν‑challenges."""
    t.add_serialized_bytes(b"register_evaluations", _serialize_ints_or_bytes(rel_poly_evals))
    t.add_serialized_bytes(b"shifted_linearization_evaluation", _serialize_int_or_bytes(agg_poly_eval))
    return t.get_kzg_aggregation_challenges(8)


def derive_challenges_after_vk(
    t: FiatShamirTranscript,
    result_point: Any,
    witness_commitments: Sequence[Any],
    quotient_commitment: Any,
    evals: list[int] | bytes,
    lin_eval: int | bytes,
) -> tuple[FiatShamirTranscript, list[int], int, list[int]]:
    """Derive all post-vk verifier challenges from a copied transcript."""
    t = t.copy()
    instance_bytes = _serialize_instance(result_point)
    commitments_bytes = _serialize_commitments(witness_commitments)
    quotient_bytes = _serialize_bytes_or_fallback(quotient_commitment)
    evals_bytes = _serialize_ints_or_bytes(evals)
    lin_eval_bytes = _serialize_int_or_bytes(lin_eval)

    t.add_serialized_bytes(b"instance", instance_bytes)
    t.add_serialized_bytes(b"committed_cols", commitments_bytes)
    alpha_list = t.get_constraints_aggregation_coeffs(7)
    t.add_serialized_bytes(b"quotient", quotient_bytes)
    zeta = t.get_evaluation_point(1)[0]
    t.add_serialized_bytes(b"register_evaluations", evals_bytes)
    t.add_serialized_bytes(b"shifted_linearization_evaluation", lin_eval_bytes)
    return t, alpha_list, zeta, t.get_kzg_aggregation_challenges(8)


def _serialize_instance(result_point: Any) -> bytes:
    if isinstance(result_point, tuple) and len(result_point) == 2:
        x, y = result_point
        return int(x).to_bytes(32, "little") + int(y).to_bytes(32, "little")
    return serialize(result_point)


def _serialize_commitments(commitments: Sequence[Any]) -> bytes:
    if isinstance(commitments, bytes):
        return commitments
    if isinstance(commitments, bytearray):
        return bytes(commitments)
    if all(isinstance(commitment, bytes | bytearray) for commitment in commitments):
        return b"".join(bytes(commitment) for commitment in commitments)
    return serialize(commitments)


def _serialize_bytes_or_fallback(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return serialize(value)


def _serialize_ints_or_bytes(values: list[int] | bytes) -> bytes:
    if isinstance(values, bytes):
        return values
    if isinstance(values, bytearray):
        return bytes(values)
    try:
        chunks = [value.to_bytes(32, "little") for value in values]
    except AttributeError:
        return serialize(values)
    return b"".join(chunks)


def _serialize_int_or_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, int):
        return value.to_bytes(32, "little")
    return serialize(value)
