from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript

__all__ = [
    "derive_challenges_after_vk",
    "phase1_alphas_after_vk",
    "phase2_eval_point",
    "phase3_nu_vector",
    "serialize_verifier_key",
]


def phase1_alphas_after_vk(
    t: FiatShamirTranscript,
    result_point: Any,
    witness_commitments: Sequence[Any],
) -> Any:
    """Append phase-1 data after the verifier key has already been absorbed."""
    t.absorb_labeled(b"instance", _serialize_instance(result_point))
    t.absorb_labeled(b"committed_cols", _serialize_commitments(witness_commitments))
    return t, t.challenges(b"constraints_aggregation", 7)


def phase2_eval_point(t: FiatShamirTranscript, C_q_commitment: Any) -> Any:
    """Append quotient commitment and derive the evaluation point."""
    t.absorb_labeled(b"quotient", _serialize_bytes(C_q_commitment))
    return t, t.challenge(b"evaluation_point")


def phase3_nu_vector(
    t: FiatShamirTranscript,
    rel_poly_evals: list[int] | bytes,
    agg_poly_eval: int,
) -> list[int]:
    """Append evaluation bundle and linearization eval, then return 8 challenges."""
    t.absorb_labeled(b"register_evaluations", _serialize_ints_or_bytes(rel_poly_evals))
    t.absorb_labeled(b"shifted_linearization_evaluation", _serialize_int_or_bytes(agg_poly_eval))
    return t.challenges(b"kzg_aggregation", 8)


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
    quotient_bytes = _serialize_bytes(quotient_commitment)
    evals_bytes = _serialize_ints_or_bytes(evals)
    lin_eval_bytes = _serialize_int_or_bytes(lin_eval)

    t.absorb_labeled(b"instance", instance_bytes)
    t.absorb_labeled(b"committed_cols", commitments_bytes)
    alpha_list = t.challenges(b"constraints_aggregation", 7)
    t.absorb_labeled(b"quotient", quotient_bytes)
    zeta = t.challenge(b"evaluation_point")
    t.absorb_labeled(b"register_evaluations", evals_bytes)
    t.absorb_labeled(b"shifted_linearization_evaluation", lin_eval_bytes)
    return t, alpha_list, zeta, t.challenges(b"kzg_aggregation", 8)


def serialize_verifier_key(g1: Any, g2_points: Sequence[Any], commitments: Sequence[Any]) -> bytes:
    """Serialize the fixed verifier key exactly as the ring transcript expects."""
    return _serialize_bls_pair(g1) + b"".join(_serialize_bls_pair(point) for point in g2_points) + _serialize_commitments(commitments)


def _serialize_instance(result_point: Any) -> bytes:
    if isinstance(result_point, tuple) and len(result_point) == 2:
        x, y = result_point
        return int(x).to_bytes(32, "little") + int(y).to_bytes(32, "little")
    return _serialize_bytes(result_point)


def _serialize_commitments(commitments: Sequence[Any]) -> bytes:
    if isinstance(commitments, bytes):
        return commitments
    if isinstance(commitments, bytearray):
        return bytes(commitments)
    if all(isinstance(commitment, bytes | bytearray) for commitment in commitments):
        return b"".join(bytes(commitment) for commitment in commitments)
    return b"".join(_serialize_bls_pair(commitment) for commitment in commitments)


def _serialize_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, tuple) and len(value) == 2:
        return _serialize_bls_pair(value)
    raise TypeError(f"expected bytes or a BLS point, got {type(value).__name__}")


def _serialize_ints_or_bytes(values: list[int] | bytes) -> bytes:
    if isinstance(values, bytes):
        return values
    if isinstance(values, bytearray):
        return bytes(values)
    return b"".join(int(value).to_bytes(32, "little") for value in values)


def _serialize_int_or_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return int(value).to_bytes(32, "little")


def _serialize_bls_pair(point: Any) -> bytes:
    if not isinstance(point, tuple | list) or len(point) != 2:
        raise TypeError(f"expected a two-coordinate BLS point, got {type(point).__name__}")
    x, y = point
    return _serialize_bls_coord(x) + _serialize_bls_coord(y)


def _serialize_bls_coord(value: Any) -> bytes:
    return int(value).to_bytes(48, "big")
