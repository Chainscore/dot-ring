# phases.py
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from dot_ring.ring_proof.transcript.serialize import serialize
from dot_ring.ring_proof.transcript.transcript import Transcript

__all__ = [
    "phase1_alphas",
    "phase2_eval_point",
    "phase3_nu_vector",
]


def phase1_alphas(
    t: Transcript,
    vk: Any,
    result_point: Any,
    witness_commitments: Sequence[Any],
) -> Any:
    """Append phase‑1 data and return 7 constraint‑aggregation coefficients."""
    t.add_serialized(b"vk", serialize(vk))
    t.add_serialized(b"instance", serialize(result_point))
    t.add_serialized(b"committed_cols", serialize(witness_commitments))
    return t, t.get_constraints_aggregation_coeffs(7)


def phase2_eval_point(t: Transcript, C_q_commitment: Any) -> Any:
    """Append quotient commitment and derive evaluation point ζ."""
    t.add_serialized(b"quotient", serialize(C_q_commitment))
    return t, t.get_evaluation_point(1)[0]


def phase3_nu_vector(
    t: Transcript,
    rel_poly_evals: list[int],
    agg_poly_eval: int,
) -> list[int]:
    """Append evaluation bundle and linearisation eval, return 8 ν‑challenges."""
    t.add_serialized(b"register_evaluations", serialize(rel_poly_evals))
    t.add_serialized(b"shifted_linearization_evaluation", serialize(agg_poly_eval))
    return t.get_kzg_aggregation_challenges(8)
