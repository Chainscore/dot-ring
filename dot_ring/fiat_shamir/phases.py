"""Convenience wrappers for common transcript phases used in ring-proof.

These functions are re-exported from the original implementation but now live
in ``dot_ring.fiat_shamir`` so that other packages can import them without a
ring-proof dependency.
"""

from __future__ import annotations

from typing import Any, Sequence, List

from dot_ring.fiat_shamir.serialize import serialize
from dot_ring.fiat_shamir.transcript import Transcript

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
):
    t.add_serialized(b"vk", serialize(vk))
    t.add_serialized(b"instance", serialize(result_point))
    t.add_serialized(b"committed_cols", serialize(witness_commitments))
    return t.get_constraints_aggregation_coeffs(7)


def phase2_eval_point(t: Transcript, C_q_commitment: Any):
    t.add_serialized(b"quotient", serialize(C_q_commitment))
    return t.get_evaluation_point(1)[0]


def phase3_nu_vector(
    t: Transcript,
    rel_poly_evals: List[int],
    agg_poly_eval: int,
):
    t.add_serialized(b"register_evaluations", serialize(rel_poly_evals))
    t.add_serialized(b"shifted_linearization_evaluation", serialize(agg_poly_eval))
    return t.get_kzg_aggregation_challenges(8)