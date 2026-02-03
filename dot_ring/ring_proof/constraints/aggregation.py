from __future__ import annotations

from collections.abc import Sequence

from dot_ring.curve.native_field.vector_ops import vect_add
from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.polynomial.interpolation import poly_interpolate_fft
from dot_ring.ring_proof.polynomial.ops import (
    poly_multiply,
    vect_scalar_mul,
)

__all__ = [
    "vanishing_poly",
    "aggregate_constraints",
]


def vanishing_poly(domain: list[int], k: int = 3, prime: int = S_PRIME) -> list[int]:
    vanishing_term = [1]
    for i in range(1, k + 1):
        vanishing_term = poly_multiply(vanishing_term, [-domain[-i], 1], prime)
    return vanishing_term


def aggregate_constraints(
    polys: Sequence[Sequence[int]],
    alphas: Sequence[int],
    omega_root: int,
    prime: int = S_PRIME,
    k: int = 3,
    domain: list[int] | None = None,
) -> list[int]:
    result = [0] * len(polys[0])
    for poly, alpha in zip(polys, alphas, strict=False):
        weighted = vect_scalar_mul(poly, alpha, prime)
        result = vect_add(result, weighted, prime)
    interpolated_result = poly_interpolate_fft(result, omega_root, prime)

    # get vanishing ply
    if domain is None:
        domain = RingProofParams().domain
    v_t = vanishing_poly(domain, k, prime)
    # mul with c_agg
    final_cs_agg = poly_multiply(interpolated_result, v_t, prime)

    i = len(final_cs_agg) - 1
    while i >= 0 and final_cs_agg[i] == 0:
        i -= 1
    return final_cs_agg[: i + 1]
