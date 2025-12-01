from __future__ import annotations

from collections.abc import Sequence

from dot_ring.ring_proof.constants import D_512 as D
from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.polynomial.interpolation import (
    poly_interpolate_fft,
    poly_mul_fft,
)
from dot_ring.ring_proof.polynomial.ops import (
    poly_multiply,
    vect_add,
    vect_scalar_mul,
)

__all__ = [
    "vanishing_poly",
    "aggregate_constraints",
]


def vanishing_poly(k: int, omega_root: int, prime: int = S_PRIME) -> list[int]:
    vanishing_term = [1]
    for i in range(1, k + 1):
        vanishing_term = poly_mul_fft(vanishing_term, [-D[-i], 1], prime)
    return vanishing_term


def aggregate_constraints(
    polys: Sequence[Sequence[int]],
    alphas: Sequence[int],
    omega_root: int,
    prime: int = S_PRIME,
    k: int = 3,
) -> list[int]:
    result = [0] * len(polys[0])
    for poly, alpha in zip(polys, alphas, strict=False):
        weighted = vect_scalar_mul(poly, alpha, prime)
        result = vect_add(result, weighted, prime)
    interpolated_result = poly_interpolate_fft(result, omega_root, prime)

    # get vanishing ply
    v_t = vanishing_poly(k, omega_root, prime)
    # mul with c_agg
    final_cs_agg = poly_multiply(interpolated_result, v_t, prime)

    i = len(final_cs_agg) - 1
    while i >= 0 and final_cs_agg[i] == 0:
        i -= 1
    return final_cs_agg[: i + 1]
