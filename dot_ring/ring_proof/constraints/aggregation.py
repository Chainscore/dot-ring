from __future__ import  annotations
from typing import List, Sequence
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.load_powers import g1_points, g2_points
from dot_ring.ring_proof.transcript.transcript import Transcript
from dot_ring.ring_proof.transcript.phases import phase1_alphas
from py_ecc.optimized_bls12_381 import normalize as nm
from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.polynomial.ops import (
    poly_multiply, vect_scalar_mul, vect_add,
)
from dot_ring.ring_proof.constants import OMEGA_2048 as omega_2048, D_512 as D
from dot_ring.ring_proof.polynomial.interpolation  import poly_interpolate_fft

__all__ = [
    "vanishing_poly",
    "aggregate_constraints",
]


def vanishing_poly(k: int, omega_root: int, prime: int = S_PRIME) -> List[int]:

    vanishing_term = [1]
    for i in range(1, k+1):
        vanishing_term = poly_multiply(vanishing_term, [-D[-i], 1],
                                       prime)
    return vanishing_term



def aggregate_constraints(
    polys: Sequence[Sequence[int]],
    alphas: Sequence[int],
    omega_root: int,
    prime: int = S_PRIME,
    k: int = 3,
) -> List[int]:

    result = [0] * len(polys[0])
    for poly, alpha in zip(polys, alphas):
        weighted = vect_scalar_mul(poly, alpha, prime)
        result = vect_add(result, weighted, prime)
    # print("intermediate_aggregation:", result)
    interpolated_result=poly_interpolate_fft(result, omega_root, prime)

    #get vanishing ply
    v_t= vanishing_poly(k, omega_root, prime)
    # print("vanishing term:", v_t)

    #mul with c_agg
    final_cs_agg= poly_multiply(interpolated_result, v_t,prime)

    i = len(final_cs_agg) - 1
    while i >= 0 and final_cs_agg[i] == 0:
        i -= 1
    return final_cs_agg[:i + 1]
