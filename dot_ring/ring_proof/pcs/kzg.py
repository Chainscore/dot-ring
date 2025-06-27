from __future__ import annotations
import time
import math
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Sequence, Tuple, Any

# clone the https://github.com/supranational/blst.git
#run change the directory to bindings/python , run make run.me and specify the path as below and import blst

# sys.path.append("/home/siva/blst/bindings/python")
# import blst

import time
import py_ecc.optimized_bls12_381 as bls
from py_ecc.optimized_bls12_381 import (
    G1,
    add,
    multiply,
    neg,
    pairing, Z1, optimized_pairing, normalize, double)
from py_ecc.optimized_bls12_381 import FQ, FQ2
from pyblst import BlstP1Element

from dot_ring.ring_proof.helpers import Helpers
from dot_ring.ring_proof.pcs.load_powers import (
    g1_points as _RAW_G1_POWERS,
    g2_points as _RAW_G2_POWERS, g2_points,
)

Scalar = int
CoeffVector = List[Scalar]
G1Point = Tuple[FQ, FQ, FQ]
G2Point = Tuple[FQ2, FQ2, FQ2]
Point_G1=Any


def _horner_eval(poly: CoeffVector, x: Scalar) -> Scalar:
    """Evaluate *poly* at *x* modulo the curve order using Horner’s rule."""
    acc = 0
    for c in reversed(poly):
        acc = (acc * x + c) % bls.curve_order
    return acc


def _synthetic_div(poly: CoeffVector, x: Scalar, y: Scalar) -> CoeffVector:
    """Return q(X) such that f(X)−y = (X−x)·q(X).  Checks remainder."""
    n = len(poly)
    q = [0] * (n - 1)
    rem = poly[-1]
    for i in range(n - 2, -1, -1):
        q[i] = rem
        rem = (rem * x + poly[i]) % bls.curve_order
    if rem != y:
        raise ValueError("point/value pair inconsistent with polynomial")
    return q


@dataclass(slots=True, frozen=True)
class SRS:
    g1: Sequence[G1Point]  # now guaranteed projective tuples
    g2: Sequence[G2Point]

    def __init__(self, g1_raw, g2_raw):
        object.__setattr__(self, "g1", [self._to_jacobian_g1(p) for p in g1_raw])
        object.__setattr__(self, "g2", [self._to_jacobian_g2(p) for p in g2_raw[:2]])

    @classmethod
    def _to_jacobian_g1(cls, pt) -> G1Point:
        """(x, y) | (int, int)  →  (FQ, FQ, FQ_one)."""
        if len(pt) == 3:  # already projective
            return pt
        x, y = pt
        return FQ(x), FQ(y), FQ.one()

    @classmethod
    def _to_jacobian_g2(cls, pt) -> G2Point:
        if len(pt) == 3:
            return pt
        x,y=pt
        res=(FQ2([x[0], x[1]]), FQ2([y[0], y[1]]), FQ2([1, 0]))
        return res

    @classmethod
    def from_loaded(cls, max_deg: int) -> "SRS":
        if max_deg >= len(_RAW_G1_POWERS):
            raise ValueError("polynomial degree exceeds available SRS length")

        g1_jac = [cls._to_jacobian_g1(p) for p in _RAW_G1_POWERS[: max_deg + 1]]
        # G₂ only needs two powers: 1 and τ
        g2_jac = [cls._to_jacobian_g2(p) for p in _RAW_G2_POWERS[:2]]
        return cls(g1_jac, g2_jac)

    @staticmethod
    @lru_cache(maxsize=None)
    def default(max_deg: int = 2048) -> "SRS":
        return SRS.from_loaded(max_deg)




@dataclass(slots=True, frozen=True)
class Opening:
    proof: G1Point  # commitment to the quotient polynomial
    y: Scalar  # claimed evaluation f(x)

class KZG:
    """Commit‑and‑open abstraction hiding group math from callers."""

    __slots__ = ("_srs",)

    def __init__(self, srs: SRS):
        self._srs = srs

    # msm
    def commit(self, coeffs:CoeffVector, c=6)->G1Point:
        start=time.time()
        bases=self._srs.g1[:len(coeffs)]
        assert len(bases) == len(coeffs)
        num_bits = 255
        num_buckets = (1 << c) - 1
        window_sums = []

        for w_start in range(0, num_bits, c):
            buckets = [Z1] * num_buckets
            res = Z1

            for scalar, base in zip(coeffs, bases):
                shifted = scalar >> w_start
                idx = shifted & ((1 << c) - 1)
                if idx != 0:
                    buckets[idx - 1] = add(buckets[idx - 1], base)

            running_sum = Z1
            for b in reversed(buckets):
                running_sum = add(running_sum, b)
                res = add(res, running_sum)

            window_sums.append(res)

        result = window_sums[-1]
        for window in reversed(window_sums[:-1]):
            for _ in range(c):
                result = double(result)
            result = add(result, window)
        end=time.time()

        print("Time in this call:", end-start)
        return result

    #w.o using multi scalar multiplication
    # def commit(self, coeffs: CoeffVector) -> G1Point:
    #     start_time=time.time()
    #
    #     if len(coeffs) > len(self._srs.g1):
    #         raise ValueError("polynomial degree exceeds SRS size")
    #     acc: G1Point = bls.Z1  # point at infinity
    #     for a, g in zip(coeffs, self._srs.g1):
    #         if a:
    #             acc = add(acc, multiply(g, a))
    #     end_time=time.time()
    #
    #     print("Inside Commit func:", end_time - start_time)
    #     return acc


    def open(self, coeffs: CoeffVector, x: Scalar) -> Opening:
        st_time=time.time()
        y = _horner_eval(coeffs, x)
        q = _synthetic_div(coeffs, x, y)
        proof = self.commit(q)
        ed_time=time.time()
        # print("Inside Open Func:", ed_time- st_time)
        return Opening(proof, y)


    def verify(self,
            commitment: Point_G1,
            proof: Point_G1,
            point: Scalar,
            value: Scalar,
    ) -> bool:
        """
        Verify a KZG proof.

        Args:
            commitment: Commitment to the polynomial
            proof: Proof of evaluation
            point: Evaluation point
            value: Claimed value of polynomial at point
            srs_g1: G1 elements of SRS
            srs_g2: G2 elements of SRS

        Returns:
            True if proof is valid, False otherwise
        """
        s_time=time.time()
        srs_g2 = [
            (FQ2([x[0], x[1]]), FQ2([y[0], y[1]]), FQ2([1, 0]))
            for (x, y) in g2_points
        ]
        # Compute right side: e(commitment - [value]G1, G2)
        g1_value = multiply(G1, value)  # G1->G
        commitment_minus_value = add(commitment, neg(g1_value))
        # Right pairing: e(commitment - [value]G1, G2)
        st_time=time.time()
        right_pairing = pairing(srs_g2[0], commitment_minus_value)
        ed_time=time.time()
        # print("a pairing takes:", ed_time- st_time)

        # Left pairing: e(proof, [tau]G2 - [point]G2)
        # Compute left side: e(proof, [tau]G2 - [point]G2)
        g2_point = multiply(srs_g2[0], point)  # G2->H.i
        shifted_g2 = add(srs_g2[1], neg(g2_point))  # srs_g2[1]->H.t
        left_pairing = pairing(shifted_g2, proof)
        end_time=time.time()
        return left_pairing == right_pairing

    @classmethod
    def default(cls, *, max_deg: int = 2048) -> "pcs":
        return cls(SRS.default(max_deg))

