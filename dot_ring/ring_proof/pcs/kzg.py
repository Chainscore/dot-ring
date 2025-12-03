from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, cast

import py_ecc.optimized_bls12_381 as bls  # type: ignore[import-untyped]

import dot_ring.blst as _blst  # type: ignore[import-untyped]

from ..polynomial.ops import poly_evaluate_single
from .pairing import blst_final_verify, blst_miller_loop
from .srs import G1Point, srs
from .utils import CoeffVector, Scalar, blst_p1_to_fq_tuple, g1_to_blst, synthetic_div

blst = cast(Any, _blst)
Point_G1 = Any


# Helper functions for blst.P1 arithmetic
def p1_scalar_mul(p: Any, scalar: int) -> Any:
    """Multiply blst.P1 point by scalar"""
    return p.dup().mult(scalar)


def p1_add(a: Any, b: Any) -> Any:
    """Add two blst.P1 points"""
    return a.dup().add(b)


def p1_neg(p: Any) -> Any:
    """Negate a blst.P1 point"""
    return p.dup().neg()


def p2_scalar_mul(p: Any, scalar: int) -> Any:
    """Multiply blst.P2 point by scalar"""
    return p.dup().mult(scalar)


def p2_add(a: Any, b: Any) -> Any:
    """Add two blst.P2 points"""
    return a.dup().add(b)


def p2_neg(p: Any) -> Any:
    """Negate a blst.P2 point"""
    return p.dup().neg()


@dataclass(slots=True, frozen=True)
class Opening:
    proof: G1Point  # commitment to the quotient polynomial
    y: Scalar  # claimed evaluation f(x)


class KZG:
    @classmethod
    def commit(cls, coeffs: CoeffVector) -> G1Point:
        """
        Commit to a polynomial using Pippenger multi-scalar multiplication.

        Args:
            coeffs (CoeffVector): Polynomial coefficients
        Returns:
            G1Point: Commitment point
        """
        if len(coeffs) > len(srs.g1):
            raise ValueError("polynomial degree exceeds SRS size")

        # Filter non-zero coefficients
        blst_points = []
        active_scalars = []

        for coeff, blst_point in zip(coeffs, srs.blst_g1, strict=False):
            if coeff != 0:
                blst_points.append(blst_point)
                active_scalars.append(coeff)

        if not blst_points:
            result = blst.P1()  # point at infinity
        else:
            # Use Pippenger multi-scalar multiplication
            result = blst.P1_Affines.mult_pippenger(
                blst.P1_Affines.as_memory(blst_points), active_scalars
            )
        return blst_p1_to_fq_tuple(result)

    @classmethod
    def open(cls, coeffs: CoeffVector, x: Scalar) -> Opening:
        """
        Open the polynomial at a given point.

        Args:
            coeffs (CoeffVector): Polynomial coefficients
            x (Scalar): Evaluation point

        Returns:
            Opening: Opening proof and evaluation value
        """
        y = poly_evaluate_single(coeffs, x, bls.curve_order)
        q = synthetic_div(coeffs, x, y)
        proof = cls.commit(q)
        return Opening(proof, y)

    @classmethod
    def verify(
        cls,
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

        Returns:
            True if proof is valid, False otherwise
        """
        if isinstance(commitment, blst.P1):
            comm_blst = commitment
        else:
            comm_blst = g1_to_blst(commitment)

        if isinstance(proof, blst.P1):
            proof_blst = proof
        else:
            proof_blst = g1_to_blst(proof)

        g1_gen = srs.blst_g1[0]  # [1]G1
        g2_gen = srs.blst_g2[0]  # [1]G2
        g2_tau = srs.blst_g2[1]  # [tau]G2

        # Term 1: commitment - [value]G1
        val_g1 = p1_scalar_mul(g1_gen, value)
        comm_term = comm_blst.dup().add(p1_neg(val_g1))

        # Term 2: [tau]G2 - [point]G2
        point_g2 = g2_gen.dup().mult(point)
        tau_term = g2_tau.dup().add(p2_neg(point_g2))

        lhs = blst_miller_loop(comm_term, g2_gen)
        rhs = blst_miller_loop(proof_blst, tau_term)

        return bool(blst_final_verify(lhs, rhs))

    @classmethod
    def batch_verify(
        cls,
        verifications: list[tuple[Point_G1, Point_G1, Scalar, Scalar]],
    ) -> bool:
        """
        Batch verify multiple KZG proofs using random linear combination.

        Each verification is (commitment, proof, point, value).
        Uses random coefficients for security.

        Args:
            verifications: List of (commitment, proof, point, value) tuples

        Returns:
            True if all proofs are valid, False otherwise
        """
        if not verifications:
            return True

        if len(verifications) == 1:
            return cls.verify(*verifications[0])

        order = bls.curve_order

        # Generate random coefficients for batching (first coefficient fixed to 1)
        coeffs = [1]
        for _ in range(len(verifications) - 1):
            coeff = 0
            while coeff == 0:
                coeff = secrets.randbelow(order)
            coeffs.append(coeff)

        g1_gen = srs.blst_g1[0]  # [1]G1
        g2_gen = srs.blst_g2[0]  # [1]G2
        g2_tau = srs.blst_g2[1]  # [tau]G2

        # Accumulate points and scalars for MSMs
        # LHS = sum(coeff_i * C_i) - (sum(coeff_i * v_i)) * G1 + sum(coeff_i * z_i * proof_i)
        # RHS = sum(coeff_i * proof_i)

        lhs_points = []
        lhs_scalars = []
        
        rhs_points = []
        rhs_scalars = []

        sum_v = 0
        
        for coeff, (commitment, proof, point, value) in zip(
            coeffs, verifications, strict=False
        ):
            comm_blst = commitment
            proof_blst = proof

            # LHS terms
            lhs_points.append(comm_blst)
            lhs_scalars.append(coeff)
            
            sum_v = (sum_v + coeff * value) % order
            
            coeff_z = (coeff * point) % order
            lhs_points.append(proof_blst)
            lhs_scalars.append(coeff_z)
            
            # RHS terms
            rhs_points.append(proof_blst)
            rhs_scalars.append(coeff)

        # Add G1 term to LHS
        lhs_points.append(g1_gen)
        lhs_scalars.append((-sum_v) % order)

        lhs_point = blst.P1_Affines.mult_pippenger(
            blst.P1_Affines.as_memory(lhs_points), lhs_scalars
        )
        
        rhs_point = blst.P1_Affines.mult_pippenger(
            blst.P1_Affines.as_memory(rhs_points), rhs_scalars
        )

        lhs = blst_miller_loop(lhs_point, g2_gen)
        rhs = blst_miller_loop(rhs_point, g2_tau)

        return bool(blst_final_verify(lhs, rhs))
