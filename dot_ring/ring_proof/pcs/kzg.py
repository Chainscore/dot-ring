from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Tuple, cast
import secrets

import blst as _blst  # type: ignore[import-untyped]

blst = cast(Any, _blst)

import py_ecc.optimized_bls12_381 as bls  # type: ignore[import-untyped]

from pyblst import BlstP1Element, BlstP2Element  # type: ignore[import-untyped]

from dot_ring.ring_proof.helpers import Helpers

from ..polynomial.ops import poly_evaluate_single
from .srs import srs, G1Point
from .pairing import blst_miller_loop, blst_final_verify

Point_G1 = Any

from .utils import blst_p1_to_fq_tuple, synthetic_div, Scalar, CoeffVector, py_ecc_point_to_blst

@dataclass(slots=True, frozen=True)
class Opening:
    proof: G1Point  # commitment to the quotient polynomial
    y: Scalar  # claimed evaluation f(x)


class KZG:
    @classmethod
    def commit(cls, scalars: CoeffVector) -> G1Point:
        """
        Depending on whether blst is installed, use either third-party or in-built commitment generation.

        Args:
            scalars (CoeffVector):  Polynomial coefficients

        Returns:
            G1Point: Commitment point
        """
        try:
            import blst  # noqa: F401
            return cls._third_party_commit(scalars)
        except ImportError:
            print("blst not found, using in-built commitment")
            return cls._in_built_commit(scalars)

    @classmethod
    def _in_built_commit(cls, scalars: CoeffVector) -> G1Point:
        """Raw commitment using py_blst library

        Args:
            scalars (CoeffVector): Polynomial coefficients

        Returns:
            G1Point: Commitment point
        """
        # bases_py_ecc = self._srs.g1[:len(scalars)]
        bases = srs.blst_g1[: len(scalars)]
        # bases = [self.py_ecc_point_to_blst(p) for p in bases_py_ecc]
        acc = BlstP1Element()
        for base, scalar in zip(bases, scalars):
            acc += base.scalar_mul(scalar)
        res = acc
        decompressed = Helpers.bls_g1_decompress(
            res.compress().hex()
        )  # compress the blst to byte_string and then to bls g1 point type
        return decompressed
    
    @classmethod
    def _third_party_commit(cls, coeffs: CoeffVector) -> G1Point:
        """
        Commit to a polynomial using Pippenger multi-scalar multiplication.
        
        Args:
            coeffs (CoeffVector): Polynomial coefficients
        Returns:
            G1Point: Commitment point
        """
        if len(coeffs) > len(srs.g1):
            raise ValueError("polynomial degree exceeds SRS size")

        # Convert points and filter non-zero coefficients
        blst_points = []
        active_scalars = []

        for coeff, blst_point in zip(coeffs, srs.blst_sw_g1):
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
    def open(
        cls, 
        coeffs: CoeffVector, 
        x: Scalar
    ) -> Opening:
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
        if isinstance(commitment, BlstP1Element):
            comm_blst = commitment
        else:
            comm_blst = py_ecc_point_to_blst(commitment)
            
        if isinstance(proof, BlstP1Element):
            proof_blst = proof
        else:
            proof_blst = py_ecc_point_to_blst(proof)
        
        g1_gen = srs.blst_g1[0] # [1]G1
        g2_gen = srs.blst_g2[0] # [1]G2
        g2_tau = srs.blst_g2[1] # [tau]G2
        
        # Term 1: commitment - [value]G1
        # comm_term = comm_blst - value * G1_gen
        val_g1 = g1_gen.scalar_mul(value)
        comm_term = comm_blst + (-val_g1)
        
        # Term 2: [tau]G2 - [point]G2
        # tau_term = g2_tau - point * G2_gen
        point_g2 = g2_gen.scalar_mul(point)
        tau_term = g2_tau + (-point_g2)
        
        lhs = blst_miller_loop(comm_term, g2_gen)
        rhs = blst_miller_loop(proof_blst, tau_term)
        
        # Verify: e(A, B) == e(C, D) <=> final_verify(lhs, rhs)
        return blst_final_verify(lhs, rhs)

    @classmethod
    def batch_verify(
        cls,
        verifications: List[Tuple[Point_G1, Point_G1, Scalar, Scalar]],
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
        
        # Accumulators for the linear combination
        # acc_commit stores \sum r_i (C_i - v_i G1)
        # acc_proof stores \sum r_i * proof_i
        # acc_z_proof stores \sum r_i * z_i * proof_i
        acc_commit = BlstP1Element()
        acc_proof = BlstP1Element()
        acc_z_proof = BlstP1Element()
        
        for coeff, (commitment, proof, point, value) in zip(coeffs, verifications):
            if isinstance(commitment, BlstP1Element):
                comm_blst = commitment
            else:
                comm_blst = py_ecc_point_to_blst(commitment)
            
            if isinstance(proof, BlstP1Element):
                proof_blst = proof
            else:
                proof_blst = py_ecc_point_to_blst(proof)
            
            # r_i * (C_i - v_i * G1)
            val_g1 = g1_gen.scalar_mul(value % order)
            comm_term = comm_blst + (-val_g1)
            acc_commit = acc_commit + comm_term.scalar_mul(coeff)
            
            # r_i * proof_i
            acc_proof = acc_proof + proof_blst.scalar_mul(coeff)
            
            # r_i * z_i * proof_i
            coeff_z = (coeff * (point % order)) % order
            acc_z_proof = acc_z_proof + proof_blst.scalar_mul(coeff_z)
        
        # Final pairing check derived from:
        # e(Σ r_i (C_i - v_i G1) + Σ r_i z_i proof_i, G2) == e(Σ r_i proof_i, τ)
        lhs_point = acc_commit + acc_z_proof
        lhs = blst_miller_loop(lhs_point, g2_gen)
        rhs = blst_miller_loop(acc_proof, g2_tau)
        
        return blst_final_verify(lhs, rhs)