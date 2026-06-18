from __future__ import annotations

import hashlib
import secrets
from typing import Any, cast

import py_ecc.optimized_bls12_381 as bls  # type: ignore[import-untyped]

import dot_ring.blst as _blst  # type: ignore[import-untyped]

from .opening import Opening
from .pairing import blst_final_verify, blst_miller_loop
from .srs import SRS, srs
from .utils import (
    CoeffVector,
    LinearPcsVerification,
    PcsVerification,
    Scalar,
    g1_to_blst,
    synthetic_div_with_eval,
)

blst = cast(Any, _blst)
Point_G1 = Any


def _add_aggregated_g1_term(
    points_by_id: dict[int, Any],
    scalars_by_id: dict[int, int],
    point: Any,
    scalar: int,
    order: int,
) -> None:
    scalar %= order
    if scalar == 0:
        return
    point_id = id(point)
    if point_id in scalars_by_id:
        scalars_by_id[point_id] = (scalars_by_id[point_id] + scalar) % order
    else:
        points_by_id[point_id] = point
        scalars_by_id[point_id] = scalar


def _aggregated_g1_vectors(points_by_id: dict[int, Any], scalars_by_id: dict[int, int]) -> tuple[list[Any], list[int]]:
    points: list[Any] = []
    scalars: list[int] = []
    for point_id, point in points_by_id.items():
        scalar = scalars_by_id[point_id]
        if scalar:
            points.append(point)
            scalars.append(scalar)
    return points, scalars


def _aggregate_linear_batch(
    verifications: list[LinearPcsVerification],
    coeffs: list[int],
    g1_gen: Any,
    order: int,
) -> tuple[list[Any], list[int], list[Any], list[int]]:
    lhs_points_by_id: dict[int, Any] = {}
    lhs_scalars_by_id: dict[int, int] = {}
    rhs_points_by_id: dict[int, Any] = {}
    rhs_scalars_by_id: dict[int, int] = {}

    sum_v = 0
    for coeff, verification in zip(coeffs, verifications, strict=False):
        for commitment, scalar in verification.commitment_terms:
            _add_aggregated_g1_term(lhs_points_by_id, lhs_scalars_by_id, commitment, coeff * scalar, order)

        proof = verification.proof
        sum_v = (sum_v + coeff * verification.value) % order
        _add_aggregated_g1_term(lhs_points_by_id, lhs_scalars_by_id, proof, coeff * verification.point, order)
        _add_aggregated_g1_term(rhs_points_by_id, rhs_scalars_by_id, proof, coeff, order)

    _add_aggregated_g1_term(lhs_points_by_id, lhs_scalars_by_id, g1_gen, -sum_v, order)

    lhs_points, lhs_scalars = _aggregated_g1_vectors(lhs_points_by_id, lhs_scalars_by_id)
    rhs_points, rhs_scalars = _aggregated_g1_vectors(rhs_points_by_id, rhs_scalars_by_id)
    return lhs_points, lhs_scalars, rhs_points, rhs_scalars


def _random_nonzero_coefficients(count: int, order: int) -> list[int]:
    if count <= 0:
        return []
    coeffs = [1]
    if count == 1:
        return coeffs

    byte_len = (order.bit_length() + 7) // 8
    limit = (1 << (8 * byte_len)) - ((1 << (8 * byte_len)) % order)
    seed = secrets.token_bytes(32)
    counter = 0
    while len(coeffs) < count:
        remaining = count - len(coeffs)
        raw = hashlib.shake_256(seed + counter.to_bytes(8, "little")).digest(byte_len * remaining * 2)
        counter += 1
        for offset in range(0, len(raw), byte_len):
            candidate = int.from_bytes(raw[offset : offset + byte_len], "big")
            if candidate >= limit:
                continue
            coeff = candidate % order
            if coeff:
                coeffs.append(coeff)
                if len(coeffs) == count:
                    break
    return coeffs


class KZG:
    commitment_size = 48
    scalar_modulus = bls.curve_order
    srs = srs

    @classmethod
    def ensure_srs_size(cls, max_degree: int) -> None:
        if max_degree >= len(cls.srs.g1):
            cls.srs = SRS.default(max_degree)

    @staticmethod
    def normalize_g1(point: Point_G1) -> tuple[int, int]:
        if isinstance(point, (blst.P1, blst.P1_Affine)):
            raw = g1_to_blst(point).serialize()
            return int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:], "big")
        x, y = bls.normalize(point)
        return int(x), int(y)

    @classmethod
    def compress_g1(cls, point: Point_G1) -> bytes:
        return g1_to_blst(point).compress()

    @classmethod
    def serialize_g1_uncompressed(cls, point: Point_G1) -> bytes:
        return g1_to_blst(point).serialize()

    @classmethod
    def decompress_g1(cls, data: bytes) -> Any:
        if len(data) != cls.commitment_size:
            raise ValueError(f"invalid BLS12-381 G1 length: expected {cls.commitment_size}, got {len(data)}")
        try:
            return blst.P1(blst.P1_Affine(data))
        except RuntimeError as exc:
            raise ValueError("invalid BLS12-381 G1 encoding") from exc

    @classmethod
    def msm_g1(cls, points: list[Any], scalars: list[int]) -> Any:
        blst_points = [g1_to_blst(point) for point in points]
        return blst.P1_Affines.mult_pippenger(blst.P1_Affines.as_memory(blst_points), scalars)

    @classmethod
    def commit(cls, coeffs: CoeffVector) -> Any:
        """
        Commit to a polynomial using Pippenger multi-scalar multiplication.

        Args:
            coeffs (CoeffVector): Polynomial coefficients
        Returns:
            G1Point: Commitment point
        """
        if len(coeffs) > 0:
            cls.ensure_srs_size(len(coeffs) - 1)
        srs = cls.srs
        if len(coeffs) > len(srs.g1):
            raise ValueError("polynomial degree exceeds SRS size")

        if not any(coeffs):
            result = blst.P1()  # point at infinity
        else:
            result = blst.P1_Affines.mult_pippenger(
                srs.blst_g1_memory[: len(coeffs)],
                coeffs,
            )

        return result

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
        q, y = synthetic_div_with_eval(coeffs, x)
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
        comm_blst = g1_to_blst(commitment)
        proof_blst = g1_to_blst(proof)

        srs = cls.srs
        g1_gen = srs.blst_g1[0]  # [1]G1
        g2_gen = srs.blst_g2[0]  # [1]G2
        g2_tau = srs.blst_g2[1]  # [tau]G2

        val_g1 = g1_gen.dup().mult(value)
        comm_term = comm_blst.dup().add(val_g1.dup().neg())

        point_g2 = g2_gen.dup().mult(point)
        tau_term = g2_tau.dup().add(point_g2.dup().neg())

        lhs = blst_miller_loop(comm_term, g2_gen)
        rhs = blst_miller_loop(proof_blst, tau_term)

        return bool(blst_final_verify(lhs, rhs))

    @classmethod
    def batch_verify(
        cls,
        verifications: list[PcsVerification],
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

        # Generate random coefficients for batching (first coefficient fixed to 1).
        coeffs = _random_nonzero_coefficients(len(verifications), order)

        srs = cls.srs
        g1_gen = srs.blst_g1[0]  # [1]G1
        g2_gen = srs.blst_g2[0]  # [1]G2
        g2_tau = srs.blst_g2[1]  # [tau]G2

        # Accumulate points and scalars for MSMs
        # LHS = sum(coeff_i * C_i) - (sum(coeff_i * v_i)) * G1 + sum(coeff_i * z_i * proof_i)
        # RHS = sum(coeff_i * proof_i)

        lhs_points_by_id: dict[int, Any] = {}
        lhs_scalars_by_id: dict[int, int] = {}
        rhs_points_by_id: dict[int, Any] = {}
        rhs_scalars_by_id: dict[int, int] = {}

        sum_v = 0

        for coeff, (commitment, proof, point, value) in zip(coeffs, verifications, strict=False):
            comm_blst = g1_to_blst(commitment)
            proof_blst = g1_to_blst(proof)

            # LHS terms
            _add_aggregated_g1_term(lhs_points_by_id, lhs_scalars_by_id, comm_blst, coeff, order)

            sum_v = (sum_v + coeff * value) % order

            _add_aggregated_g1_term(lhs_points_by_id, lhs_scalars_by_id, proof_blst, coeff * point, order)

            # RHS terms
            _add_aggregated_g1_term(rhs_points_by_id, rhs_scalars_by_id, proof_blst, coeff, order)

        # Add G1 term to LHS
        _add_aggregated_g1_term(lhs_points_by_id, lhs_scalars_by_id, g1_gen, -sum_v, order)

        lhs_points, lhs_scalars = _aggregated_g1_vectors(lhs_points_by_id, lhs_scalars_by_id)
        rhs_points, rhs_scalars = _aggregated_g1_vectors(rhs_points_by_id, rhs_scalars_by_id)
        lhs_point = blst.P1_Affines.mult_pippenger(blst.P1_Affines.as_memory(lhs_points), lhs_scalars)
        rhs_point = blst.P1_Affines.mult_pippenger(blst.P1_Affines.as_memory(rhs_points), rhs_scalars)

        lhs = blst_miller_loop(lhs_point, g2_gen)
        rhs = blst_miller_loop(rhs_point, g2_tau)

        return bool(blst_final_verify(lhs, rhs))

    @classmethod
    def batch_verify_linear_preconverted(
        cls,
        verifications: list[LinearPcsVerification],
    ) -> bool:
        """
        Batch verify KZG openings whose commitments are linear combinations.

        The verifier prepares BLST P1 objects up front, so this path folds
        linear commitment terms into the final large batch MSM without first
        materializing small commitments.
        """
        if not verifications:
            return True

        order = bls.curve_order
        coeffs = _random_nonzero_coefficients(len(verifications), order)

        srs = cls.srs
        g1_gen = srs.blst_g1[0]
        g2_gen = srs.blst_g2[0]
        g2_tau = srs.blst_g2[1]

        lhs_points, lhs_scalars, rhs_points, rhs_scalars = _aggregate_linear_batch(
            verifications,
            coeffs,
            g1_gen,
            order,
        )
        lhs_point = blst.P1_Affines.mult_pippenger(blst.P1_Affines.as_memory(lhs_points), lhs_scalars)
        rhs_point = blst.P1_Affines.mult_pippenger(blst.P1_Affines.as_memory(rhs_points), rhs_scalars)

        lhs = blst_miller_loop(lhs_point, g2_gen)
        rhs = blst_miller_loop(rhs_point, g2_tau)

        return bool(blst_final_verify(lhs, rhs))


__all__ = ["KZG", "Opening"]
