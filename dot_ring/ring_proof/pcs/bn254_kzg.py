from __future__ import annotations

import secrets
from typing import Any

import py_ecc.optimized_bn128 as bn254  # type: ignore[import-untyped]

from .bn254_serialization import read_field, sqrt_mod_prime, write_field, y_flag
from .bn254_srs import BN254SRS
from .opening import Opening
from .utils import CoeffVector, Scalar

BN254_G1Point = Any


def _poly_evaluate_mod(coeffs: CoeffVector, x: int, modulus: int) -> int:
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + int(coeff)) % modulus
    return result


def _synthetic_div_mod(coeffs: CoeffVector, x: int, y: int, modulus: int) -> list[int]:
    if len(coeffs) < 2:
        return [0]
    q = [0] * (len(coeffs) - 1)
    carry = int(coeffs[-1]) % modulus
    q[-1] = carry
    for i in range(len(coeffs) - 2, 0, -1):
        carry = (int(coeffs[i]) + carry * x) % modulus
        q[i - 1] = carry
    remainder = (int(coeffs[0]) + carry * x) % modulus
    if remainder != y % modulus:
        raise ValueError("inconsistent polynomial opening")
    return q


class BN254KZG:
    commitment_size = 32
    scalar_modulus = bn254.curve_order
    srs = BN254SRS.default()

    @staticmethod
    def normalize_g1(point: BN254_G1Point) -> tuple[int, int]:
        if bn254.is_inf(point):
            return (0, 0)
        x, y = bn254.normalize(point)
        return int(x), int(y)

    @classmethod
    def compress_g1(cls, point: BN254_G1Point) -> bytes:
        if bn254.is_inf(point):
            return write_field(0, 0x40)
        x, y = cls.normalize_g1(point)
        return write_field(x, y_flag(y))

    @classmethod
    def serialize_g1_uncompressed(cls, point: BN254_G1Point) -> bytes:
        if bn254.is_inf(point):
            return write_field(0) + write_field(0, 0x40)
        x, y = cls.normalize_g1(point)
        return write_field(x) + write_field(y, y_flag(y))

    @classmethod
    def decompress_g1(cls, data: bytes) -> BN254_G1Point:
        x, flag = read_field(data, flags=True)
        if flag == 0x40:
            if x != 0:
                raise ValueError("invalid BN254 point at infinity")
            return bn254.Z1
        rhs = (pow(x, 3, bn254.field_modulus) + 3) % bn254.field_modulus
        y = sqrt_mod_prime(rhs, bn254.field_modulus)
        if y_flag(y) != flag:
            y = (-y) % bn254.field_modulus
        point = (bn254.FQ(x), bn254.FQ(y), bn254.FQ(1))
        if not bn254.is_on_curve(point, bn254.b):
            raise ValueError("invalid BN254 G1 point")
        return point

    @classmethod
    def commit(cls, coeffs: CoeffVector) -> BN254_G1Point:
        if len(coeffs) > len(cls.srs.g1):
            raise ValueError("polynomial degree exceeds SRS size")
        acc = bn254.Z1
        for coeff, point in zip(coeffs, cls.srs.g1, strict=False):
            scalar = int(coeff) % cls.scalar_modulus
            if scalar:
                acc = bn254.add(acc, bn254.multiply(point, scalar))
        return acc

    @classmethod
    def msm_g1(cls, points: list[BN254_G1Point], scalars: list[int]) -> BN254_G1Point:
        acc = bn254.Z1
        for point, scalar in zip(points, scalars, strict=False):
            scalar = int(scalar) % cls.scalar_modulus
            if scalar:
                acc = bn254.add(acc, bn254.multiply(point, scalar))
        return acc

    @classmethod
    def open(cls, coeffs: CoeffVector, x: Scalar) -> Opening:
        point = int(x) % cls.scalar_modulus
        y = _poly_evaluate_mod(coeffs, point, cls.scalar_modulus)
        q = _synthetic_div_mod(coeffs, point, y, cls.scalar_modulus)
        return Opening(cls.commit(q), y)

    @classmethod
    def verify(cls, commitment: BN254_G1Point, proof: BN254_G1Point, point: Scalar, value: Scalar) -> bool:
        z = int(point) % cls.scalar_modulus
        y = int(value) % cls.scalar_modulus
        g1_gen = cls.srs.g1[0]
        g2_gen = cls.srs.g2[0]
        g2_tau = cls.srs.g2[1]
        commitment_term = bn254.add(commitment, bn254.neg(bn254.multiply(g1_gen, y)))
        tau_term = bn254.add(g2_tau, bn254.neg(bn254.multiply(g2_gen, z)))
        lhs = bn254.final_exponentiate(bn254.pairing(g2_gen, commitment_term, final_exponentiate=False))
        rhs = bn254.final_exponentiate(bn254.pairing(tau_term, proof, final_exponentiate=False))
        return bool(lhs == rhs)

    @classmethod
    def batch_verify(cls, verifications: list[tuple[BN254_G1Point, BN254_G1Point, Scalar, Scalar]]) -> bool:
        if not verifications:
            return True

        if len(verifications) == 1:
            return cls.verify(*verifications[0])

        order = cls.scalar_modulus
        coeffs = [1]
        for _ in range(len(verifications) - 1):
            coeff = 0
            while coeff == 0:
                coeff = secrets.randbelow(order)
            coeffs.append(coeff)

        g1_gen = cls.srs.g1[0]
        g2_gen = cls.srs.g2[0]
        g2_tau = cls.srs.g2[1]
        lhs_points: list[BN254_G1Point] = []
        lhs_scalars: list[int] = []
        rhs_points: list[BN254_G1Point] = []
        rhs_scalars: list[int] = []
        sum_v = 0

        for coeff, (commitment, proof, point, value) in zip(coeffs, verifications, strict=False):
            z = int(point) % order
            y = int(value) % order
            lhs_points.append(commitment)
            lhs_scalars.append(coeff)
            lhs_points.append(proof)
            lhs_scalars.append((coeff * z) % order)
            rhs_points.append(proof)
            rhs_scalars.append(coeff)
            sum_v = (sum_v + coeff * y) % order

        lhs_points.append(g1_gen)
        lhs_scalars.append((-sum_v) % order)

        lhs_point = cls.msm_g1(lhs_points, lhs_scalars)
        rhs_point = cls.msm_g1(rhs_points, rhs_scalars)
        lhs = bn254.final_exponentiate(bn254.pairing(g2_gen, lhs_point, final_exponentiate=False))
        rhs = bn254.final_exponentiate(bn254.pairing(g2_tau, rhs_point, final_exponentiate=False))
        return bool(lhs == rhs)
