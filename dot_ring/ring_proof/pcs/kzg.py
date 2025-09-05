from __future__ import annotations

import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Sequence, Tuple, Any

import time
import py_ecc.optimized_bls12_381 as bls
from py_ecc.optimized_bls12_381 import (
    G1,
    add,
    multiply,
    neg, Z1, pairing, normalize, double)
from py_ecc.optimized_bls12_381.optimized_pairing import miller_loop
from py_ecc.optimized_bls12_381 import FQ, FQ2
#use either of pyblst or blst from github
from pyblst import BlstP1Element, final_verify, BlstP2Element

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
    """Evaluate poly at x modulo the curve order using Horner’s rule."""
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
        # G2 only needs two powers: 1 and Tau
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

    __slots__ = ("_srs","_blst_g1_cache","use_third_party_commit")


    def __init__(self, srs: SRS, use_third_party_commit: bool = True):
        self._srs = srs
        self._blst_g1_cache = [self.py_ecc_point_to_blst(p) for p in srs.g1]
        self.use_third_party_commit = use_third_party_commit

    # convert py_ecc's bls g1 type point to blst_P1
    @staticmethod
    def py_ecc_point_to_blst(p):
            compressed_hex = Helpers.bls_g1_compress(p)  # gives valid compressed hex string
            compressed_bytes = bytes.fromhex(compressed_hex)
            return BlstP1Element().uncompress(compressed_bytes)


    def commit(self, scalars: CoeffVector) -> G1Point:
        if getattr(self, "use_third_party_commit", True):
            return self.third_party_commit(scalars)
        else:
            return self.in_built_commit(scalars)

    #commitment generation using py_blst
    def in_built_commit(self, scalars:CoeffVector)->G1Point:
        # bases_py_ecc = self._srs.g1[:len(scalars)]
        bases=self._blst_g1_cache[:len(scalars)]
        # bases = [self.py_ecc_point_to_blst(p) for p in bases_py_ecc]
        acc = BlstP1Element()
        for base, scalar in zip(bases, scalars):
            acc += base.scalar_mul(scalar)
        res=acc
        decompressed = Helpers.bls_g1_decompress(res.compress().hex()) #compress the blst to byte_string and then to bls g1 point type
        return decompressed

    # w.o using multi scalar multiplication
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
    @staticmethod
    def fq_to_bytes(fq_element, byte_length=48):
        """Convert optimized_bls12_381_FQ to 48-byte big-endian format"""
        try:
            # Try different methods to extract the integer value
            if hasattr(fq_element, 'n'):
                # Some libraries store the value in .n attribute
                value = fq_element.n
            elif hasattr(fq_element, 'value'):
                # Some libraries store the value in .value attribute
                value = fq_element.value
            elif hasattr(fq_element, '__int__'):
                # If it supports direct int conversion
                value = int(fq_element)
            else:
                # Try to convert to string then int (last resort)
                value = int(str(fq_element))

            # Convert to 48-byte big-endian format as required by blst
            return value.to_bytes(byte_length, 'big')
        except Exception as e:
            raise ValueError(f"Cannot convert FQ element to bytes: {e}")

    @staticmethod
    def jacobian_to_affine_coords(x, y, z):
        """Convert Jacobian coordinates (x, y, z) to affine (x/z², y/z³)"""
        # BLS12-381 field prime
        p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

        if int(z) == 0:
            # Point at infinity
            return None, None
        elif int(z) == 1:
            # Already in affine coordinates
            return int(x), int(y)
        else:
            # Convert z to int and compute modular inverse
            z_int = int(z)
            z_inv = pow(z_int, -1, p)  # Modular inverse
            z_inv_squared = (z_inv * z_inv) % p
            z_inv_cubed = (z_inv_squared * z_inv) % p

            x_affine = (int(x) * z_inv_squared) % p
            y_affine = (int(y) * z_inv_cubed) % p

            return x_affine, y_affine

    @staticmethod
    def convert_g1_point_to_blst(g1_tuple):
        """Convert (x, y, z) tuple to blst.P1 point"""
        try:
            import blst
        except ImportError:
            raise ImportError("blst is not installed. Please install it or set use_third_party_commit=False.")
        x, y, z = g1_tuple

        # Convert to affine coordinates
        x_affine, y_affine = KZG.jacobian_to_affine_coords(x, y, z)

        if x_affine is None:
            # Point at infinity
            return blst.P1()  # Identity point

        # Convert to bytes (48 bytes each for x and y)
        x_bytes = x_affine.to_bytes(48, 'big')
        y_bytes = y_affine.to_bytes(48, 'big')

        # Create affine point from 96 bytes (48 + 48)
        point_bytes = x_bytes + y_bytes

        try:
            # Method 1: Try direct P1_Affine constructor
            affine_point = blst.P1_Affine(point_bytes)
            return blst.P1(affine_point)
        except:
            try:
                # Method 2: Try deserialize
                point = blst.P1()
                if point.deserialize(point_bytes) == blst.BLST_SUCCESS:
                    return point
                else:
                    raise ValueError("Deserialization failed")
            except:
                # Method 3: Try uncompress (if we have compressed format)
                try:
                    point = blst.P1()
                    # Try with compressed format (48 bytes x-coordinate only)
                    if point.uncompress(x_bytes) == blst.BLST_SUCCESS:
                        return point
                    else:
                        raise ValueError("Uncompression failed")
                except:
                    raise ValueError("All conversion methods failed")

    def third_party_commit(self, coeffs: CoeffVector) -> G1Point:

        try:
            import blst
        except ImportError:
            raise ImportError("blst is not installed. Please install it or set use_third_party_commit=False.")

        if len(coeffs) > len(self._srs.g1):
            raise ValueError("polynomial degree exceeds SRS size")

        # Convert points and filter non-zero coefficients
        blst_points = []
        active_scalars = []

        for coeff, g1_tuple in zip(coeffs, self._srs.g1):
            if coeff != 0:
                try:
                    blst_point = KZG.convert_g1_point_to_blst(g1_tuple)
                    blst_points.append(blst_point)
                    active_scalars.append(coeff)
                except Exception as e:
                    print(f"Warning: Failed to convert point, skipping: {e}")
                    continue

        if not blst_points:
            result = bls.Z1  # point at infinity
        else:
            # Use Pippenger multi-scalar multiplication
            try:
                result = blst.P1_Affines.mult_pippenger(
                    blst.P1_Affines.as_memory(blst_points),
                    active_scalars
                )
            except Exception as e:
                print(f"Pippenger failed: {e}")
                # Fallback to original method
                result = bls.Z1
                for coeff, g1_point in zip(coeffs, self._srs.g1):
                    if coeff:
                        result = add(result, multiply(g1_point, coeff))
        return KZG.blst_p1_to_fq_tuple(result)

    @staticmethod
    def blst_p1_to_fq_tuple(blst_point):
        """Convert blst.P1 point back to (FQ, FQ, FQ) tuple in Jacobian coordinates"""

        try:
            # Method 1: Convert to affine coordinates first
            affine_point = blst_point.to_affine()

            # Serialize the affine point to bytes (96 bytes: 48 for x, 48 for y)
            point_bytes = affine_point.serialize()

            # Split into x and y coordinates (48 bytes each)
            x_bytes = point_bytes[:48]
            y_bytes = point_bytes[48:96]

            # Convert bytes back to integers
            x_int = int.from_bytes(x_bytes, 'big')
            y_int = int.from_bytes(y_bytes, 'big')

            # Create FQ elements from integers
            x_fq = FQ(x_int)
            y_fq = FQ(y_int)
            z_fq = FQ(1)  # Affine coordinates have z=1

            return (x_fq, y_fq, z_fq)

        except Exception as e:
            print(f"Method 1 failed: {e}")

            try:
                # Method 2: Use compress/serialize if available
                compressed_bytes = blst_point.compress()  # 48 bytes compressed format

                # You'll need to decompress this back to full coordinates
                # This might require using your optimized_bls12_381 library's decompression
                # For now, let's try a different approach

                # Get the jacobian coordinates directly if possible
                # Note: This is pseudocode - blst might not expose jacobian coords directly
                if hasattr(blst_point, 'x') and hasattr(blst_point, 'y') and hasattr(blst_point, 'z'):
                    x_fq = FQ(int(blst_point.x))
                    y_fq = FQ(int(blst_point.y))
                    z_fq = FQ(int(blst_point.z))
                    return (x_fq, y_fq, z_fq)
                else:
                    raise ValueError("Cannot access jacobian coordinates")

            except Exception as e2:
                print(f"Method 2 failed: {e2}")

                # Method 3: Manual decompression from compressed format
                try:
                    compressed = blst_point.compress()
                    x_bytes = compressed[:48]
                    x_int = int.from_bytes(x_bytes, 'big')

                    # Decompress using curve equation y² = x³ + 4 (for BLS12-381)
                    # This is complex and might be better done by your library
                    p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

                    # y² = x³ + 4 (mod p)
                    y_squared = (pow(x_int, 3, p) + 4) % p

                    # Find square root (this is simplified - actual implementation is more complex)
                    y_int = pow(y_squared, (p + 1) // 4, p)  # Works for p ≡ 3 (mod 4)

                    # Check sign bit from compressed format to determine correct y
                    if compressed[0] & 0x20:  # Sign bit
                        y_int = p - y_int

                    x_fq = FQ(x_int)
                    y_fq = FQ(y_int)
                    z_fq = FQ(1)

                    return (x_fq, y_fq, z_fq)

                except Exception as e3:
                    raise ValueError(f"All conversion methods failed: {e}, {e2}, {e3}")



    def open(self, coeffs: CoeffVector, x: Scalar) -> Opening:

        y = _horner_eval(coeffs, x)
        q = _synthetic_div(coeffs, x, y)
        proof = self.commit(q)
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
        srs_g2 = [
            (FQ2([x[0], x[1]]), FQ2([y[0], y[1]]), FQ2([1, 0]))
            for (x, y) in g2_points
        ]
        # Compute right side: e(commitment - [value]G1, G2)
        g1_value = multiply(G1, value)  # G1->G
        commitment_minus_value = add(commitment, neg(g1_value))
        # Right pairing: e(commitment - [value]G1, G2)
        right_pairing = miller_loop(srs_g2[0],commitment_minus_value)
        # Left pairing: e(proof, [tau]G2 - [point]G2)
        # Compute left side: e(proof, [tau]G2 - [point]G2)
        g2_point = multiply(srs_g2[0], point)  # G2->H.i
        shifted_g2 = add(srs_g2[1], neg(g2_point))  # srs_g2[1]->H.t
        left_pairing =miller_loop(shifted_g2,proof)
        return left_pairing == right_pairing


    @classmethod
    def default(cls, *, max_deg: int = 2048, use_third_party_commit=True) -> "KZG":
        srs = SRS.default(max_deg)
        kzg = cls(srs)
        kzg.use_third_party_commit = use_third_party_commit  # <== Add this flag to instance
        return kzg


