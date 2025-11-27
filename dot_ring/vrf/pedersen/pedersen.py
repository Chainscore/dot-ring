from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Optional, Tuple, Type, Any
from dot_ring.curve.point import CurvePoint, Point

from ...curve.curve import Curve, CurveVariant
from ..vrf import VRF
from ...ring_proof.helpers import Helpers

@dataclass
class PedersenVRF(VRF):
    """
    Pedersen VRF implementation.

    This implementation provides Pedersen-style VRF operations
    with blinding support.
    
    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.pedersen.pedersen import PedersenVRF
    >>> proof = PedersenVRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    >>> verified = PedersenVRF[Bandersnatch].verify(input_point, additional_data, proof)
    """
    
    output_point: CurvePoint
    blinded_pk: CurvePoint
    result_point: CurvePoint
    ok: CurvePoint
    s: int
    sb: int
    
    # Blinding factor used in proof generation
    _blinding_factor: int

    @classmethod
    def from_bytes(cls, proof: bytes) -> "PedersenVRF":
        scalar_len = (cls.cv.curve.PRIME_FIELD.bit_length() + 7) // 8

        point_length = cls.cv.curve.POINT_LEN
        if cls.cv.curve.UNCOMPRESSED:
            point_length *= 2

        output_point = cls.cv.point.string_to_point(
            proof[point_length * 0 : point_length * 1]
        )

        public_key_cp, R, Ok, s, Sb = (
            cls.cv.point.string_to_point(proof[point_length * 1 : point_length * 2]),
            cls.cv.point.string_to_point(proof[point_length * 2 : point_length * 3]),
            cls.cv.point.string_to_point(proof[point_length * 3 : point_length * 4]),
            Helpers.str_to_int(proof[-scalar_len * 2 : -scalar_len], cls.cv.curve.ENDIAN),
            Helpers.str_to_int(proof[-scalar_len:], cls.cv.curve.ENDIAN),
        )
        
        return cls(
            output_point=output_point,
            blinded_pk=public_key_cp,
            result_point=R,
            ok=Ok,
            s=s,
            sb=Sb,
            _blinding_factor=0 # Blinding factor is not needed to verify
        )
    
    def to_bytes(self) -> bytes:
        """
        Serialize proof to bytes.

        Returns:
            bytes: Serialized proof
        """
        scalar_len = (self.cv.curve.PRIME_FIELD.bit_length() + 7) // 8
        point_length = self.cv.curve.POINT_LEN
        if self.cv.curve.UNCOMPRESSED:
            point_length *= 2

        proof = (
            self.output_point.point_to_string()
            + self.blinded_pk.point_to_string()
            + self.result_point.point_to_string()
            + self.ok.point_to_string()
            + Helpers.int_to_str(self.s, self.cv.curve.ENDIAN, scalar_len)
            + Helpers.int_to_str(self.sb, self.cv.curve.ENDIAN, scalar_len)
        )
        return proof
    
    @classmethod
    def prove(
        cls,
        alpha: bytes,
        secret_key: bytes,
        additional_data: bytes,
        salt: bytes = b"",
    ) -> PedersenVRF:
        """
        Generate Pedersen VRF proof.

        Args:
            alpha: Input message
            secret_key: Secret key
            additional_data: Additional data for challenge
            need_blinding: Whether to return blinding factor
            salt: Optional salt for encoding

        Returns:
            bytes: Proof bytes, or tuple of (proof, blinding) if need_blinding=True
        """

        scalar_len = (cls.cv.curve.PRIME_FIELD.bit_length() + 7) // 8
        secret_key = (
            Helpers.str_to_int(secret_key, cls.cv.curve.ENDIAN) % cls.cv.curve.ORDER
        )

        # Create generator point
        generator = cls.cv.point.generator_point()

        b_base = cls.cv.point(cls.cv.curve.BBx, cls.cv.curve.BBy)
        input_point = cls.cv.point.encode_to_curve(alpha, salt)
        # Use curve's endianness for secret key serialization
        secret_key_bytes = secret_key.to_bytes(scalar_len, cls.cv.curve.ENDIAN)
        blinding_factor = cls.blinding(secret_key_bytes, input_point.point_to_string(), additional_data)
        
        output_point = input_point * secret_key

        if cls.cv.point.__name__ == "P256PointVariant":
            input_point_octet = input_point.point_to_string()
            k = cls.ecvrf_nonce_rfc6979(secret_key, input_point_octet)
            Kb = cls.ecvrf_nonce_rfc6979(blinding_factor, input_point_octet)
        else:
            k = cls.generate_nonce(secret_key, input_point)
            Kb = cls.generate_nonce(blinding_factor, input_point)

        public_key_cp = generator * secret_key + b_base * blinding_factor
        R = generator * k + b_base * Kb
        Ok = input_point * k
        c = cls.challenge(
            [public_key_cp, input_point, output_point, R, Ok], additional_data
        )
        s = (k + c * secret_key) % cls.cv.curve.ORDER
        Sb = (Kb + c * blinding_factor) % cls.cv.curve.ORDER
        
        return cls(
            output_point=output_point,
            blinded_pk=public_key_cp,
            result_point=R,
            ok=Ok,
            s=s,
            sb=Sb,
            _blinding_factor=blinding_factor
        )

    def verify(
        self,
        input: bytes,
        additional_data: bytes
    ) -> bool:
        """
        Verify Pedersen VRF proof.

        Args:
            input: Input message bytes
            additional_data: Additional data used in proof

        Returns:
            bool: True if proof is valid
        """
        generator = self.cv.point.generator_point()
        input_point = self.cv.point.encode_to_curve(input)
        b_base = self.cv.point(self.cv.curve.BBx, self.cv.curve.BBy)

        c = self.challenge(
            [self.blinded_pk, input_point, self.output_point, self.result_point, self.ok], additional_data
        )

        # Check 1: ok + c * output_point - s * input_point == 0
        # 1*ok + c*output_point + (-s)*input_point == identity
        check1 = self.cv.point.msm(
            [self.ok, self.output_point, input_point], 
            [1, c, -self.s]
        )
        Theta0 = check1.is_identity()

        # Check 2: result_point + c * blinded_pk - s * generator - sb * b_base == 0
        # 1*result_point + c*blinded_pk + (-s)*generator + (-sb)*b_base == identity
        check2 = self.cv.point.msm(
            [self.result_point, self.blinded_pk, generator, b_base],
            [1, c, -self.s, -self.sb]
        )
        Theta1 = check2.is_identity()

        return Theta0 and Theta1
    
    @classmethod
    def blinding(cls, secret: bytes, input_point: bytes, add: bytes) -> int:
        DOM_SEP_START = b"\xCC"
        DOM_SEP_END = b"\x00"
        buf = cls.cv.curve.SUITE_STRING + DOM_SEP_START
        buf += secret
        buf += input_point
        buf += add
        buf += DOM_SEP_END
        scalar_len = (cls.cv.curve.ORDER.bit_length() + 7) // 8
        hashed = cls.cv.curve.hash(buf, 2 * scalar_len)
        return int.from_bytes(hashed, "big") % cls.cv.curve.ORDER

    @classmethod
    def ecvrf_proof_to_hash(cls, output_point_bytes: bytes | str) -> bytes:
        """Convert VRF output point to hash.

        Args:
            output_point_bytes: VRF output point bytes

        Returns:
            bytes: Hash of VRF output
        """
        if not isinstance(output_point_bytes, bytes):
            output_point_bytes = bytes.fromhex(output_point_bytes)
        output_point = cls.cv.point.string_to_point(output_point_bytes)
        return cls.proof_to_hash(output_point)
