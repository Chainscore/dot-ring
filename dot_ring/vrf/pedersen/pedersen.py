from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Optional, Tuple, Type, Any
from dot_ring.curve.point import Point

from ...curve.curve import Curve
from ..vrf import VRF
from ...ring_proof.helpers import Helpers


@dataclass
class PedersenVRFProof:
    """
    Container for Pedersen VRF proof components.

    Attributes:

        challenge: The challenge value c
        response: The response value s
    """

    challenge: int
    response: int


class PedersenVRF(VRF):
    def __init__(self, curve: Curve, point_type: Type[Point]):
        """
        Initialize Pedersen VRF with a curve.

        Args:
            curve: Elliptic curve to use (should be Bandersnatch)
        """
        super().__init__(curve, point_type)
        if not isinstance(curve, Curve):
            raise TypeError("Curve must be a valid elliptic curve")

    def blinding(self, secret: bytes, input_point: bytes, add: bytes) -> int:
        DOM_SEP_START = b"\xCC"
        DOM_SEP_END = b"\x00"
        buf = self.curve.SUITE_STRING + DOM_SEP_START
        buf += secret
        buf += input_point
        buf += add
        buf += DOM_SEP_END
        # hashed = hashlib.sha512(buf).digest()
        hashed = self.hash(buf)
        return int.from_bytes(hashed) % self.curve.ORDER

    def proof(
        self,
        alpha: bytes | str,
        secret_key: bytes | str,
        additional_data: bytes | str,
        need_blinding=False,
        salt: bytes = b"",
    ) -> bytes | tuple[Any, bytes]:
        """
        Generate Pedersen VRF proof.

        Args:
            alpha: Input message
            secret_key: Secret key
            additional_data: Additional data for challenge
            blinding_factor:blinding factor for compressed public Key
            salt: Optional salt for encoding

        Returns:
            Tuple[Point, Tuple[Point,Point,Point,int,int]]: (output_point, (public_key_cp_proof,r_proof,Ok_proof,s,sb))
        """

        if not isinstance(additional_data, bytes):
            additional_data = bytes.fromhex(additional_data)
        if not isinstance(alpha, bytes):
            alpha = bytes.fromhex(alpha)

        scalar_len = (self.curve.PRIME_FIELD.bit_length() + 7) // 8
        secret_key = (
            Helpers.str_to_int(secret_key, self.curve.ENDIAN) % self.curve.ORDER
        )

        # Create generator point
        generator = self.point_type.generator_point()

        b_base = self.point_type(self.curve.BBx, self.curve.BBy)
        input_point = self.point_type.encode_to_curve(alpha, salt)
        blinding = Helpers.to_l_endian(self.blinding(secret_key.to_bytes(self.point_len,'little'), input_point.point_to_string(),additional_data), self.point_len)
        blinding_factor = Helpers.l_endian_2_int(blinding)
        output_point = input_point * secret_key

        if self.point_type.__name__ == "P256PointVariant":
            input_point_octet = input_point.point_to_string()
            k = self.ecvrf_nonce_rfc6979(secret_key, input_point_octet)
            Kb = self.ecvrf_nonce_rfc6979(blinding_factor, input_point_octet)

        else:
            k = self.generate_nonce(secret_key, input_point)
            Kb = self.generate_nonce(blinding_factor, input_point)

        public_key_cp = generator * secret_key + b_base * blinding_factor
        R = generator * k + b_base * Kb
        Ok = input_point * k
        c = self.challenge(
            [public_key_cp, input_point, output_point, R, Ok], additional_data
        )
        s = (k + c * secret_key) % self.curve.ORDER
        Sb = (Kb + c * blinding_factor) % self.curve.ORDER
        proof = (
            output_point.point_to_string()
            + public_key_cp.point_to_string()
            + R.point_to_string()
            + Ok.point_to_string()
            + Helpers.int_to_str(s, self.curve.ENDIAN, scalar_len)
            + Helpers.int_to_str(Sb, self.curve.ENDIAN, scalar_len)
        )
        if need_blinding:
            return proof, blinding
        return proof

    # to make the point type dynamic

    def verify(
        self,
        input_point: Point,
        additional_data: bytes | str,
        proof: bytes | str,
    ) -> bool:
        """
        Verify Pedersen VRF proof.

        Args:
            input_point: Input point
            additional_data: Additional data used in proof
            output_point: Claimed output point
            proof: Proof tuple (Compressed_input_point, R_point, Ok_point,c, s)

        Returns:
            bool: True if proof is valid
        """
        if not isinstance(additional_data, bytes):
            additional_data = bytes.fromhex(additional_data)

        if not isinstance(proof, bytes):
            proof = bytes.fromhex(proof)

        generator = self.point_type.generator_point()

        scalr_len = (self.curve.PRIME_FIELD.bit_length() + 7) // 8

        point_length = self.point_len

        if self.curve.UNCOMPRESSED:
            point_length *= 2

        output_point = self.point_type.string_to_point(
            proof[point_length * 0 : point_length * 1]
        )
        b_base = self.point_type(self.curve.BBx, self.curve.BBy)

        public_key_cp, R, Ok, s, Sb = (
            self.point_type.string_to_point(proof[point_length * 1 : point_length * 2]),
            self.point_type.string_to_point(proof[point_length * 2 : point_length * 3]),
            self.point_type.string_to_point(proof[point_length * 3 : point_length * 4]),
            Helpers.str_to_int(proof[-scalr_len * 2 : -scalr_len], self.curve.ENDIAN),
            Helpers.str_to_int(proof[-scalr_len:], self.curve.ENDIAN),
        )

        c = self.challenge(
            [public_key_cp, input_point, output_point, R, Ok], additional_data
        )
        
        # Theta0 = (Ok + output_point * c) == input_point * s
        theta0_lhs = Ok + output_point * c
        
        Theta0 = theta0_lhs == input_point * s
        
        # Theta1 = R + (public_key_cp * c) == generator * s + b_base * Sb
        theta1_lhs = R + (public_key_cp * c)
        theta1_rhs = generator * s + b_base * Sb
            
        Theta1 = theta1_lhs == theta1_rhs
        return Theta0 == Theta1

    def get_public_key(self, secret_key: bytes | str) -> bytes:
        """Take the Secret_Key and return Public Key"""
        secret_key = Helpers.str_to_int(secret_key, self.curve.ENDIAN)
        # Create generator point
        generator = self.point_type.generator_point()
        public_key = generator * secret_key
        p_k = public_key.point_to_string()
        return p_k
