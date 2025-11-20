from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Type
from dot_ring.curve.point import Point
from ..vrf import VRF
from ...curve.curve import Curve
from ...ring_proof.helpers import Helpers


@dataclass
class IETFVRFProof:
    """
    Container for IETF VRF proof components.

    Attributes:
        challenge: The challenge value c
        response: The response value s
    """
    challenge: int
    response: int


class IETF_VRF(VRF):
    """
    IETF specification compliant VRF implementation.

    This implementation follows the IETF draft specification
    for VRFs using the Bandersnatch curve.
    """

    def __init__(self, curve: Curve, point_type: Type[Point]):
        """
        Initialize IETF VRF with a curve.

        Args:
            curve: Elliptic curve to use (should be Bandersnatch)
        """
        super().__init__(curve, point_type)
        if not isinstance(curve, Curve):
            raise TypeError("Curve must be a valid elliptic curve")
    def proof(
            self,
            alpha: bytes|str,
            secret_key: bytes|str,
            additional_data: bytes|str,
            salt: bytes = b''
    ) -> bytes:
        """
        Generate IETF VRF proof.

        Args:
            alpha: Input message
            secret_key: Secret key
            additional_data: Additional data for challenge
            salt: Optional salt for encoding

        Returns:
            Tuple[BandersnatchPoint, Tuple[int, int]]: (output_point, (c, s))
        """
        if not isinstance(additional_data, bytes):
            additional_data= bytes.fromhex(additional_data)
        if not isinstance(alpha, bytes):
            alpha= bytes.fromhex(alpha)

        secret_key = Helpers.str_to_int(secret_key, self.curve.ENDIAN)%self.curve.ORDER

        # Create generator point
        generator = self.point_type.generator_point()

        # Encode input to curve point
        input_point = self.point_type.encode_to_curve(alpha, salt)
        # Compute output point and public key
        output_point = input_point * secret_key
        public_key = generator * secret_key

        # if self.point_type.__name__ == "P256PointVariant":

        if self.point_type.__name__ == "P256Point":
            input_point_octet = input_point.point_to_string()
            nonce = self.ecvrf_nonce_rfc6979(secret_key, input_point_octet)
        else:
            # Generate nonce and compute proof points
            nonce = self.generate_nonce(secret_key, input_point)

        U = generator * nonce
        V = input_point * nonce

        # Generate challenge
        c = self.challenge(
            [public_key, input_point, output_point, U, V],
            additional_data
        )
        s = (nonce + (c * secret_key)) % self.curve.ORDER
        scalar_len=(self.curve.PRIME_FIELD.bit_length() + 7) // 8
        proof= output_point.point_to_string()+ Helpers.int_to_str(c,self.curve.ENDIAN,self.curve.CHALLENGE_LENGTH)+ Helpers.int_to_str(s,self.curve.ENDIAN, scalar_len)
        return proof

    #to make the point type dynamic
    def verify(
            self,
            public_key: Point,
            input_point: Point,
            additional_data: bytes|str,
            proof:bytes|str
    ) -> bool:
        """
        Verify IETF VRF proof.

        Args:
            public_key: Public key point
            input_point: Input point
            additional_data: Additional data used in proof
            proof: Proof tuple (c, s)

        Returns:
            bool: True if proof is valid
        """
        if not isinstance(additional_data, bytes):
            additional_data= bytes.fromhex(additional_data)

        if  not isinstance(proof, bytes):
            proof = bytes.fromhex(proof)

        point_len = self.point_len # Compressed point length is fixed at 32 bytes for Bandersnatch\
        challenge_len = self.curve.CHALLENGE_LENGTH
        output_point_end=point_len
        # Calculate positions in the proof
        if self.curve.UNCOMPRESSED:
            output_point_end *=2

        c_end = output_point_end + challenge_len
        # Extract components
        output_point = self.point_type.string_to_point(proof[:output_point_end])
        c = Helpers.str_to_int(proof[output_point_end:c_end], self.curve.ENDIAN)%self.curve.ORDER
        s = Helpers.str_to_int(proof[c_end:], self.curve.ENDIAN)%self.curve.ORDER
        # Create generator point
        generator = self.point_type.generator_point()
        # Compute proof points
        U = (generator * s) - (public_key * c)
        V = (input_point * s) - (output_point * c)
        # Verify challenge
        expected_c = self.challenge(
            [public_key, input_point, output_point, U, V],
            additional_data
        )

        return c == expected_c

    def get_public_key(self, secret_key:bytes|str)->bytes:
        """Take the Secret_Key and return Public Key"""
        secret_key = Helpers.str_to_int(secret_key, self.curve.ENDIAN) % self.curve.ORDER
        # Create generator point
        generator = self.point_type.generator_point()
        public_key = generator * secret_key
        p_k=public_key.point_to_string()
        return p_k