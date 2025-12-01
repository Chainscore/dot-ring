from __future__ import annotations
from dataclasses import dataclass
from ...curve.point import CurvePoint
from dot_ring.curve.point import Point
from ..vrf import VRF
from ...curve.curve import Curve, CurveVariant
from ...ring_proof.helpers import Helpers

@dataclass
class IETF_VRF(VRF):
    """
    IETF specification compliant VRF implementation.

    This implementation follows the IETF draft specification
    for VRFs using the Bandersnatch curve.
    
    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.ietf.ietf import IETF_VRF
    >>> proof: IETF_VRF = IETF_VRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    >>> verified = proof.verify(public_key, input_point, additional_data)
    """
    output_point: CurvePoint
    c: int
    s: int
    
    @classmethod
    def from_bytes(cls, proof_bytes: bytes) -> IETF_VRF:
        """
        Deserialize proof from bytes.

        Args:
            proof_bytes: Bytes representation of the proof
        Returns:
            IETF_VRF: Deserialized proof object
        """
        challenge_len = cls.cv.curve.CHALLENGE_LENGTH
        output_point_end = cls.cv.curve.POINT_LEN
        # Calculate positions in the proof
        if cls.cv.curve.UNCOMPRESSED:
            output_point_end *= 2

        c_end = output_point_end + challenge_len
        # Extract components
        output_point = cls.cv.point.string_to_point(proof_bytes[:output_point_end])
        c = (
            Helpers.str_to_int(proof_bytes[output_point_end:c_end], cls.cv.curve.ENDIAN)
            % cls.cv.curve.ORDER
        )
        s = Helpers.str_to_int(proof_bytes[c_end:], cls.cv.curve.ENDIAN) % cls.cv.curve.ORDER
        return cls(output_point, c, s)
    
    def to_bytes(self) -> bytes:
        """
        Serialize proof to bytes.

        Returns:
            bytes: Bytes representation of the proof
        """
        scalar_len = (self.cv.curve.PRIME_FIELD.bit_length() + 7) // 8
        proof = (
            self.output_point.point_to_string()
            + Helpers.int_to_str(self.c, self.cv.curve.ENDIAN, self.cv.curve.CHALLENGE_LENGTH)
            + Helpers.int_to_str(self.s, self.cv.curve.ENDIAN, scalar_len)
        )
        return proof
    
    @classmethod
    def prove(
        cls,
        alpha: bytes,
        secret_key: bytes,
        additional_data: bytes,
        salt: bytes = b"",
    ) -> IETF_VRF:
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
        secret_key = (
            Helpers.str_to_int(secret_key, cls.cv.curve.ENDIAN) % cls.cv.curve.ORDER
        )

        # Create generator point
        generator = cls.cv.point.generator_point()
        # Encode input to curve point
        input_point = cls.cv.point.encode_to_curve(alpha, salt)
        # Compute output point and public key
        output_point = input_point * secret_key
        public_key = generator * secret_key

        if cls.cv.point.__name__ == "P256PointVariant":
            input_point_octet = input_point.point_to_string()
            nonce = cls.ecvrf_nonce_rfc6979(secret_key, input_point_octet)
        else:
            # Generate nonce and compute proof points
            nonce = cls.generate_nonce(secret_key, input_point)

        U = generator * nonce
        V = input_point * nonce

        # Generate challenge
        c = cls.challenge(
            [public_key, input_point, output_point, U, V], additional_data
        )
        s = (nonce + (c * secret_key)) % cls.cv.curve.ORDER
        return cls(output_point, c, s)


    def verify(
        self,
        public_key: bytes,
        input: bytes,
        additional_data: bytes,
        salt: bytes = b""
    ) -> bool:
        """
        Verify IETF VRF proof.

        Args:
            public_key: Public key point
            input_point: Input point
            additional_data: Additional data used in proof
            proof: Proof bytes
            salt: Optional salt for encoding

        Returns:
            bool: True if proof is valid
        """
        input_point = self.cv.point.encode_to_curve(input, salt)
        public_key_pt = self.cv.point.string_to_point(public_key)
        generator = self.cv.point.generator_point()
        n = self.cv.curve.ORDER
        neg_c = (-self.c) % n

        # MSM for U = G*s + pk*(-c) and V = H*s + O*(-c)
        U = self.cv.point.msm([generator, public_key_pt], [self.s, neg_c])
        V = self.cv.point.msm([input_point, self.output_point], [self.s, neg_c])
        
        # Verify challenge
        expected_c = self.challenge(
            [public_key_pt, input_point, self.output_point, U, V], additional_data
        )

        return self.c == expected_c

