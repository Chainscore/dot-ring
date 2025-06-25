from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple, Type

from dot_ring.curve.point import Point
from ..vrf import VRF
from ...curve.curve import Curve


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

    def prove(
            self,
            alpha: bytes,
            secret_key: int,
            additional_data: bytes,
            salt: bytes = b''
    ) -> Tuple[Point, Tuple[int, int]]:
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
        # Create generator point
        generator = self.point_type.generator_point()

        # Encode input to curve point
        input_point = self.point_type.encode_to_curve(alpha, salt)

        # Compute output point and public key
        output_point = input_point * secret_key
        public_key = generator * secret_key

        # Generate nonce and compute proof points
        nonce = self.generate_nonce(secret_key, input_point)
        U = generator * nonce
        V = input_point * nonce

        # Generate challenge
        c = self.challenge(
            [public_key, input_point, output_point, U, V],
            additional_data
        )

        # Compute response
        s = (nonce + c * secret_key) % self.curve.ORDER

        return output_point, (c, s)

    def verify(
            self,
            public_key: Point,
            input_point: Point,
            additional_data: bytes,
            output_point: Point,
            proof: Tuple[int, int]
    ) -> bool:
        """
        Verify IETF VRF proof.

        Args:
            public_key: Public key point
            input_point: Input point
            additional_data: Additional data used in proof
            output_point: Claimed output point
            proof: Proof tuple (c, s)

        Returns:
            bool: True if proof is valid
        """
        c, s = proof

        # Create generator point
        generator = self.point_type.generator_point()

        # Compute proof points
        U = generator * s - public_key * c
        V = input_point * s - output_point * c
        # Verify challenge
        expected_c = self.challenge(
            [public_key, input_point, output_point, U, V],
            additional_data
        )

        return c == expected_c