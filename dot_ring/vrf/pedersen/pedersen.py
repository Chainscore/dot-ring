from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Optional, Tuple, Type
from dot_ring.curve.point import Point

from ...curve.curve import Curve
from ...curve.specs.bandersnatch import BandersnatchPoint
from ..vrf import VRF


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

    def prove(
        self,
        alpha: bytes,
        secret_key: int,
        additional_data: bytes,
        blinding_factor: int,
        salt: bytes = b"",
    ) -> Tuple[
        Point,
        Tuple[Point, Point, Point, int, int],
    ]:
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

        # Create generator point
        generator = self.point_type.generator_point()

        b_base = self.point_type(self.curve.BBx, self.curve.BBy)
        input_point = self.point_type.encode_to_curve(alpha, salt)

        output_point = input_point * secret_key
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

        return output_point, (public_key_cp, R, Ok, s, Sb)

    def verify(
        self,
        input_point: Point,
        additional_data: bytes,
        output_point: Point,
        proof: Tuple[Point, Point, Point, int, int],
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
        generator = self.point_type.generator_point()

        b_base = self.point_type(self.curve.BBx, self.curve.BBy)
        public_key_cp, R, Ok, s, Sb = proof
        c = self.challenge(
            [public_key_cp, input_point, output_point, R, Ok], additional_data
        )
        Theta0 = (Ok + output_point * c) == input_point * s
        Theta1 = R + (public_key_cp * c) == generator * s + b_base * Sb
        return Theta0 == Theta1
