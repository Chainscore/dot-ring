from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Protocol, Tuple, Type, TypeVar

# from dot_ring.types.protocol.crypto import Hash
# from dot_ring.utils.conv_helper import ConversionHelper

from ..curve.curve import Curve
from ..curve.point import Point
from ..ring_proof.helpers import Helpers

C = TypeVar("C", bound=Curve)
P = TypeVar("P", bound=Point)


class VRFProtocol(Protocol[C, P]):
    """Protocol defining the interface for VRF implementations."""
    curve: C
    point_type: Type[P]

    @abstractmethod
    def prove(
            self, alpha: bytes, secret_key: int, additional_data: bytes
    ) -> Tuple[P, Tuple[int, int]]:
        """Generate VRF proof."""
        ...

    @abstractmethod
    def verify(
            self,
            public_key: P,
            input_point: P,
            additional_data: bytes,
            output_point: P,
            proof: Tuple[int, int],
    ) -> bool:
        """Verify VRF proof."""
        ...


class VRF(ABC):
    """
    Base VRF (Verifiable Random Function) implementation.

    This class provides the core functionality for VRF operations,
    following the IETF specification.
    """
    curve: C
    point_type: Type[P]

    def __init__(self, curve: C, point_type: Type[P]):
        """
        Initialize VRF with a curve.

        Args:
            curve: Elliptic curve to use for VRF operations
        """
        self.curve = curve
        self.point_type = point_type

    def generate_nonce(self, secret_key: int, input_point: Point) -> int:
        """
        Generate a deterministic nonce for VRF proof.

        Args:
            secret_key: The secret key
            input_point: The input point

        Returns:
            int: Generated nonce
        """
        # Hash secret key (little-endian)
        sk_encoded = Helpers.to_l_endian(secret_key)
        # hashed_sk = bytes(Hash.sha512(sk_encoded))
        hashed_sk=Helpers.sha512(sk_encoded)
        sk_hash = hashed_sk[32:64]  # Use second half of SHA-512 output

        # Concatenate with input point encoding
        point_octet = input_point.point_to_string()
        data = sk_hash + point_octet

        # Generate final nonce
        nonce_hash = bytes(Helpers.sha512(data))
        nonce = Helpers.l_endian_2_int(nonce_hash)

        return nonce % self.curve.ORDER

    def challenge(self, points: List[Point], additional_data: bytes) -> int:
        """
        Generate VRF challenge.

        Args:
            Y: Public key point
            I: Input point
            O: Output point
            U: First proof point
            V: Second proof point
            additional_data: Additional data to include in challenge

        Returns:
            int: Generated challenge
        """
        # Create challenge string
        str0 = self.curve.SUITE_STRING + bytes([0x02])
        challenge_string = str0

        # Add point encodings
        for P in points:
            challenge_string += P.point_to_string()

        # Add additional data and finalize
        hash_input = challenge_string + additional_data + bytes([0x00])
        challenge_hash = bytes(Helpers.sha512(hash_input))[:32]

        return Helpers.b_endian_2_int(challenge_hash) % self.curve.ORDER

    def ecvrf_decode_proof(self, pi_string: bytes|str) -> Tuple[Point, int, int]:
        """Decode VRF proof.

        Args:
            pi_string: VRF proof

        Returns:
            Tuple[Point, int, int]: (gamma, C, S)
        """
        if not isinstance(pi_string, bytes):
            pi_string=bytes.fromhex(pi_string)

        ptLen = qLen = cLen = 32
        gamma_string = pi_string[:ptLen]
        c_string = pi_string[ptLen:ptLen + cLen]
        s_string = pi_string[ptLen + cLen:ptLen + cLen + qLen]

        gamma = self.point_type.string_to_point(gamma_string)
        # C = ConversionHelper.to_int(c_string) % self.curve.ORDER
        # S = ConversionHelper.to_int(s_string) % self.curve.ORDER
        C=Helpers.b_endian_2_int(c_string) %self.curve.ORDER
        S=Helpers.b_endian_2_int(s_string) %self.curve.ORDER
        if S >= self.curve.PRIME_FIELD:
            assert False, "S out of bounds"
        return gamma, C, S

    def ecvrf_proof_to_hash(self, pi_string: bytes|str) -> bytes:
        """Convert VRF proof to hash.

        Args:
            pi_string: VRF proof

        Returns:
            bytes: Hash of VRF proof
        """
        if not isinstance(pi_string, bytes):
            pi_string=bytes.fromhex(pi_string)
        gamma, C, S = self.ecvrf_decode_proof(pi_string)
        return self.proof_to_hash(gamma)

    def proof_to_hash(self, gamma: Point, mul_cofactor: bool = False) -> bytes:
        """Convert VRF proof to hash.

        Args:
            gamma: VRF output point

        Returns:
            bytes: Hash of VRF proof
        """
        proof_to_hash_domain_separator_front = b"\x03"
        proof_to_hash_domain_separator_back = b"\x00"
        beta_string = Helpers.sha512(
            self.curve.SUITE_STRING +
            proof_to_hash_domain_separator_front +
            (
                gamma
                # In some cases, we don't want to multiply by the cofactor.
                # https://github.com/davxy/ark-ec-vrfs/issues/52
                if not mul_cofactor
                else gamma * self.curve.COFACTOR
            ).point_to_string() +
            proof_to_hash_domain_separator_back
        )
        return bytes(beta_string)

    @abstractmethod
    def prove(self, *args) -> Tuple[Point, Tuple[int, int]]:
        """
        Generate VRF proof.

        Args:
            alpha: Input message
            secret_key: Secret key
            additional_data: Additional data for challenge
            salt: Optional salt for encoding

        Returns:
            Tuple[Point, Tuple[int, int]]: (output_point, (challenge, response))
        """
        raise NotImplementedError("Must be implemented by the VRF implementation")

    @abstractmethod
    def verify(self, *args) -> bool:
        """
        Verify VRF proof.

        Args:
            public_key: Public key point
            input_point: Input point
            additional_data: Additional data used in proof
            output_point: Claimed output point
            proof: Proof tuple (challenge, response)

        Returns:
            bool: True if proof is valid
        """
        raise NotImplementedError("Must be implemented by the VRF implementation")
