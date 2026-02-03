from __future__ import annotations

import hashlib
import hmac
from abc import abstractmethod
from typing import Any, ClassVar, Generic, Literal, Protocol, Self, TypeVar, cast

from ..curve.curve import CurveVariant
from ..curve.point import CurvePoint, Point
from ..ring_proof.helpers import Helpers

C = TypeVar("C", bound=CurveVariant)
P = TypeVar("P", bound=Point)


class VRFProtocol(Protocol[C, P]):
    """Protocol defining the interface for VRF implementations."""

    curve: C
    point_type: type[P]

    @abstractmethod
    def proof(self, alpha: bytes, secret_key: int, additional_data: bytes) -> tuple[P, tuple[int, int]]:
        """Generate VRF proof."""
        ...

    @abstractmethod
    def verify(
        self,
        public_key: P,
        input_point: P,
        additional_data: bytes,
        output_point: P,
        proof: tuple[int, int],
    ) -> bool:
        """Verify VRF proof."""
        ...


class VRF(Generic[C]):
    """
    Base VRF (Verifiable Random Function) implementation.

    This class provides the core functionality for VRF operations,
    following the IETF specification.

    Usage with subscript syntax:
        >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
        >>> from dot_ring.vrf.ietf.ietf import IETF_VRF
        >>> proof = IETF_VRF[Bandersnatch].prove(alpha, secret_key, additional_data)
    """

    cv: ClassVar[CurveVariant]

    def __class_getitem__(cls, curve_variant: CurveVariant | Any) -> type[Self] | Any:
        """
        Create a specialized VRF class for a specific curve variant.

        Args:
            curve_variant: The CurveVariant to specialize for

        Returns:
            A new class with cv set to the curve variant, or cls if generic
        """
        if not isinstance(curve_variant, CurveVariant):
            return cls
        new_class = type(f"{cls.__name__}[{curve_variant.name}]", (cls,), {"cv": curve_variant})
        return new_class

    @classmethod
    def generate_nonce(cls, secret_key: int, input_point: CurvePoint) -> int:
        """
        Generate a deterministic nonce for VRF proof.

        Args:
            secret_key: The secret key
            input_point: The input point

        Returns:
            int: Generated nonce
        """
        # Hash secret key (little-endian)
        scalr_len = (cls.cv.curve.ORDER.bit_length() + 7) // 8
        sk_encoded = Helpers.int_to_str(
            secret_key % cls.cv.curve.ORDER,
            cast(Literal["little", "big"], cls.cv.curve.ENDIAN),
            scalr_len,
        )
        hash_len = 2 * scalr_len
        hashed_sk = cls.cv.curve.hash(sk_encoded, hash_len)
        sk_hash = hashed_sk[scalr_len:hash_len]
        # sk_hash_int was unused
        # sk_hash_int = Helpers.str_to_int(sk_hash, cast(Literal["little", "big"], cls.cv.curve.ENDIAN))
        # Concatenate with input point encoding
        if isinstance(input_point, int):
            raise ValueError("Input point must be a CurvePoint")
        input_point_octet = input_point.point_to_string()
        data = sk_hash + input_point_octet
        # Generate final nonce
        nonce_hash = cls.cv.curve.hash(data, hash_len)
        nonce = Helpers.str_to_int(nonce_hash, cast(Literal["little", "big"], cls.cv.curve.ENDIAN))

        # Calculate k = nonce % order
        k = nonce % cls.cv.curve.ORDER
        return k

    @classmethod
    def challenge(cls, points: list[CurvePoint], additional_data: bytes) -> int:
        """
        Generate VRF challenge according to RFC 9381.

        The challenge length is determined by the curve's CHALLENGE_LENGTH parameter,
        which is typically set based on the curve's security level.

        Args:
            points: List of points to include in the challenge
            additional_data: Additional data to include in challenge

        Returns:
            int: Generated challenge in the range [0, curve.ORDER)
        """
        # Create challenge string with domain separator (0x02)
        challenge_string = cls.cv.curve.SUITE_STRING + bytes([0x02])

        # Add point encodings for each point in the challenge
        for point in points:
            challenge_string += point.point_to_string()

        # Add additional data and finalize with 0x00
        hash_input = challenge_string + additional_data + bytes([0x00])

        # Generate hash output
        hash_output = cls.cv.curve.hash(hash_input, cls.cv.curve.CHALLENGE_LENGTH)

        # Truncate to the curve's specified challenge length
        challenge_hash = hash_output[: cls.cv.curve.CHALLENGE_LENGTH]

        # Convert to integer and reduce modulo curve order
        return Helpers.b_endian_2_int(challenge_hash) % cls.cv.curve.ORDER

    @classmethod
    def ecvrf_nonce_rfc6979(cls, secret_scalar: int, h_string: bytes, hash_func: str = "sha256") -> int:
        """
        nonce generation as per rfc_6979
        Deterministically derives a nonce from secret scalar and input bytes.
        Simplified: one HMAC pass, no loop.
        """
        hasher = getattr(hashlib, hash_func)
        hlen = hasher().digest_size
        q = cls.cv.curve.ORDER
        # Convert inputs
        x_bytes = secret_scalar.to_bytes((q.bit_length() + 7) // 8, "big")
        h1 = hasher(h_string).digest()
        # Initialize V, K
        V = b"\x01" * hlen
        K = b"\x00" * hlen
        # Step 1: K = HMAC_K(V || 0x00 || x || h1)
        K = hmac.new(K, V + b"\x00" + x_bytes + h1, hasher).digest()
        # Step 2: V = HMAC_K(V)
        V = hmac.new(K, V, hasher).digest()
        # Step 3: K = HMAC_K(V || 0x01 || x || h1)
        K = hmac.new(K, V + b"\x01" + x_bytes + h1, hasher).digest()
        # Step 4: V = HMAC_K(V)
        V = hmac.new(K, V, hasher).digest()
        # Step 5: one more HMAC_K(V)
        V = hmac.new(K, V, hasher).digest()
        # Interpret V as integer and mod q
        k = int.from_bytes(V, "big") % q
        if k == 0:
            k = 1  # (optional) avoid zero, as per RFC6979 loop idea
        return k

    @classmethod
    def ecvrf_decode_proof(cls, pi_string: bytes | str) -> tuple[CurvePoint, int, int]:
        """Decode VRF proof.

        Args:
            pi_string: VRF proof

        Returns:
            Tuple[CurvePoint, int, int]: (gamma, C, S)
        """

        if not isinstance(pi_string, bytes):
            pi_string = bytes.fromhex(pi_string)

        # Get lengths from curve parameters
        challenge_len = cls.cv.curve.CHALLENGE_LENGTH  # Dynamic challenge length from curve
        scalar_len = (cls.cv.curve.ORDER.bit_length() + 7) // 8  # Scalar length based on curve order

        # Calculate positions in the proof
        gamma_end = cls.cv.curve.POINT_LEN

        if cls.cv.curve.UNCOMPRESSED:
            gamma_end *= 2

        c_end = gamma_end + challenge_len
        s_end = c_end + scalar_len

        # Extract components
        gamma_string = pi_string[:gamma_end]
        c_string = pi_string[gamma_end:c_end]
        s_string = pi_string[c_end:s_end]

        # Convert to appropriate types]
        gamma = cls.cv.point.string_to_point(gamma_string)
        if isinstance(gamma, str):
            raise ValueError("Invalid gamma point")
        C = Helpers.str_to_int(c_string, cast(Literal["little", "big"], cls.cv.curve.ENDIAN))
        S = Helpers.str_to_int(s_string, cast(Literal["little", "big"], cls.cv.curve.ENDIAN))

        if S >= cls.cv.curve.ORDER:
            raise ValueError("Response scalar S is not less than the curve order")

        return gamma, C, S

    @classmethod
    def ecvrf_proof_to_hash(cls, pi_string: bytes | str) -> bytes:
        """Convert VRF proof to hash.

        Args:
            pi_string: VRF proof

        Returns:
            bytes: Hash of VRF proof
        """
        if not isinstance(pi_string, bytes):
            pi_string = bytes.fromhex(pi_string)
        gamma, C, S = cls.ecvrf_decode_proof(pi_string)
        return cls.proof_to_hash(gamma)

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        """Convert VRF proof to hash.

        Args:
            gamma: VRF output point

        Returns:
            bytes: Hash of VRF proof
        """
        proof_to_hash_domain_separator_front = b"\x03"
        proof_to_hash_domain_separator_back = b"\x00"
        beta_string = cls.cv.curve.hash(
            cls.cv.curve.SUITE_STRING
            + proof_to_hash_domain_separator_front
            + (
                gamma
                # In some cases, we don't want to multiply by the cofactor.
                # https://github.com/davxy/ark-ec-vrfs/issues/52
                if not mul_cofactor
                else gamma * cls.cv.curve.COFACTOR
            ).point_to_string()
            + proof_to_hash_domain_separator_back,
        )
        return beta_string

    @classmethod
    def get_public_key(cls, secret_key: bytes) -> bytes:
        """Take the Secret_Key and return Public Key"""
        secret_key_int = Helpers.str_to_int(secret_key, cast(Literal["little", "big"], cls.cv.curve.ENDIAN)) % cls.cv.curve.ORDER
        # Create generator point
        generator = cls.cv.point.generator_point()
        public_key: CurvePoint = cast(Any, generator) * secret_key_int
        p_k = public_key.point_to_string()
        return p_k
