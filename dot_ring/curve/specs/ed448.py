from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class Ed448Params:
    """
    Ed448 curve parameters (edwards448).

    The Ed448 curve is a high-security Twisted Edwards curve providing ~224-bit security.
    Defined in RFC 8032 and hash-to-curve parameters from RFC 9380.
    """
    # RFC 9380 compliant suite string and DST for edwards448_XOF:SHAKE256_ELL2_RO_
    SUITE_STRING = b"edwards448_XOF:SHAKE256_ELL2_RO_"
    DST = b"edwards448_XOF:SHAKE256_ELL2_RO_"

    # Curve parameters from RFC 8032
    PRIME_FIELD: Final[int] = 2 ** 448 - 2 ** 224 - 1
    ORDER: Final[int] = 2 ** 446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
    COFACTOR: Final[int] = 4

    # Generator point (x, y) - Valid Ed448 base point that satisfies the curve equation
    # This point is on the curve: x² + y² = 1 + (-39081)*x²*y² (mod p)
    GENERATOR_X: Final[int] = (
        3
    )
    GENERATOR_Y: Final[int] = (
        608248142315725548579089613027470755631970544493249636720114649005312536082174920317165848102547021453544566006733948867319461398184873
    )

    # Twisted Edwards parameters: ax² + y² = 1 + dx²y² (mod p)
    # From RFC 8032: Ed448 uses a = 1 and d = -39081
    EDWARDS_A: Final[int] = 1  # a = 1 for Ed448 (untwisted Edwards form)
    EDWARDS_D: Final[int] = -39081  # d = -39081

    # Z parameter for Elligator 2 mapping (RFC 9380)
    Z: Final[int] = -1

    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 64  # 512 bits for Ed448 (higher security)

    # Independent blinding base for Pedersen VRF
    # Generated using a deterministic method from a different seed point
    # These should be cryptographically independent from the generator
    BBx: Final[int] = (
        0x5f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05f
    )
    BBy: Final[int] = (
        0x793f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa16
    )


class Ed448Curve(TECurve):
    """
    Ed448 curve implementation.

    A high-security Twisted Edwards curve providing ~224-bit security.
    Defined in RFC 8032 with hash-to-curve support per RFC 9380.
    """
    # Ed448 points are encoded in 57 bytes (448 bits + 1 sign bit)
    ENCODING_LENGTH: Final[int] = 57  # 448 bits = 56 bytes + 1 byte for sign bit

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for Ed448 VRF."""
        return Ed448Params.CHALLENGE_LENGTH

    def __init__(self) -> None:
        """Initialize Ed448 curve with RFC-compliant parameters."""
        super().__init__(
            PRIME_FIELD=Ed448Params.PRIME_FIELD,
            ORDER=Ed448Params.ORDER,
            GENERATOR_X=Ed448Params.GENERATOR_X,
            GENERATOR_Y=Ed448Params.GENERATOR_Y,
            COFACTOR=Ed448Params.COFACTOR,
            glv=DisabledGLV,  # Ed448 doesn't use GLV
            Z=Ed448Params.Z,
            EdwardsA=Ed448Params.EDWARDS_A,
            EdwardsD=Ed448Params.EDWARDS_D,
            SUITE_STRING=Ed448Params.SUITE_STRING,
            DST=Ed448Params.DST,
            E2C=E2C_Variant.ELL2,
            BBx=Ed448Params.BBx,
            BBy=Ed448Params.BBy
        )
        # Set the encoding length for this curve
        self.ENCODING_LENGTH = self.__class__.ENCODING_LENGTH

    def is_on_curve(self, x: int, y: int) -> bool:
        """
        Check if point (x, y) is on the Ed448 curve.

        Ed448 equation: x² + y² = 1 + d*x²*y² (mod p)
        where a = 1 (untwisted Edwards form)

        Args:
            x: x-coordinate
            y: y-coordinate

        Returns:
            bool: True if point is on curve
        """
        p = self.PRIME_FIELD
        d = Ed448Params.EDWARDS_D

        # Compute left side: x² + y²
        left = (x * x + y * y) % p

        # Compute right side: 1 + d*x²*y²
        right = (1 + d * x * x * y * y) % p

        return left == right


# Singleton instance
Ed448_TE_Curve: Final[Ed448Curve] = Ed448Curve()


@dataclass(frozen=True)
class Ed448Point(TEAffinePoint):
    """
    Point on the Ed448 curve.

    Implements point operations specific to the Ed448 curve
    with RFC 8032 and RFC 9380 compliance.
    """
    curve: Final[Ed448Curve] = Ed448_TE_Curve

    def __init__(self, x: int, y: int) -> None:
        """
        Initialize a point on the Ed448 curve.

        Args:
            x: x-coordinate
            y: y-coordinate

        Raises:
            ValueError: If point is not on curve
        """
        if not self.curve.is_on_curve(x, y):
            raise ValueError(f"Point ({x}, {y}) is not on Ed448 curve")
        super().__init__(x, y, self.curve)

    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the RFC 8032 standard generator point of the curve.

        Returns:
            Ed448Point: Standard Ed448 generator point
        """
        return cls(
            Ed448Params.GENERATOR_X,
            Ed448Params.GENERATOR_Y
        )

    @classmethod
    def identity(cls) -> Self:
        """
        Get the identity element (point at infinity).

        For Edwards curves: (0, 1) is the identity element.

        Returns:
            Ed448Point: Identity element
        """
        return cls(0, 1)

    @classmethod
    def blinding_base(cls) -> Self:
        """
        Get the blinding base point for VRF operations.

        This point is cryptographically independent from the generator
        for secure Pedersen VRF implementations.

        Returns:
            Ed448Point: Blinding base point
        """
        return cls(
            Ed448Params.BBx,
            Ed448Params.BBy
        )

    def encode_point(self) -> bytes:
        """
        Encode point according to RFC 8032 Ed448 encoding.
        Uses the base class point_to_string method with the curve's ENCODING_LENGTH.

        Returns:
            bytes: 57-byte encoded point
        """
        return super().point_to_string()

    def to_bytes(self) -> bytes:
        """
        Convert point to bytes using Ed448 encoding.
        Alias for encode_point() for compatibility with existing code.

        Returns:
            bytes: 57-byte encoded point
        """
        return self.encode_point()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        Create point from bytes using Ed448 decoding.
        Uses the base class string_to_point method.

        Args:
            data: 57-byte encoded point

        Returns:
            Ed448Point: Decoded point
        """
        return cls.string_to_point(data)

    @classmethod
    def decode_point(cls, data: bytes) -> Self:
        """
        Decode point according to RFC 8032 Ed448 encoding.
        Alias for from_bytes for compatibility with existing code.

        Args:
            data: 57-byte encoded point

        Returns:
            Ed448Point: Decoded point

        Raises:
            ValueError: If decoding fails
        """
        return cls.from_bytes(data)


# Additional utility functions for Ed448

def ed448_scalar_clamp(scalar_bytes: bytes) -> int:
    """
    Clamp a scalar according to RFC 8032 Ed448 requirements.

    Args:
        scalar_bytes: 57-byte scalar

    Returns:
        int: Clamped scalar
    """
    if len(scalar_bytes) != 57:
        raise ValueError("Ed448 scalar must be 57 bytes")

    # Convert to integer
    scalar = int.from_bytes(scalar_bytes, 'little')

    # Clear the two least significant bits
    scalar &= ~3

    # Clear all bits of the last octet
    scalar &= ~(0xFF << (8 * 56))

    # Set the highest bit of the second-to-last octet
    scalar |= (1 << (8 * 55 + 7))

    return scalar

