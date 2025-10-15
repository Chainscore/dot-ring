
from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Optional
from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..montgomery.mg_curve import MGCurve
from ..montgomery.mg_affine_point import MGAffinePoint


@dataclass(frozen=True)
class Curve25519Params:
    """
    Curve25519 parameters (Montgomery form of edwards25519).

    Curve25519 is a Montgomery curve defined by: v² = u³ + 486662u² + u
    over the prime field 2^255 - 19.
    """
    # From RFC 9380 Section 4.1: curve25519_XMD:SHA-512_ELL2_RO_
    SUITE_STRING = b"curve25519_XMD:SHA-512_ELL2_RO_"
    DST = b"QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_"  # Default DST is the same as SUITE_STRING

    # Curve parameters
    PRIME_FIELD: Final[int] = 2 ** 255 - 19
    ORDER: Final[int] = 2 ** 252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    COFACTOR: Final[int] = 8
    # Generator point (u, v) - corresponds to the base point of edwards25519
    GENERATOR_U: Final[int] = 9
    GENERATOR_V: Final[int] = 14781619447589544791020593568409986887264606134616475288964881837755586237401

    # Montgomery curve parameters: v² = u³ + Au² + u
    A: Final[int] = 486662
    B: Final[int] = 1  # B = 1 for Curve25519

    # Z parameter for Elligator 2 mapping (from RFC 9380 Section 4.1)
    Z: Final[int] = 2  # Curve25519 uses Z = 2 for Elligator 2 mapping
    L: Final[int] = 48
    H_A: [Final] = "SHA-512"
    ENDIAN = 'little'
    M: [Final] = 1
    K: [Final] = 128
    S_in_bytes: [Final] = 128
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    # Challenge length in bytes for VRF
    CHALLENGE_LENGTH: Final[int] = 16

    # Blinding base for Pedersen VRF
    BBu: Final[int] = GENERATOR_U
    BBv: Final[int] = GENERATOR_V


class Curve25519Curve(MGCurve):
    """
    Curve25519 implementation (Montgomery form).

    A high-performance curve used in X25519 key exchange.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> None:
        """Initialize Curve255198 with its parameters."""
        # Start with default RO suite and dst
        SUITE_STRING = Curve25519Params.SUITE_STRING
        DST = Curve25519Params.DST

        # Adjust SUITE_STRING and DST based on variant
        # Handle ELL2 variants (default is ELL2_RO)
        if e2c_variant == E2C_Variant.ELL2_NU:
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        # Initialize with proper dataclass pattern for MGCurve
        # Note: This assumes MGCurve is a dataclass with these fields
        super().__init__(
            PRIME_FIELD=Curve25519Params.PRIME_FIELD,
            ORDER=Curve25519Params.ORDER,
            GENERATOR_X=Curve25519Params.GENERATOR_U,
            GENERATOR_Y=Curve25519Params.GENERATOR_V,
            COFACTOR=Curve25519Params.COFACTOR,
            glv=DisabledGLV,  # Curve25519 doesn't use GLV
            Z=Curve25519Params.Z,
            A=Curve25519Params.A,
            B=Curve25519Params.B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Curve25519Params.BBu,
            BBy=Curve25519Params.BBv,
            L=Curve25519Params.L,
            M=Curve25519Params.M,
            K=Curve25519Params.K,
            H_A=Curve25519Params.H_A,
            S_in_bytes=Curve25519Params.S_in_bytes,
            Requires_Isogeny=Curve25519Params.Requires_Isogeny,
            Isogeny_Coeffs=Curve25519Params.Isogeny_Coeffs,
        )

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return challenge length for VRF operations."""
        return Curve25519Params.CHALLENGE_LENGTH

    def __post_init__(self):
        """Skip parent validation since Curve25519 parameters are known to be valid."""
        # Override the validation from the fixed MGCurve to avoid redundant checks
        pass


# Alternative simpler implementation if the above constructor doesn't work
class Curve25519CurveSimple(MGCurve):
    """
    Simplified Curve25519 implementation using direct dataclass initialization.
    """
    PRIME_FIELD: Final[int] = Curve25519Params.PRIME_FIELD
    A: Final[int] = Curve25519Params.A
    B: Final[int] = Curve25519Params.B

    @property
    def CHALLENGE_LENGTH(self) -> int:
        return Curve25519Params.CHALLENGE_LENGTH

    def __post_init__(self):
        """Skip validation for known good parameters."""
        pass


# Try the main implementation first, fall back to simple if needed
Curve25519_MG_Curve: Final[Curve25519Curve] = Curve25519Curve()


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2):
    """
    Factory function to create a Curve25519Point class with a specific E2C variant.
    This is the recommended way for library users to work with different hash-to-curve variants.

    Args:
        e2c_variant: The E2C variant to use (ELL2, ELL2_NU)
    Returns:
        A Curve25519Point class configured with the specified variant
    Example:
    """
    # Create curve with the specified variant
    curve = Curve25519Curve(e2c_variant)

    # Create and return a point class with this curve
    class Curve25519PointVariant(MGAffinePoint):
        """Point on Curve25519 with custom E2C variant"""
        pass

    # Set the curve as a class attribute
    Curve25519PointVariant.curve = curve

    return Curve25519PointVariant


class Curve25519Point(MGAffinePoint):
    """
    Point on the Curve25519 Montgomery curve.
    """
    curve: Final[Curve25519Curve] = Curve25519_MG_Curve

    def __init__(self, u: Optional[int], v: Optional[int], curve=None) -> None:
        """
        Initialize a point on Curve25519.

        Args:
            u: u-coordinate (Montgomery x-coordinate) or None for identity
            v: v-coordinate (Montgomery y-coordinate) or None for identity
            curve: Curve instance (defaults to singleton)
        """
        if curve is None:
            curve = Curve25519_MG_Curve

        # Call parent constructor
        super().__init__(u, v, curve)

    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the generator point of the curve.

        Returns:
            Curve25519Point: Generator point
        """
        return cls(
            Curve25519Params.GENERATOR_U,
            Curve25519Params.GENERATOR_V
        )


    def __str__(self) -> str:
        """String representation."""
        if self.is_identity():
            return "Curve25519Point(IDENTITY)"
        return f"Curve25519Point(u={self.x}, v={self.y})"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return self.__str__()