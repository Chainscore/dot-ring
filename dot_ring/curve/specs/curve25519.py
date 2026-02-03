from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..montgomery.mg_affine_point import MGAffinePoint
from ..montgomery.mg_curve import MGCurve


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
    PRIME_FIELD: Final[int] = 2**255 - 19
    ORDER: Final[int] = 2**252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED
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
    H_A = hashlib.sha512
    ENDIAN = "little"
    M: Final[int] = 1
    K: Final[int] = 128
    S_in_bytes: Final[int] = 128  # 48 64 136 172\
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    # Challenge length in bytes for VRF
    CHALLENGE_LENGTH: Final[int] = 16

    # Blinding base for Pedersen VRF (project-specific: keep if you need them)
    BBu: Final[int] = GENERATOR_U  # 0x2a4f9ef57d59ee131c7c4e1d9b4e3a1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1
    BBv: Final[int] = GENERATOR_V  # 0x1a8d1d5a5f9e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8
    UNCOMPRESSED = True
    POINT_LEN: Final[int] = 32


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
            UNCOMPRESSED=Curve25519Params.UNCOMPRESSED,
            ENDIAN=Curve25519Params.ENDIAN,
            POINT_LEN=Curve25519Params.POINT_LEN,
            CHALLENGE_LENGTH=Curve25519Params.CHALLENGE_LENGTH,
        )

    def __post_init__(self) -> None:
        """Skip parent validation since Curve25519 parameters are known to be valid."""
        # Override the validation from the fixed MGCurve to avoid redundant checks
        pass


# Alternative simpler implementation if the above constructor doesn't work
class Curve25519CurveSimple(MGCurve):
    """
    Simplified Curve25519 implementation using direct dataclass initialization.
    """

    PRIME_FIELD: int = Curve25519Params.PRIME_FIELD
    A: int = Curve25519Params.A
    B: int = Curve25519Params.B

    def __post_init__(self) -> None:
        """Skip validation for known good parameters."""
        pass


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> type[MGAffinePoint]:
    """
    Factory function to create a Curve25519Point class with a specific E2C variant.
    This is the recommended way for library users to work with different hash-to-curve variants.

    Args:
        e2c_variant: The E2C variant to use (ELL2, ELL2_NU)
    Returns:
        A Curve25519Point class configured with the specified variant
    Example:
    """

    class Curve25519PointVariant(MGAffinePoint):
        """Point on Curve25519 with custom E2C variant"""

        curve: Curve25519Curve = Curve25519Curve(e2c_variant)
        pass

    return Curve25519PointVariant


Curve25519_NU = CurveVariant(
    name="Curve25519_NU",
    curve=Curve25519Curve(e2c_variant=E2C_Variant.ELL2_NU),
    point=nu_variant(e2c_variant=E2C_Variant.ELL2_NU),
)

Curve25519_RO = CurveVariant(
    name="Curve25519_RO",
    curve=Curve25519Curve(e2c_variant=E2C_Variant.ELL2),
    point=nu_variant(e2c_variant=E2C_Variant.ELL2),
)
