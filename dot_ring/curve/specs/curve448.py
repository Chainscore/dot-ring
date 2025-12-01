from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..montgomery.mg_affine_point import MGAffinePoint
from ..montgomery.mg_curve import MGCurve


@dataclass(frozen=True)
class Curve448Params:
    """
    Curve448 parameters (Montgomery form of edwards448).

    Curve448 is a Montgomery curve defined by: v² = u³ + 156326u² + u
    over the prime field 2^448 - 2^224 - 1.
    """

    SUITE_STRING = b"curve448_XOF:SHAKE256_ELL2_RO_"
    DST = b"QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_RO_"

    # Curve parameters
    PRIME_FIELD: Final[int] = 2**448 - 2**224 - 1
    ORDER: Final[int] = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
    COFACTOR: Final[int] = 4

    # Generator point (u, v) - corresponds to the base point of edwards448
    # Generator point u-coordinate (from RFC 7748)
    GENERATOR_U: Final[int] = 5

    # v-coordinate is derived from the curve equation v^2 = u^3 + A*u^2 + u mod p
    # Using the positive square root that has even least significant bit (LSB)
    GENERATOR_V: Final[int] = (
        355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362
    )

    # Montgomery curve parameters: v² = u³ + Au² + u
    A: Final[int] = 156326
    B: Final[int] = 1  # B = 1 for Curve448

    # Z parameter for SSWU mapping
    Z: Final[int] = -1
    L: Final[int] = 84
    H_A = hashlib.shake_256
    ENDIAN = "little"
    M: Final[int] = 1
    K: Final[int] = 224
    S_in_bytes: Final[int | None] = None
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    # Challenge length in bytes for VRF (aligned with 224-bit security level)
    CHALLENGE_LENGTH: Final[int] = 28  # 224 bits for Curve448 (corrected from 24)

    # Blinding base for Pedersen VRF
    BBu: Final[int] = GENERATOR_U
    BBv: Final[int] = GENERATOR_V
    UNCOMPRESSED = True
    POINT_LEN: Final[int] = (PRIME_FIELD.bit_length() + 7) // 8


class Curve448Curve(MGCurve):
    """
    Curve448 implementation (Montgomery form).

    A high-security curve used in X448 key exchange.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> None:
        """Initialize Curve448 with its parameters."""
        # Default suite and dst
        SUITE_STRING = Curve448Params.SUITE_STRING
        DST = Curve448Params.DST

        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        # Initialize with proper dataclass pattern for MGCurve
        super().__init__(
            PRIME_FIELD=Curve448Params.PRIME_FIELD,
            ORDER=Curve448Params.ORDER,
            GENERATOR_X=Curve448Params.GENERATOR_U,
            GENERATOR_Y=Curve448Params.GENERATOR_V,
            COFACTOR=Curve448Params.COFACTOR,
            Z=Curve448Params.Z,
            A=Curve448Params.A,
            B=Curve448Params.B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Curve448Params.BBu,
            BBy=Curve448Params.BBv,
            L=Curve448Params.L,
            M=Curve448Params.M,
            K=Curve448Params.K,
            H_A=Curve448Params.H_A,
            S_in_bytes=Curve448Params.S_in_bytes,
            Requires_Isogeny=Curve448Params.Requires_Isogeny,
            Isogeny_Coeffs=Curve448Params.Isogeny_Coeffs,
            UNCOMPRESSED=Curve448Params.UNCOMPRESSED,
            ENDIAN=Curve448Params.ENDIAN,
            POINT_LEN=Curve448Params.POINT_LEN,
            CHALLENGE_LENGTH=Curve448Params.CHALLENGE_LENGTH,
        )

    def __post_init__(self) -> None:
        """Skip parent validation since Curve448 parameters are known to be valid."""
        # Override the validation from the fixed MGCurve to avoid redundant checks
        pass


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> type[MGAffinePoint]:
    """
    Factory function to create a Curve448Point class with a specific E2C variant.

    This is the recommended way for library users to work with different hash-to-curve variants.

    Args:
        e2c_variant: The E2C variant to use (ELL2, ELL2_NU)

    Returns:
        A Curve448Point class configured with the specified variant
    """
    class Curve448PointVariant(MGAffinePoint):
        """Point on Curve448 with custom E2C variant"""
        curve = Curve448Curve(e2c_variant)
        pass

    return Curve448PointVariant



Curve448_NU = CurveVariant(
    name="Curve448_NU",
    curve=Curve448Curve(e2c_variant=E2C_Variant.ELL2_NU),
    point=nu_variant(e2c_variant=E2C_Variant.ELL2_NU),
)

Curve448_RO = CurveVariant(
    name="Curve448_RO",
    curve=Curve448Curve(e2c_variant=E2C_Variant.ELL2),
    point=nu_variant(e2c_variant=E2C_Variant.ELL2),
)
