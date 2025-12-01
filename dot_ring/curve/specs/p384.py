from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..short_weierstrass.sw_curve import SWCurve


@dataclass(frozen=True)
class P384Params:
    """
    NIST P-384 curve parameters.

    The P-384 curve is a NIST-standardized Short Weierstrass curve providing
    192-bit security level, widely used in high-security applications.
    """

    # From RFC 9380 Section 8.3: P384_XMD:SHA-384_SSWU_RO_
    SUITE_STRING = b"P384_XMD:SHA-384_SSWU_RO_"
    DST = b"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_"  # Default DST is the same as SUITE_STRING

    # Curve parameters for y² = x³ - 3x + b
    PRIME_FIELD: Final[
        int
    ] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
    ORDER: Final[
        int
    ] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    COFACTOR: Final[int] = 1

    # Generator point
    GENERATOR_X: Final[
        int
    ] = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
    GENERATOR_Y: Final[
        int
    ] = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F

    # Short Weierstrass parameters: y² = x³ + ax + b
    WEIERSTRASS_A: Final[int] = -3  # a = -3
    WEIERSTRASS_B: Final[
        int
    ] = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF

    # Z parameter for SSWU mapping (from RFC 9380 Section 8.3)
    Z: Final[int] = -12  # P-384 uses Z = -12 for SSWU mapping
    M: Final[int] = 1  # Field Extension Degree
    K: Final[int] = 192  # Security level
    # expand_message: Final[str] = "XMD"
    H_A = hashlib.sha384
    ENDIAN = "little"
    L: Final[int] = 72
    S_in_bytes: Final[int] = 128
    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 24  # 192 bits for P-384
    Requires_Isogeny: Final[bool] = False
    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    # sample blinding base
    BBx: Final[
        int
    ] = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7  # noqa: E501
    ELL2_C1 = 0x1C9B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC012345678901234567890123456789012  # noqa: E501
    BBy: Final[
        int
    ] = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F  # noqa: E501
    ELL2_C2 = 0x2D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38945678901234567890123456789012345  # noqa: E501
    Isogeny_Coeffs = None
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 49


class P384Curve(SWCurve):
    """
    NIST P-384 curve implementation.

    A high-security standardized curve providing 192-bit security level.
    Defined by the equation y² = x³ - 3x + b over the prime field.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> None:
        """Initialize P-256 curve with its parameters."""
        # Default suite and dst
        SUITE_STRING = P384Params.SUITE_STRING
        DST = P384Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        super().__init__(
            PRIME_FIELD=P384Params.PRIME_FIELD,
            ORDER=P384Params.ORDER,
            GENERATOR_X=P384Params.GENERATOR_X,
            GENERATOR_Y=P384Params.GENERATOR_Y,
            COFACTOR=P384Params.COFACTOR,
            Z=P384Params.Z,
            WeierstrassA=P384Params.WEIERSTRASS_A,
            WeierstrassB=P384Params.WEIERSTRASS_B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=P384Params.BBx,
            BBy=P384Params.BBy,
            M=P384Params.M,
            K=P384Params.K,
            L=P384Params.L,
            S_in_bytes=P384Params.S_in_bytes,
            H_A=P384Params.H_A,
            Requires_Isogeny=P384Params.Requires_Isogeny,
            Isogeny_Coeffs=P384Params.Isogeny_Coeffs,
            UNCOMPRESSED=P384Params.UNCOMPRESSED,
            ENDIAN=P384Params.ENDIAN,
            POINT_LEN=P384Params.POINT_LEN,
            CHALLENGE_LENGTH=P384Params.CHALLENGE_LENGTH,
        )


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> type[SWAffinePoint]:
    class P384PointVariant(SWAffinePoint):
        """Point on P384 with custom E2C variant"""

        curve: P384Curve = P384Curve(e2c_variant)

    return P384PointVariant


P384_RO = CurveVariant(
    name="P384_RO",
    curve=P384Curve(e2c_variant=E2C_Variant.SSWU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU),
)

P384_NU = CurveVariant(
    name="P384_NU",
    curve=P384Curve(e2c_variant=E2C_Variant.SSWU_NU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU_NU),
)
