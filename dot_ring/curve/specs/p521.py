from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..short_weierstrass.sw_curve import SWCurve


@dataclass(frozen=True)
class P521Params:
    """
    NIST P-521 curve parameters.

    The P-521 curve is a NIST-standardized Short Weierstrass curve providing
    256-bit security level, the highest security level in the NIST suite.
    """

    # From RFC 9380 Section 8.4: P521_XMD:SHA-512_SSWU_RO_
    SUITE_STRING = b"P521_XMD:SHA-512_SSWU_RO_"
    DST = b"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_"  # Default DST is the same as SUITE_STRING

    # Curve parameters for y² = x³ - 3x + b
    PRIME_FIELD: Final[
        int
    ] = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    ORDER: Final[
        int
    ] = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    COFACTOR: Final[int] = 1

    # Generator point
    GENERATOR_X: Final[
        int
    ] = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
    GENERATOR_Y: Final[
        int
    ] = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650

    # Short Weierstrass parameters: y² = x³ + ax + b
    WEIERSTRASS_A: Final[int] = -3  # a = -3
    WEIERSTRASS_B: Final[
        int
    ] = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00

    # Z parameter for SSWU mapping (from RFC 9380 Section 8.4)
    Z: Final[int] = -4  # P-521 uses Z = -4 for SSWU mapping
    M: Final[int] = 1  # Field Extension Degree
    K: Final[int] = 256  # Security level
    # expand_message: Final[str] = "XMD"
    H_A = hashlib.sha512
    ENDIAN = "little"
    L: Final[int] = 98
    S_in_bytes: Final[int] = 128  # 64 128 136 72
    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 32  # 256 bits for P-521
    Requires_Isogeny: Final[bool] = False
    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    BBx: Final[
        int
    ] = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66  # noqa: E501
    ELL2_C1 = 0x01C9B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC012345678901234567890123456789012345678901234567890123456789012345678  # noqa: E501
    BBy: Final[
        int
    ] = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650  # noqa: E501
    ELL2_C2 = 0x02D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38945678901234567890123456789012345678901234567890123456789012345678901  # noqa: E501
    Isogeny_Coeffs = None
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 67


class P521Curve(SWCurve):
    """
    NIST P-521 curve implementation.

    The highest security level standardized curve in the NIST suite.
    Defined by the equation y² = x³ - 3x + b over the prime field.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> None:
        """Initialize P-521 curve with its parameters."""
        # Default suite and dst
        SUITE_STRING = P521Params.SUITE_STRING
        DST = P521Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        super().__init__(
            PRIME_FIELD=P521Params.PRIME_FIELD,
            ORDER=P521Params.ORDER,
            GENERATOR_X=P521Params.GENERATOR_X,
            GENERATOR_Y=P521Params.GENERATOR_Y,
            COFACTOR=P521Params.COFACTOR,
            Z=P521Params.Z,
            WeierstrassA=P521Params.WEIERSTRASS_A,
            WeierstrassB=P521Params.WEIERSTRASS_B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=P521Params.BBx,
            BBy=P521Params.BBy,
            M=P521Params.M,
            K=P521Params.K,
            L=P521Params.L,
            S_in_bytes=P521Params.S_in_bytes,
            H_A=P521Params.H_A,
            Requires_Isogeny=P521Params.Requires_Isogeny,
            Isogeny_Coeffs=P521Params.Isogeny_Coeffs,
            UNCOMPRESSED=P521Params.UNCOMPRESSED,
            ENDIAN=P521Params.ENDIAN,
            POINT_LEN=P521Params.POINT_LEN,
            CHALLENGE_LENGTH=P521Params.CHALLENGE_LENGTH,
        )


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> type[SWAffinePoint]:
    class P521PointVariant(SWAffinePoint):
        """Point on P521 with custom E2C variant"""

        curve: P521Curve = P521Curve(e2c_variant)

    return P521PointVariant


P521_RO = CurveVariant(
    name="P521_RO",
    curve=P521Curve(e2c_variant=E2C_Variant.SSWU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU),
)

P521_NU = CurveVariant(
    name="P521_NU",
    curve=P521Curve(e2c_variant=E2C_Variant.SSWU_NU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU_NU),
)
