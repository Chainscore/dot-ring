from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve


@dataclass(frozen=True)
class Ed25519Params:
    """
    JubJub curve parameters.

    Specification of the JubJub curve in Twisted Edwards form.
    """

    SUITE_STRING = b"edwards25519_XMD:SHA-512_ELL2_RO_"
    DST = b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"

    # Curve parameters
    PRIME_FIELD: Final[int] = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
    ORDER: Final[int] = 2**252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED
    COFACTOR: Final[int] = 8
    # Generator point
    GENERATOR_X: Final[int] = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    GENERATOR_Y: Final[int] = 0x6666666666666666666666666666666666666666666666666666666666666658
    # Edwards curve parameters
    EDWARDS_A: Final[int] = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC
    EDWARDS_D: Final[int] = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3

    # Z parameter for Elligator 2 mapping (from RFC 9380 Section 4.1)
    Z: Final[int] = 2  # Curve25519 uses Z = 2 for Elligator 2 mapping
    L: Final[int] = 48
    H_A = hashlib.sha512
    ENDIAN = "little"
    M: Final = 1
    K: Final = 128
    S_in_bytes: Final = 128  # 48 64 136 172\
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits

    BBx: Final[int] = 52417091031015867055192825304177001039906336859819158874861527659737645967040
    BBy: Final[int] = 24364467899048426341436922427697710961180476432856951893648702734568269272170

    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 32


class Ed25519Curve(TECurve):
    """
    Bandersnatch curve implementation.

    A high-performance curve designed for zero-knowledge proofs and VRFs,
    offering both efficiency and security.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> None:
        """Initialize Ed25519 curve with RFC-compliant parameters."""
        # Default suite and dst
        SUITE_STRING = Ed25519Params.SUITE_STRING
        DST = Ed25519Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")
        if e2c_variant.value == "TryAndIncrement":
            SUITE_STRING = b"Ed25519_SHA-512_TAI"  # as per davxy
            DST = b""
        super().__init__(
            PRIME_FIELD=Ed25519Params.PRIME_FIELD,
            ORDER=Ed25519Params.ORDER,
            GENERATOR_X=Ed25519Params.GENERATOR_X,
            GENERATOR_Y=Ed25519Params.GENERATOR_Y,
            COFACTOR=Ed25519Params.COFACTOR,
            Z=Ed25519Params.Z,
            EdwardsA=Ed25519Params.EDWARDS_A,
            EdwardsD=Ed25519Params.EDWARDS_D,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Ed25519Params.BBx,
            BBy=Ed25519Params.BBy,
            L=Ed25519Params.L,
            H_A=Ed25519Params.H_A,
            M=Ed25519Params.M,
            K=Ed25519Params.K,
            S_in_bytes=Ed25519Params.S_in_bytes,
            Requires_Isogeny=Ed25519Params.Requires_Isogeny,
            Isogeny_Coeffs=Ed25519Params.Isogeny_Coeffs,
            UNCOMPRESSED=Ed25519Params.UNCOMPRESSED,
            ENDIAN=Ed25519Params.ENDIAN,
            POINT_LEN=Ed25519Params.POINT_LEN,
            CHALLENGE_LENGTH=Ed25519Params.CHALLENGE_LENGTH,
        )

    def calculate_j_k(self) -> tuple[int, int]:
        """
        Calculate curve parameters J and K for Elligator 2.

        Returns:
            Tuple[int, int]: J and K parameters
        """
        return (486662, 1)  # As Curve25519 is its equivalent MGC


class Ed25519Point(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """

    @classmethod
    def map_to_curve(cls, u: int) -> Self:
        # Use a different mapping specifically for Ed25519
        s, t = cls.curve.map_to_curve_ell2(u)
        return cls.mont_to_ed25519(s, t)

    @classmethod
    def mont_to_ed25519(cls, u: int, v: int) -> Self:
        """
        Convert a point (u, v) from Montgomery form to Edwards form (x, y).
        Returns (x, y).
        """
        p = cls.curve.PRIME_FIELD
        # Precompute sqrt(-486664) mod p
        sqrt_neg_A_minus_2 = cls.curve.mod_sqrt(-486664 % p)
        # y = (u - 1) / (u + 1) mod p
        y = ((u - 1) * pow(u + 1, -1, p)) % p
        # x = sqrt(-486664) * u / v mod p
        x = (sqrt_neg_A_minus_2 * u * pow(v, -1, p)) % p
        return cls(x, y)


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2_NU) -> type[Ed25519Point]:
    class Ed25519PointVariant(Ed25519Point):
        """Point on Ed25519 with custom E2C variant"""

        curve: TECurve = Ed25519Curve(e2c_variant)

    return Ed25519PointVariant


Ed25519_RO = CurveVariant(
    name="Ed25519_RO",
    curve=Ed25519Curve(e2c_variant=E2C_Variant.ELL2),
    point=nu_variant(e2c_variant=E2C_Variant.ELL2),
)

Ed25519_NU = CurveVariant(
    name="Ed25519_TAI",
    curve=Ed25519Curve(e2c_variant=E2C_Variant.TAI),
    point=nu_variant(e2c_variant=E2C_Variant.TAI),
)
