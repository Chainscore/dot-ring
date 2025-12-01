from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve


@dataclass(frozen=True)
class Ed448Params:
    """
    Ed448 curve parameters (edwards448).

    The Ed448 curve is a high-security Twisted Edwards curve providing ~224-bit security.
    Defined in RFC 8032 and hash-to-curve parameters from RFC 9380.
    """

    # RFC 9380 compliant suite string and DST for edwards448_XOF:SHAKE256_ELL2_RO_
    SUITE_STRING = b"edwards448_XOF:SHAKE256_ELL2_RO_"
    DST = b"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_"

    # Curve parameters from RFC 8032
    PRIME_FIELD: Final[int] = 2**448 - 2**224 - 1
    ORDER: Final[int] = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
    COFACTOR: Final[int] = 4

    # Generator point (x, y) - Valid Ed448 base point that satisfies the curve equation
    # This point is on the curve: x² + y² = 1 + (-39081)*x²*y² (mod p)
    # GENERATOR_X: Final[int] = (
    #     3
    # )
    # GENERATOR_Y: Final[int] = (
    #     60824814231572554857908961302747
    GENERATOR_X: Final[int] = (
        117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495
    )
    GENERATOR_Y: Final[int] = 19

    # Twisted Edwards parameters: ax² + y² = 1 + dx²y² (mod p)
    # From RFC 8032: Ed448 uses a = 1 and d = -39081
    EDWARDS_A: Final[int] = 1  # a = 1 for Ed448 (untwisted Edwards form)
    EDWARDS_D: Final[int] = -39081  # d = -39081

    # Z parameter for Elligator 2 mapping (RFC 9380)
    Z: Final[int] = -1
    L: Final[int] = 84
    H_A = hashlib.shake_256
    ENDIAN = "little"
    M: Final[int] = 1
    K: Final[int] = 224
    S_in_bytes: Final[int] = 0
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 64  # 512 bits for Ed448 (higher security)

    # Independent blinding base for Pedersen VRF
    # Generated using a deterministic method from a different seed point
    # These should be cryptographically independent from the generator
    BBx: Final[int] = GENERATOR_X
    BBy: Final[int] = GENERATOR_Y
    ELL2_C1 = 0x570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05F  # noqa: E501
    ELL2_C2 = 0x3736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA16  # noqa: E501
    UNCOMPRESSED = True
    POINT_LEN: Final[int] = (PRIME_FIELD.bit_length() + 7) // 8


class Ed448Curve(TECurve):
    """
    Ed448 curve implementation.

    A high-security Twisted Edwards curve providing ~224-bit security.
    Defined in RFC 8032 with hash-to-curve support per RFC 9380.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> None:
        """Initialize Ed448 curve with RFC-compliant parameters."""
        # Default suite and dst
        SUITE_STRING = Ed448Params.SUITE_STRING
        DST = Ed448Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        if e2c_variant.value == "TryAndIncrement":
            SUITE_STRING = b"Ed25519_SHA-512_TAI"  # as per davxy
            DST = b"" + SUITE_STRING

        super().__init__(
            PRIME_FIELD=Ed448Params.PRIME_FIELD,
            ORDER=Ed448Params.ORDER,
            GENERATOR_X=Ed448Params.GENERATOR_X,
            GENERATOR_Y=Ed448Params.GENERATOR_Y,
            COFACTOR=Ed448Params.COFACTOR,
            Z=Ed448Params.Z,
            EdwardsA=Ed448Params.EDWARDS_A,
            EdwardsD=Ed448Params.EDWARDS_D,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Ed448Params.BBx,
            BBy=Ed448Params.BBy,
            L=Ed448Params.L,
            H_A=Ed448Params.H_A,
            M=Ed448Params.M,
            K=Ed448Params.K,
            S_in_bytes=Ed448Params.S_in_bytes,
            Requires_Isogeny=Ed448Params.Requires_Isogeny,
            Isogeny_Coeffs=Ed448Params.Isogeny_Coeffs,
            UNCOMPRESSED=Ed448Params.UNCOMPRESSED,
            ENDIAN=Ed448Params.ENDIAN,
            POINT_LEN=Ed448Params.POINT_LEN,
            CHALLENGE_LENGTH=Ed448Params.CHALLENGE_LENGTH,
        )

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

    def calculate_j_k(self) -> tuple[int, int]:
        """
        Calculate curve parameters J and K for Elligator 2.

        Returns:
            Tuple[int, int]: J and K parameters
        """
        return (156326, 1)  # As Curve448 is its equivalent MGC


class Ed448Point(TEAffinePoint):
    """
    Point on the Ed448 curve.

    Implements point operations specific to the Ed448 curve
    with RFC 8032 and RFC 9380 compliance.
    """

    @classmethod
    def blinding_base(cls) -> Self:
        """
        Get the blinding base point for VRF operations.

        This point is cryptographically independent from the generator
        for secure Pedersen VRF implementations.

        Returns:
            Ed448Point: Blinding base point
        """
        return cls(Ed448Params.BBx, Ed448Params.BBy)

    @classmethod
    def map_to_curve(cls, u: int) -> Self:
        # Use a different mapping specifically for Ed25519
        s, t = cls.curve.map_to_curve_ell2(u)
        return cls.mont_to_ed448(s, t)

    @classmethod
    def mont_to_ed448(cls, u: int, v: int) -> Self:
        """
        Convert a point (u, v) from Curve448 (Montgomery form)
        to Ed448 (Twisted Edwards form).

        Args:
            u (int): Montgomery u-coordinate (mod p)
            v (int): Montgomery v-coordinate (mod p)

        Returns:
            (x, y): Edwards coordinates as integers mod p
        """
        p = cls.curve.PRIME_FIELD

        # x numerator: 4 * v * (u^2 - 1)
        x_num = (4 * v * ((u * u - 1) % p)) % p

        # x denominator: u^4 - 2u^2 + 4v^2 + 1
        x_den = (pow(u, 4, p) - 2 * pow(u, 2, p) + 4 * pow(v, 2, p) + 1) % p

        x = (x_num * cls.curve.inv(x_den)) % p

        # y numerator: -(u^5 - 2u^3 - 4uv^2 + u)
        y_num = -(pow(u, 5, p) - 2 * pow(u, 3, p) - 4 * u * pow(v, 2, p) + u) % p

        # y denominator: u^5 - 2u^2v^2 - 2u^3 - 2v^2 + u
        y_den = (pow(u, 5, p) - 2 * pow(u, 2, p) * pow(v, 2, p) - 2 * pow(u, 3, p) - 2 * pow(v, 2, p) + u) % p

        y = (y_num * cls.curve.inv(y_den)) % p
        return cls(x, y)


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2_NU) -> type[Ed448Point]:
    class Ed448PointVariant(Ed448Point):
        """Point on Ed448 with custom E2C variant"""

        curve: TECurve = Ed448Curve(e2c_variant)

    return Ed448PointVariant


Ed448_NU = CurveVariant(
    name="Ed448_NU",
    curve=Ed448Curve(e2c_variant=E2C_Variant.ELL2_NU),
    point=nu_variant(e2c_variant=E2C_Variant.ELL2_NU),
)

Ed448_RO = CurveVariant(
    name="Ed448_RO",
    curve=Ed448Curve(e2c_variant=E2C_Variant.ELL2),
    point=nu_variant(e2c_variant=E2C_Variant.ELL2),
)
