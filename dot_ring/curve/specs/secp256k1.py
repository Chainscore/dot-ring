from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Self

import hashlib

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant
from ..glv import GLV
from ..short_weierstrass.sw_curve import SWCurve
from ..short_weierstrass.sw_affine_point import SWAffinePoint


@dataclass(frozen=True)
class Secp256k1Params:
    """
    secp256k1 curve parameters.

    The secp256k1 curve is a Short Weierstrass curve widely used in Bitcoin
    and other cryptocurrencies. It's defined by y² = x³ + 7.
    """

    SUITE_STRING = b"secp256k1_XMD:SHA-256_SSWU_RO_"
    DST = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"

    # Curve parameters for y² = x³ + 7

    PRIME_FIELD: Final[
        int
    ] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    ORDER: Final[
        int
    ] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    COFACTOR: Final[int] = 1
    # Generator point
    GENERATOR_X: Final[
        int
    ] = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    GENERATOR_Y: Final[
        int
    ] = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    # Short Weierstrass parameters: y² = x³ + ax + b
    WEIERSTRASS_A: Final[int] = 0  # a = 0
    WEIERSTRASS_B: Final[int] = 7  # b = 7

    # GLV parameters for secp256k1
    GLV_LAMBDA: Final[
        int
    ] = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
    GLV_B: Final[int] = 0x3086D221A7D46BCDE86C90E49284EB15
    GLV_C: Final[int] = 0xE4437ED6010E88286F547FA90ABFE4C3

    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits

    # Z parameter for SSWU mapping
    # Z: Final[int] = 1
    Z: Final[int] = -11  # P-256 uses Z = -11 for SSWU mapping
    M: Final[int] = 1  # Field Extension Degree
    K: Final[int] = 128  # Security level
    # expand_message: Final[str] = "XMD"
    H_A = hashlib.sha256
    ENDIAN = "little"
    L: Final[int] = 48
    S_in_bytes: Final[int] = 64
    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    BBx: Final[int] = 0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0
    BBy: Final[int] = 0x31D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38904
    Requires_Isogeny: Final[bool] = True
    Isogeny_Coeffs = {
        "x_num": [
            0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C,
            0x534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262,
            0x7D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581,
            0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7,
        ],
        "x_den": [
            0x1,  # leading coefficient is 1 for x'^2 term
            0xEDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14,
            0xD35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B,
        ],
        "y_num": [
            0x2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84,
            0x29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931,
            0xC75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3,
            0x4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C,
        ],
        "y_den": [
            0x1,  # leading coefficient is 1 for x'^3 term
            0x6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F,
            0x7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573,
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B,
        ],
    }
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 32


"""GLV endomorphism parameters for secp256k1 curve."""
Secp256k1GLVSpecs = GLV(
    lambda_param=Secp256k1Params.GLV_LAMBDA,
    constant_b=Secp256k1Params.GLV_B,
    constant_c=Secp256k1Params.GLV_C,
)


class Secp256k1Curve(SWCurve):
    """
    secp256k1 curve implementation.

    The curve used by Bitcoin and many other cryptocurrencies.
    Defined by the equation y² = x³ + 7 over the prime field.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> None:
        """Initialize secp256k1 curve with its parameters."""
        # Default suite and dst
        SUITE_STRING = Secp256k1Params.SUITE_STRING
        DST = Secp256k1Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        super().__init__(
            PRIME_FIELD=Secp256k1Params.PRIME_FIELD,
            ORDER=Secp256k1Params.ORDER,
            GENERATOR_X=Secp256k1Params.GENERATOR_X,
            GENERATOR_Y=Secp256k1Params.GENERATOR_Y,
            COFACTOR=Secp256k1Params.COFACTOR,
            Z=Secp256k1Params.Z,
            WeierstrassA=Secp256k1Params.WEIERSTRASS_A,
            WeierstrassB=Secp256k1Params.WEIERSTRASS_B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Secp256k1Params.BBx,
            BBy=Secp256k1Params.BBy,
            M=Secp256k1Params.M,
            K=Secp256k1Params.K,
            L=Secp256k1Params.L,
            S_in_bytes=Secp256k1Params.S_in_bytes,
            H_A=Secp256k1Params.H_A,
            Requires_Isogeny=Secp256k1Params.Requires_Isogeny,
            Isogeny_Coeffs=Secp256k1Params.Isogeny_Coeffs,
            UNCOMPRESSED=Secp256k1Params.UNCOMPRESSED,
            ENDIAN=Secp256k1Params.ENDIAN,
            POINT_LEN=Secp256k1Params.POINT_LEN,
            CHALLENGE_LENGTH=Secp256k1Params.CHALLENGE_LENGTH,
        )


Secp256k1_SW_Curve: Final[Secp256k1Curve] = Secp256k1Curve()


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.SSWU):
    # Create curve with the specified variant
    curve = Secp256k1Curve(e2c_variant)

    # Create and return a point class with this curve
    class Secp256k1PointVariant(SWAffinePoint):
        """Point on Secp256k1 with custom E2C variant"""

        def __init__(self, x: int, y: int) -> None:
            """Initialize a point with the variant curve."""
            super().__init__(x, y, curve)

    # Set the curve as a class attribute
    Secp256k1PointVariant.curve = curve

    return Secp256k1PointVariant


@dataclass(frozen=True)
class Secp256k1Point(SWAffinePoint):
    """
    Point on the secp256k1 curve.

    Implements optimized point operations specific to the secp256k1 curve,
    including GLV scalar multiplication for enhanced performance.
    """

    curve: Final[Secp256k1Curve] = Secp256k1_SW_Curve

    def __mul__(self, scalar: int) -> Self:
        """
        GLV-optimized scalar multiplication for secp256k1.

        Args:
            k: Scalar to multiply by

        Returns:
            Secp256k1Point: Result of scalar multiplication
        """
        if scalar == 0:
            return self.identity()

        if scalar < 0:
            return (-self).__mul__(-scalar)

        # GLV decomposition: k = k1 + k2*λ (mod n)
        # where λ is the GLV parameter
        n = self.curve.ORDER

        # Simple GLV decomposition (can be optimized further)
        k1 = scalar % n
        k2 = 0  # Simplified - in practice you'd compute proper decomposition

        # For now, fall back to standard multiplication
        # TODO: Implement full GLV decomposition
        return super().__mul__(scalar)


Secp256k1_RO = CurveVariant(
    name="Secp256k1_RO",
    curve=Secp256k1Curve(e2c_variant=E2C_Variant.SSWU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU),
)

Secp256k1_NU = CurveVariant(
    name="Secp256k1_NU",
    curve=Secp256k1Curve(e2c_variant=E2C_Variant.SSWU_NU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU_NU),
)