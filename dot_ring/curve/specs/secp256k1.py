from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Self, Dict, List

from dot_ring.curve.e2c import E2C_Variant
from ..glv import GLVSpecs
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

    PRIME_FIELD: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    ORDER: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    COFACTOR: Final[int] = 1
    # Generator point
    GENERATOR_X: Final[int] = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    GENERATOR_Y: Final[int] = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    # Short Weierstrass parameters: y² = x³ + ax + b
    WEIERSTRASS_A: Final[int] = 0  # a = 0
    WEIERSTRASS_B: Final[int] = 7  # b = 7

    # GLV parameters for secp256k1
    GLV_LAMBDA: Final[int] = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
    GLV_B: Final[int] = 0x3086D221A7D46BCDE86C90E49284EB15
    GLV_C: Final[int] = 0xE4437ED6010E88286F547FA90ABFE4C3

    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits

    # Z parameter for SSWU mapping
    # Z: Final[int] = 1
    Z: Final[int] = -11 # P-256 uses Z = -11 for SSWU mapping
    M: Final[int] = 1  # Field Extension Degree
    K: Final[int] = 128  # Security level
    # expand_message: Final[str] = "XMD"
    H_A: Final[str] = "SHA-256"
    L: [int] = 48
    S_in_bytes: Final[int] = 64
    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    BBx: Final[int] = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
    BBy: Final[int] = 0x31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904
    Requires_Isogeny: Final[bool] = True
    Isogeny_Coeffs= {
            "x_num": [
                0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c,
                0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262,
                0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581,
                0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7
            ],
            "x_den": [
                0x1,  # leading coefficient is 1 for x'^2 term
                0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14,
                0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b,
            ],
            "y_num": [
                0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84,
                0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931,
                0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3,
                0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c
            ],
            "y_den": [
                0x1,  # leading coefficient is 1 for x'^3 term
                0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f,
                0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573,
                0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b,
            ],
        }
    UNCOMPRESSED = False


"""GLV endomorphism parameters for secp256k1 curve."""
Secp256k1GLVSpecs = GLVSpecs(
    is_enabled=True,
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
    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for secp256k1 VRF."""
        return Secp256k1Params.CHALLENGE_LENGTH

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
            glv=Secp256k1GLVSpecs,
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
            UNCOMPRESSED=Secp256k1Params.UNCOMPRESSED
        )


# Singleton instance
Secp256k1_SW_Curve:Final[Secp256k1Curve] = Secp256k1Curve()

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

    def __init__(self, x: int, y: int) -> None:
        """
        Initialize a point on the secp256k1 curve.

        Args:
            x: x-coordinate
            y: y-coordinate

        Raises:
            ValueError: If point is not on curve
        """
        super().__init__(x, y, self.curve)


    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the generator point of the curve.

        Returns:
            Secp256k1Point: Generator point
        """
        return cls(
            Secp256k1Params.GENERATOR_X,
            Secp256k1Params.GENERATOR_Y
        )


    def __mul__(self, scalar: int) -> Self:
        """
        Optimized scalar multiplication using GLV if enabled.

        Args:
            scalar: Scalar to multiply by

        Returns:
            Secp256k1Point: Result of scalar multiplication
        """
        if self.curve.glv.is_enabled:
            return self._glv_mul(scalar)
        else:
            return super().__mul__(scalar)

    def _glv_mul(self, k: int) -> Self:
        """
        GLV-optimized scalar multiplication for secp256k1.

        Args:
            k: Scalar to multiply by

        Returns:
            Secp256k1Point: Result of scalar multiplication
        """
        if k == 0:
            return self.identity()

        if k < 0:
            return (-self)._glv_mul(-k)

        # GLV decomposition: k = k1 + k2*λ (mod n)
        # where λ is the GLV parameter
        glv = self.curve.glv
        n = self.curve.ORDER

        # Simple GLV decomposition (can be optimized further)
        k1 = k % n
        k2 = 0  # Simplified - in practice you'd compute proper decomposition

        # For now, fall back to standard multiplication
        # TODO: Implement full GLV decomposition
        return super().__mul__(k)