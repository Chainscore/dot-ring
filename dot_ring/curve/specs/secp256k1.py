from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

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
    expand_message: Final[str] = "XMD"
    H_A: Final[str] = "SHA256"
    L: [int] = 48

    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    BBx: Final[int] = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
    BBy: Final[int] = 0x31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904


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

    def __init__(self) -> None:
        """Initialize secp256k1 curve with its parameters."""
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
            SUITE_STRING=Secp256k1Params.SUITE_STRING,
            DST=Secp256k1Params.DST,
            E2C=E2C_Variant.SSWU,
            BBx=Secp256k1Params.BBx,
            BBy=Secp256k1Params.BBy
        )


# Singleton instance
Secp256k1_SW_Curve: Final[Secp256k1Curve] = Secp256k1Curve()


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
