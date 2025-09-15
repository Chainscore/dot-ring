from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..short_weierstrass.sw_curve import SWCurve
from ..short_weierstrass.sw_affine_point import SWAffinePoint


@dataclass(frozen=True)
class P256Params:
    """
    NIST P-256 (secp256r1) curve parameters.

    The P-256 curve is a NIST-standardized Short Weierstrass curve widely used
    in TLS, digital signatures, and other cryptographic applications.
    """
    # From RFC 9380 Section 8.1: P-256_XMD:SHA-256_SSWU_RO_
    SUITE_STRING = b"P256_XMD:SHA-256_SSWU_RO_"
    DST = b"P256_XMD:SHA-256_SSWU_RO_"  # Default DST is the same as SUITE_STRING

    # Curve parameters for y² = x³ - 3x + b
    PRIME_FIELD: Final[int] = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    ORDER: Final[int] = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    COFACTOR: Final[int] = 1

    # Generator point
    GENERATOR_X: Final[int] = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    GENERATOR_Y: Final[int] = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    # Short Weierstrass parameters: y² = x³ + ax + b
    WEIERSTRASS_A: Final[int] = -3  # a = -3
    WEIERSTRASS_B: Final[int] = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    # Z parameter for SSWU mapping (from RFC 9380 Section 8.1)
    Z: Final[int] = -10  # P-256 uses Z = -10 for SSWU mapping

    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    BBx: Final[int] = 0x2c9b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac012
    BBy: Final[int] = 0x7d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38945
    
    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits


class P256Curve(SWCurve):
    """
    NIST P-256 (secp256r1) curve implementation.

    A widely standardized curve used in many cryptographic protocols.
    Defined by the equation y² = x³ - 3x + b over the prime field.
    """
    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for P-256 VRF."""
        return P256Params.CHALLENGE_LENGTH

    def __init__(self) -> None:
        """Initialize P-256 curve with its parameters."""
        super().__init__(
            PRIME_FIELD=P256Params.PRIME_FIELD,
            ORDER=P256Params.ORDER,
            GENERATOR_X=P256Params.GENERATOR_X,
            GENERATOR_Y=P256Params.GENERATOR_Y,
            COFACTOR=P256Params.COFACTOR,
            glv=DisabledGLV,  # P-256 doesn't have efficient GLV
            Z=P256Params.Z,
            WeierstrassA=P256Params.WEIERSTRASS_A,
            WeierstrassB=P256Params.WEIERSTRASS_B,
            SUITE_STRING=P256Params.SUITE_STRING,
            DST=P256Params.DST,
            E2C=E2C_Variant.SSWU,
            BBx=P256Params.BBx,
            BBy=P256Params.BBy
        )


# Singleton instance
P256_SW_Curve: Final[P256Curve] = P256Curve()


@dataclass(frozen=True)
class P256Point(SWAffinePoint):
    """
    Point on the NIST P-256 curve.

    Implements point operations specific to the P-256 curve.
    """
    curve: Final[P256Curve] = P256_SW_Curve

    def __init__(self, x: int, y: int) -> None:
        """
        Initialize a point on the P-256 curve.

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
            P256Point: Generator point
        """
        return cls(
            P256Params.GENERATOR_X,
            P256Params.GENERATOR_Y
        )
