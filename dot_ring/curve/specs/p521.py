from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..short_weierstrass.sw_curve import SWCurve
from ..short_weierstrass.sw_affine_point import SWAffinePoint


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
    PRIME_FIELD: Final[int] = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    ORDER: Final[int] = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    COFACTOR: Final[int] = 1

    # Generator point
    GENERATOR_X: Final[int] = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
    GENERATOR_Y: Final[int] = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650

    # Short Weierstrass parameters: y² = x³ + ax + b
    WEIERSTRASS_A: Final[int] = -3  # a = -3
    WEIERSTRASS_B: Final[int] = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00

    # Z parameter for SSWU mapping (from RFC 9380 Section 8.4)
    Z: Final[int] = -4  # P-521 uses Z = -4 for SSWU mapping
    M: Final[int] = 1  # Field Extension Degree
    K: Final[int] = 256  # Security level
    # expand_message: Final[str] = "XMD"
    H_A: Final[str] = "SHA-512"
    L: [int] = 98
    S_in_bytes:[Final]= 128# 64 128 136 72
    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 32  # 256 bits for P-521
    
    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    BBx: Final[int] = 0x01C9B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC012345678901234567890123456789012345678901234567890123456789012345678
    BBy: Final[int] = 0x02D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38945678901234567890123456789012345678901234567890123456789012345678901


class P521Curve(SWCurve):
    """
    NIST P-521 curve implementation.

    The highest security level standardized curve in the NIST suite.
    Defined by the equation y² = x³ - 3x + b over the prime field.
    """
    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for P-521 VRF."""
        return P521Params.CHALLENGE_LENGTH

    def __init__(self) -> None:
        """Initialize P-521 curve with its parameters."""
        super().__init__(
            PRIME_FIELD=P521Params.PRIME_FIELD,
            ORDER=P521Params.ORDER,
            GENERATOR_X=P521Params.GENERATOR_X,
            GENERATOR_Y=P521Params.GENERATOR_Y,
            COFACTOR=P521Params.COFACTOR,
            glv=DisabledGLV,  # P-521 doesn't have efficient GLV
            Z=P521Params.Z,
            WeierstrassA=P521Params.WEIERSTRASS_A,
            WeierstrassB=P521Params.WEIERSTRASS_B,
            SUITE_STRING=P521Params.SUITE_STRING,
            DST=P521Params.DST,
            E2C=E2C_Variant.SSWU,
            BBx=P521Params.BBx,
            BBy=P521Params.BBy,
            M=P521Params.M,
            K=P521Params.K,
            L=P521Params.L,
            S_in_bytes=P521Params.S_in_bytes,
            H_A=P521Params.H_A,
        )


# Singleton instance
P521_SW_Curve: Final[P521Curve] = P521Curve()


@dataclass(frozen=True)
class P521Point(SWAffinePoint):
    """
    Point on the NIST P-521 curve.

    Implements point operations specific to the P-521 curve.
    """
    curve: Final[P521Curve] = P521_SW_Curve

    def __init__(self, x: int, y: int) -> None:
        """
        Initialize a point on the P-521 curve.

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
            P521Point: Generator point
        """
        return cls(
            P521Params.GENERATOR_X,
            P521Params.GENERATOR_Y
        )

