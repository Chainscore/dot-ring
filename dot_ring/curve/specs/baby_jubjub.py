from __future__ import annotations
from dataclasses import dataclass
from typing import Final, Self
from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV, GLVSpecs
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class BabyJubJubParams:
    """
    Baby JubJub curve parameters.

    Specification of the Baby JubJub curve in Twisted Edwards form.
    """
    SUITE_STRING = b"Baby-JubJub_SHA-512_TAI"
    DST = b""

    # Curve parameters
    PRIME_FIELD: Final[int] = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    ORDER: Final[int] = 273603115188753742007522749811879420859037173
    COFACTOR: Final[int] = 8

    # Generator point
    GENERATOR_X: Final[int] = 995203441582195749578291179787384436505546430278305826713579947235728471134
    GENERATOR_Y: Final[int] = 5472060717959818805561601436314318772137091100104008585924551046643952123905

    # Edwards curve parameters
    EDWARDS_A: Final[int] = 168700
    EDWARDS_D: Final[int] = 168696

    GLV_LAMBDA: Final[int] = 0x13b4f3dc4a39a493edf849562b38c72bcfc49db970a5056ed13d21408783df05
    GLV_B: Final[int] = 0x52c9f28b828426a561f00d3a63511a882ea712770d9af4d6ee0f014d172510b4
    GLV_C: Final[int] = 0x6cc624cf865457c3a97c6efd6c17d1078456abcfff36f4e9515c806cdf650b3d

    # Z
    Z: Final[int] = 5
    
    # Challenge length in bytes for VRF (aligned with 128-bit security level)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits

    # Blinding Base For Pedersen
    BBx: Final[
        int
    ] = 8170247200255741810297410022472365370979789984587637609570347196251706043122#995203441582195749578291179787384436505546430278305826713579947235728471134
    BBy: Final[
        int
    ] = 16313972569917201570489077828713531620741538540099917729994937953803219324220#5472060717959818805561601436314318772137091100104008585924551046643952123905


JubJubGLVSpecs = GLVSpecs(
    is_enabled=True,
    lambda_param=BabyJubJubParams.GLV_LAMBDA,
    constant_b=BabyJubJubParams.GLV_B,
    constant_c=BabyJubJubParams.GLV_C
)


class BabyJubJubCurve(TECurve):
    """
    Bandersnatch curve implementation.

    A high-performance curve designed for zero-knowledge proofs and VRFs,
    offering both efficiency and security.
    """
    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for BabyJubJub VRF."""
        return BabyJubJubParams.CHALLENGE_LENGTH

    def __init__(self) -> None:
        """Initialize Bandersnatch curve with its parameters."""
        super().__init__(
            PRIME_FIELD=BabyJubJubParams.PRIME_FIELD,
            ORDER=BabyJubJubParams.ORDER,
            GENERATOR_X=BabyJubJubParams.GENERATOR_X,
            GENERATOR_Y=BabyJubJubParams.GENERATOR_Y,
            COFACTOR=BabyJubJubParams.COFACTOR,
            glv=DisabledGLV,
            Z=BabyJubJubParams.Z,
            EdwardsA=BabyJubJubParams.EDWARDS_A,
            EdwardsD=BabyJubJubParams.EDWARDS_D,
            SUITE_STRING=BabyJubJubParams.SUITE_STRING,
            DST=BabyJubJubParams.DST,
            E2C=E2C_Variant.TAI,
            BBx=BabyJubJubParams.BBx,
            BBy=BabyJubJubParams.BBy
        )


# Singleton instance
BabyJubJub_TE_Curve: Final[BabyJubJubParams] = BabyJubJubCurve()


@dataclass(frozen=True)
class BabyJubJubPoint(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """
    curve: Final[BabyJubJubCurve] = BabyJubJub_TE_Curve

    def __init__(self, x: int, y: int) -> None:
        """
        Initialize a point on the Bandersnatch curve.

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
            BandersnatchPoint: Generator point
        """
        return cls(
            BabyJubJubParams.GENERATOR_X % BabyJubJubParams.PRIME_FIELD,
            BabyJubJubParams.GENERATOR_Y % BabyJubJubParams.PRIME_FIELD
        )