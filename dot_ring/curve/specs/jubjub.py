from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.e2c import E2C_Variant

from ..glv import DisabledGLV, GLVSpecs
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class JubJubParams:
    """
    JubJub curve parameters.

    Specification of the JubJub curve in Twisted Edwards form.
    """
    SUITE_STRING = b"JubJub_SHA-512_TAI"
    DST = b""

    # Curve parameters
    PRIME_FIELD: Final[int] = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    ORDER: Final[int] = 0xe7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
    COFACTOR: Final[int] = 8

    # Generator point
    GENERATOR_X: Final[int] = 0x11dafe5d23e1218086a365b99fbf3d3be72f6afd7d1f72623e6b071492d1122b
    GENERATOR_Y: Final[int] = 0x1d523cf1ddab1a1793132e78c866c0c33e26ba5cc220fed7cc3f870e59d292aa

    # Edwards curve parameters
    EDWARDS_A: Final[int] = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    EDWARDS_D: Final[int] = 0x2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1

    # GLV parameters
    GLV_LAMBDA: Final[int] = 0x13b4f3dc4a39a493edf849562b38c72bcfc49db970a5056ed13d21408783df05
    GLV_B: Final[int] = 0x52c9f28b828426a561f00d3a63511a882ea712770d9af4d6ee0f014d172510b4
    GLV_C: Final[int] = 0x6cc624cf865457c3a97c6efd6c17d1078456abcfff36f4e9515c806cdf650b3d

    # Z
    Z: Final[int] = 5
    M: Final[int] = 1
    K: Final[int] = 128
    L: Final[int] = 48  # can define func as well
    S_in_bytes: Final[int] = 48  # can be taken as hsh_fn.block_size #not sure as its supposed to be 128 for sha512
    H_A: Final[str] = "SHA-512"
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    CHALLENGE_LENGTH: Final[int] = 32

    # Blinding Base For Pedersen
    BBx: Final[
        int
    ] = 42257337814662035284373945156525735092765968053982822992704750832078779438788
    BBy: Final[
        int
    ] = 47476395315228831116309413527962830333178159651930104661512857647213254194102

class JubJubCurve(TECurve):
    """
    Bandersnatch curve implementation.

    A high-performance curve designed for zero-knowledge proofs and VRFs,
    offering both efficiency and security.
    """
    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for JubJub VRF."""
        return 32  # 256-bit security level

    def __init__(self) -> None:
        """Initialize Bandersnatch curve with its parameters."""
        super().__init__(
            PRIME_FIELD=JubJubParams.PRIME_FIELD,
            ORDER=JubJubParams.ORDER,
            GENERATOR_X=JubJubParams.GENERATOR_X,
            GENERATOR_Y=JubJubParams.GENERATOR_Y,
            COFACTOR=JubJubParams.COFACTOR,
            glv=DisabledGLV,
            Z=JubJubParams.Z,
            EdwardsA=JubJubParams.EDWARDS_A,
            EdwardsD=JubJubParams.EDWARDS_D,
            SUITE_STRING=JubJubParams.SUITE_STRING,
            DST=JubJubParams.DST,
            E2C=E2C_Variant.TAI,
            BBx=JubJubParams.BBx,
            BBy=JubJubParams.BBy,
            M=JubJubParams.M,
            K=JubJubParams.K,
            L=JubJubParams.L,
            S_in_bytes=JubJubParams.S_in_bytes,
            H_A=JubJubParams.H_A,
            Requires_Isogeny=JubJubParams.Requires_Isogeny,
            Isogeny_Coeffs=JubJubParams.Isogeny_Coeffs,
        )


# Singleton instance
JubJub_TE_Curve: Final[JubJubCurve] = JubJubCurve()


@dataclass(frozen=True)
class JubJubPoint(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """
    curve: Final[JubJubCurve] = JubJub_TE_Curve

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
            JubJubParams.GENERATOR_X,
            JubJubParams.GENERATOR_Y
        )