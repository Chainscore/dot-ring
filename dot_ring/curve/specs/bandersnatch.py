from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.e2c import E2C_Variant

from ..glv import DisabledGLV, GLVSpecs
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class BandersnatchParams:
    """
    Bandersnatch curve parameters.

    The Bandersnatch curve is a Twisted Edwards curve designed for efficient
    implementation of zero-knowledge proofs and VRFs.
    """
    SUITE_STRING = b"Bandersnatch_SHA-512_ELL2"
    DST = b"ECVRF_Bandersnatch_XMD:SHA-512_ELL2_RO_Bandersnatch_SHA-512_ELL2"

    # Curve parameters
    PRIME_FIELD: Final[int] = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    ORDER: Final[int] = 0x1cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7e1
    COFACTOR: Final[int] = 4

    # Generator point
    GENERATOR_X: Final[int] = 18886178867200960497001835917649091219057080094937609519140440539760939937304
    GENERATOR_Y: Final[int] = 19188667384257783945677642223292697773471335439753913231509108946878080696678

    # Edwards curve parameters
    EDWARDS_A: Final[int] = -5
    EDWARDS_D: Final[int] = 0x6389c12633c267cbc66e3bf86be3b6d8cb66677177e54f92b369f2f5188d58e7

    # GLV parameters
    GLV_LAMBDA: Final[int] = 0x13b4f3dc4a39a493edf849562b38c72bcfc49db970a5056ed13d21408783df05
    GLV_B: Final[int] = 0x52c9f28b828426a561f00d3a63511a882ea712770d9af4d6ee0f014d172510b4
    GLV_C: Final[int] = 0x6cc624cf865457c3a97c6efd6c17d1078456abcfff36f4e9515c806cdf650b3d

    # Challenge length in bytes for VRF (aligned with 256-bit security level)
    CHALLENGE_LENGTH: Final[int] = 32  # 256 bits

    # Z
    Z: Final[int] = 5
    M: Final[int] = 1
    K: Final[int] = 128
    L: Final[int] = 48  # can define func as well
    S_in_bytes: Final[int] = 48 #can be taken as hsh_fn.block_size #not sure as its supposed to be 128 for sha512
    H_A: Final[str] = "SHA-512"
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs=None


    # Blinding Base For Pedersen (old)
    # BBx: Final[
    #     int
    # ] = 14576224270591906826192118712803723445031237947873156025406837473427562701854
    # BBy: Final[
    #     int
    # ] = 38436873314098705092845609371301773715650206984323659492499960072785679638442

    # new
    BBx: Final[
        int
    ] = 6150229251051246713677296363717454238956877613358614224171740096471278798312
    BBy: Final[
        int
    ] = 28442734166467795856797249030329035618871580593056783094884474814923353898473


"""GLV endomorphism parameters for Bandersnatch curve."""
BandersnatchGLVSpecs = GLVSpecs(
    is_enabled=True,
    lambda_param=BandersnatchParams.GLV_LAMBDA,
    constant_b=BandersnatchParams.GLV_B,
    constant_c=BandersnatchParams.GLV_C,
)


class BandersnatchCurve(TECurve):
    """
    Bandersnatch curve implementation.

    A high-performance curve designed for zero-knowledge proofs and VRFs,
    offering both efficiency and security.
    """

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for Bandersnatch VRF."""
        return BandersnatchParams.CHALLENGE_LENGTH

    def __init__(self) -> None:
        """Initialize Bandersnatch curve with its parameters."""
        super().__init__(
            PRIME_FIELD=BandersnatchParams.PRIME_FIELD,
            ORDER=BandersnatchParams.ORDER,
            GENERATOR_X=BandersnatchParams.GENERATOR_X,
            GENERATOR_Y=BandersnatchParams.GENERATOR_Y,
            COFACTOR=BandersnatchParams.COFACTOR,
            glv=BandersnatchGLVSpecs,
            Z=BandersnatchParams.Z,
            EdwardsA=BandersnatchParams.EDWARDS_A,
            EdwardsD=BandersnatchParams.EDWARDS_D,
            SUITE_STRING=BandersnatchParams.SUITE_STRING,
            DST=BandersnatchParams.DST,
            E2C=E2C_Variant.ELL2,
            BBx=BandersnatchParams.BBx,
            BBy=BandersnatchParams.BBy,
            M=BandersnatchParams.M,
            K=BandersnatchParams.K,
            L=BandersnatchParams.L,
            S_in_bytes=BandersnatchParams.S_in_bytes,
            H_A=BandersnatchParams.H_A,
            Requires_Isogeny=BandersnatchParams.Requires_Isogeny,
            Isogeny_Coeffs=BandersnatchParams.Isogeny_Coeffs,


        )


# Singleton instance
Bandersnatch_TE_Curve: Final[BandersnatchCurve] = BandersnatchCurve()


@dataclass(frozen=True)
class BandersnatchPoint(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """
    curve: Final[BandersnatchCurve] = Bandersnatch_TE_Curve

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
            BandersnatchParams.GENERATOR_X,
            BandersnatchParams.GENERATOR_Y
        )
