from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, ClassVar, Final, Self, cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.native_field.scalar import Scalar

from ..glv import GLV
from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve


@dataclass(frozen=True)
class BandersnatchParams:
    """
    Bandersnatch curve parameters.

    The Bandersnatch curve is a Twisted Edwards curve designed for efficient
    implementation of zero-knowledge proofs and VRFs.
    """

    SUITE_STRING = b"Bandersnatch-SHA512-ELL2-v1"
    SUITE_ID = b"Bandersnatch-SHA512-ELL2-v1"
    DST = SUITE_ID + b"\x60"

    # Curve parameters
    PRIME_FIELD: Final[int] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    ORDER: Final[int] = 0x1CFB69D4CA675F520CCE760202687600FF8F87007419047174FD06B52876E7E1
    COFACTOR: Final[int] = 4

    # Generator point
    GENERATOR_X: ClassVar[Scalar] = Scalar(18886178867200960497001835917649091219057080094937609519140440539760939937304)
    GENERATOR_Y: ClassVar[Scalar] = Scalar(19188667384257783945677642223292697773471335439753913231509108946878080696678)

    # Edwards curve parameters
    EDWARDS_A: ClassVar[Scalar] = Scalar(-5)
    EDWARDS_D: ClassVar[Scalar] = Scalar(0x6389C12633C267CBC66E3BF86BE3B6D8CB66677177E54F92B369F2F5188D58E7)

    # GLV parameters
    GLV_LAMBDA: Final[int] = 0x13B4F3DC4A39A493EDF849562B38C72BCFC49DB970A5056ED13D21408783DF05
    GLV_B: Final[int] = 0x52C9F28B828426A561F00D3A63511A882EA712770D9AF4D6EE0F014D172510B4
    GLV_C: Final[int] = 0x6CC624CF865457C3A97C6EFD6C17D1078456ABCFFF36F4E9515C806CDF650B3D

    # Challenge length in bytes for VRF (aligned with 256-bit security level)
    CHALLENGE_LENGTH: Final[int] = 16

    # Z
    Z: Final[int] = 5
    M: Final[int] = 1
    K: Final[int] = 128
    L: Final[int] = 48  # can define func as well
    S_in_bytes: Final[int] = 48  # can be taken as hsh_fn.block_size #not sure as its supposed to be 128 for sha512
    H_A = hashlib.sha512
    ENDIAN = "little"
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    BBx: Final[int] = 23335687741101763108036518445642207119627658113885888016488710494487028845889
    BBy: Final[int] = 5552214580375038693022409684979828600325210968745774080859660443337357929963
    ACCUMULATOR_BASE_X: Final[int] = 14056632001415368875257708737821299882600475929746323097150942355715730684350
    ACCUMULATOR_BASE_Y: Final[int] = 10322661992765989500407719465917595459409463902187386706652408883505670839210
    PADDING_X: Final[int] = 26913883415342152801331916189968962157924271221160514298872262294143390094043
    PADDING_Y: Final[int] = 30874728313203001508631936119690348239461579770372782660098261717479009115354
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 32
    TRANSCRIPT_HASH = "sha512"
    HASH_TO_CURVE = "ell2-xmd"


"""GLV endomorphism parameters for Bandersnatch curve."""
BandersnatchGLV = GLV(
    lambda_param=BandersnatchParams.GLV_LAMBDA,
    constant_b=BandersnatchParams.GLV_B,
    constant_c=BandersnatchParams.GLV_C,
)

Bandersnatch_TE_Curve: Final[TECurve] = TECurve(
    PRIME_FIELD=BandersnatchParams.PRIME_FIELD,
    ORDER=BandersnatchParams.ORDER,
    GENERATOR_X=BandersnatchParams.GENERATOR_X,
    GENERATOR_Y=BandersnatchParams.GENERATOR_Y,
    COFACTOR=BandersnatchParams.COFACTOR,
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
    UNCOMPRESSED=BandersnatchParams.UNCOMPRESSED,
    ENDIAN=BandersnatchParams.ENDIAN,
    POINT_LEN=BandersnatchParams.POINT_LEN,
    CHALLENGE_LENGTH=BandersnatchParams.CHALLENGE_LENGTH,
    SUITE_ID=BandersnatchParams.SUITE_ID,
    TRANSCRIPT_HASH=BandersnatchParams.TRANSCRIPT_HASH,
    HASH_TO_CURVE=BandersnatchParams.HASH_TO_CURVE,
    ACCUMULATOR_BASE_X=BandersnatchParams.ACCUMULATOR_BASE_X,
    ACCUMULATOR_BASE_Y=BandersnatchParams.ACCUMULATOR_BASE_Y,
    PADDING_X=BandersnatchParams.PADDING_X,
    PADDING_Y=BandersnatchParams.PADDING_Y,
)


class BandersnatchPoint(TEAffinePoint[TECurve]):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """

    curve: TECurve = Bandersnatch_TE_Curve

    def __mul__(self, scalar: int) -> Self:
        """
        GLV scalar multiplication using endomorphism.

        Args:
            scalar: Integer to multiply by

        Returns:
            TEAffinePoint: Scalar multiplication result
        """
        n = self.curve.ORDER
        k1, k2 = BandersnatchGLV.decompose_scalar(scalar % n, n)
        phi = BandersnatchGLV.compute_endomorphism(self)

        return cast(Self, BandersnatchGLV.windowed_simultaneous_mult(k1, k2, self, phi, w=2))

    def __add__(self, other: Any) -> Self:
        return cast(Self, super().__add__(other))

    @classmethod
    def msm(cls, points: list[Self], scalars: list[int]) -> Self:
        """
        Optimized multi-scalar multiplication using GLV.
        """
        if not points:
            return cls.identity()

        # Normalize scalars to [0, ORDER) for GLV
        n = cls.curve.ORDER
        scalars = [s % n for s in scalars]

        if len(points) == 2:
            # Size-2 MSM using GLV to split into size-4 MSM
            # k1*P1 + k2*P2 = (k1_1 + k1_2*lambda)*P1 + (k2_1 + k2_2*lambda)*P2
            #               = k1_1*P1 + k1_2*phi(P1) + k2_1*P2 + k2_2*phi(P2)

            k1_1, k1_2 = BandersnatchGLV.decompose_scalar(scalars[0], n)
            k2_1, k2_2 = BandersnatchGLV.decompose_scalar(scalars[1], n)

            phi_P1 = BandersnatchGLV.compute_endomorphism(points[0])
            phi_P2 = BandersnatchGLV.compute_endomorphism(points[1])

            return cast(
                Self,
                BandersnatchGLV.multi_scalar_mult_4(k1_1, k1_2, k2_1, k2_2, points[0], phi_P1, points[1], phi_P2),
            )

        if len(points) == 4:
            return BandersnatchGLV.multi_scalar_mult_4(
                scalars[0],
                scalars[1],
                scalars[2],
                scalars[3],
                points[0],
                points[1],
                points[2],
                points[3],
            )

        if len(points) == 3:
            # Pad to 4 with identity and 0 scalar
            return BandersnatchGLV.multi_scalar_mult_4(
                scalars[0],
                scalars[1],
                scalars[2],
                0,
                points[0],
                points[1],
                points[2],
                cls.identity(),
            )

        return super().msm(points, scalars)


Bandersnatch = CurveVariant(
    name="Bandersnatch",
    curve=Bandersnatch_TE_Curve,
    point=BandersnatchPoint,
)


Bandersnatch_SHAKE128_TE_Curve: Final[TECurve] = TECurve(
    PRIME_FIELD=BandersnatchParams.PRIME_FIELD,
    ORDER=BandersnatchParams.ORDER,
    GENERATOR_X=BandersnatchParams.GENERATOR_X,
    GENERATOR_Y=BandersnatchParams.GENERATOR_Y,
    COFACTOR=BandersnatchParams.COFACTOR,
    Z=BandersnatchParams.Z,
    EdwardsA=BandersnatchParams.EDWARDS_A,
    EdwardsD=BandersnatchParams.EDWARDS_D,
    SUITE_STRING=b"Bandersnatch-SHAKE128-ELL2-v1",
    DST=b"Bandersnatch-SHAKE128-ELL2-v1\x60",
    E2C=E2C_Variant.ELL2,
    BBx=6153734995852631824944342602386415873379775188383988340041079006556670120775,
    BBy=27204351599954061630605768787803524395123895650061061132592995395630473050754,
    M=BandersnatchParams.M,
    K=BandersnatchParams.K,
    L=BandersnatchParams.L,
    S_in_bytes=None,
    H_A=hashlib.shake_128,
    Requires_Isogeny=BandersnatchParams.Requires_Isogeny,
    Isogeny_Coeffs=BandersnatchParams.Isogeny_Coeffs,
    UNCOMPRESSED=BandersnatchParams.UNCOMPRESSED,
    ENDIAN=BandersnatchParams.ENDIAN,
    POINT_LEN=BandersnatchParams.POINT_LEN,
    CHALLENGE_LENGTH=BandersnatchParams.CHALLENGE_LENGTH,
    SUITE_ID=b"Bandersnatch-SHAKE128-ELL2-v1",
    TRANSCRIPT_HASH="shake128",
    HASH_TO_CURVE="ell2-xof",
    ACCUMULATOR_BASE_X=27631238720955528589004064829276283990465032040945349648037876197995278250917,
    ACCUMULATOR_BASE_Y=37605358688136619817560700742505556266961225274493904038881144193539047100140,
    PADDING_X=1834402953989431481748983728202937234471322740714585873803966488035889514523,
    PADDING_Y=52100941849053769665273763352270294131006971127418863694682093199651869272752,
)


class BandersnatchSHAKE128Point(BandersnatchPoint):
    curve: TECurve = Bandersnatch_SHAKE128_TE_Curve


Bandersnatch_SHAKE128 = CurveVariant(
    name="Bandersnatch_SHAKE128",
    curve=Bandersnatch_SHAKE128_TE_Curve,
    point=BandersnatchSHAKE128Point,
)
