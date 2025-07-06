from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curves.e2c import E2C_Variant
from dot_ring.curves.glv import GLVSpecs
from dot_ring.curves.twisted_edwards.te_curve import TECurve
from dot_ring.curves.twisted_edwards.te_affine_point import TEAffinePoint

__all__ = [
    "BandersnatchCurve",
    "BandersnatchPoint",
]


@dataclass(frozen=True)
class _Params:
    SUITE_STRING = b"Bandersnatch_SHA-512_ELL2"
    DST = b"ECVRF_Bandersnatch_XMD:SHA-512_ELL2_RO_Bandersnatch_SHA-512_ELL2"

    PRIME_FIELD: Final[int] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    ORDER: Final[int] = 0x1CFB69D4CA675F520CCE760202687600FF8F87007419047174FD06B52876E7E1
    COFACTOR: Final[int] = 4

    GENERATOR_X: Final[int] = 18886178867200960497001835917649091219057080094937609519140440539760939937304
    GENERATOR_Y: Final[int] = 19188667384257783945677642223292697773471335439753913231509108946878080696678

    EDWARDS_A: Final[int] = -5
    EDWARDS_D: Final[int] = 0x6389C12633C267CBC66E3BF86BE3B6D8CB66677177E54F92B369F2F5188D58E7

    GLV_LAMBDA: Final[int] = 0x13B4F3DC4A39A493EDF849562B38C72BCFC49DB970A5056ED13D21408783DF05
    GLV_B: Final[int] = 0x52C9F28B828426A561F00D3A63511A882EA712770D9AF4D6EE0F014D172510B4
    GLV_C: Final[int] = 0x6CC624CF865457C3A97C6EFD6C17D1078456ABCFFF36F4E9515C806CDF650B3D

    Z: Final[int] = 5

    BBx: Final[int] = 6150229251051246713677296363717454238956877613358614224171740096471278798312
    BBy: Final[int] = 28442734166467795856797249030329035618871580593056783094884474814923353898473


BandersnatchGLV = GLVSpecs(
    is_enabled=True,
    lambda_param=_Params.GLV_LAMBDA,
    constant_b=_Params.GLV_B,
    constant_c=_Params.GLV_C,
)


class BandersnatchCurve(TECurve):
    def __init__(self) -> None:  # noqa: D401  – simple wrapper
        super().__init__(
            PRIME_FIELD=_Params.PRIME_FIELD,
            ORDER=_Params.ORDER,
            GENERATOR_X=_Params.GENERATOR_X,
            GENERATOR_Y=_Params.GENERATOR_Y,
            COFACTOR=_Params.COFACTOR,
            glv=BandersnatchGLV,
            Z=_Params.Z,
            EdwardsA=_Params.EDWARDS_A,
            EdwardsD=_Params.EDWARDS_D,
            SUITE_STRING=_Params.SUITE_STRING,
            DST=_Params.DST,
            E2C=E2C_Variant.ELL2,
            BBx=_Params.BBx,
            BBy=_Params.BBy,
        )


_BS_CURVE = BandersnatchCurve()


@dataclass(frozen=True)
class BandersnatchPoint(TEAffinePoint):
    curve: Final[BandersnatchCurve] = _BS_CURVE

    def __init__(self, x: int, y: int) -> None:  # noqa: D401
        super().__init__(x, y, self.curve)

    @classmethod
    def generator_point(cls) -> Self:
        return cls(_Params.GENERATOR_X, _Params.GENERATOR_Y)