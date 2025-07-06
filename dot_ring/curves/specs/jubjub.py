from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curves.e2c import E2C_Variant
from dot_ring.curves.glv import DisabledGLV
from dot_ring.curves.twisted_edwards.te_curve import TECurve
from dot_ring.curves.twisted_edwards.te_affine_point import TEAffinePoint

__all__ = ["JubJubCurve", "JubJubPoint"]


@dataclass(frozen=True)
class _Params:
    SUITE_STRING = b""
    DST = b""

    PRIME_FIELD: Final[int] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    ORDER: Final[int] = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
    COFACTOR: Final[int] = 8

    GENERATOR_X: Final[int] = 0x11DAFE5D23E1218086A365B99FBF3D3BE72F6AFD7D1F72623E6B071492D1122B
    GENERATOR_Y: Final[int] = 0x1D523CF1DDAB1A1793132E78C866C0C33E26BA5CC220FED7CC3F870E59D292AA

    EDWARDS_A: Final[int] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000
    EDWARDS_D: Final[int] = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1

    Z: Final[int] = 5

    BBx: Final[int] = GENERATOR_X
    BBy: Final[int] = GENERATOR_Y


class JubJubCurve(TECurve):
    def __init__(self) -> None:
        super().__init__(
            PRIME_FIELD=_Params.PRIME_FIELD,
            ORDER=_Params.ORDER,
            GENERATOR_X=_Params.GENERATOR_X,
            GENERATOR_Y=_Params.GENERATOR_Y,
            COFACTOR=_Params.COFACTOR,
            glv=DisabledGLV,
            Z=_Params.Z,
            EdwardsA=_Params.EDWARDS_A,
            EdwardsD=_Params.EDWARDS_D,
            SUITE_STRING=_Params.SUITE_STRING,
            DST=_Params.DST,
            E2C=E2C_Variant.TAI,
            BBx=_Params.BBx,
            BBy=_Params.BBy,
        )


_JJ_CURVE = JubJubCurve()


@dataclass(frozen=True)
class JubJubPoint(TEAffinePoint):
    def __init__(self, x: int, y: int) -> None:
        super().__init__(x, y, _JJ_CURVE)

    @classmethod
    def generator_point(cls) -> Self:
        return cls(_Params.GENERATOR_X, _Params.GENERATOR_Y)