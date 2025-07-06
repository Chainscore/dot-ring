from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curves.e2c import E2C_Variant
from dot_ring.curves.glv import DisabledGLV
from dot_ring.curves.twisted_edwards.te_curve import TECurve
from dot_ring.curves.twisted_edwards.te_affine_point import TEAffinePoint

__all__ = ["Ed25519Curve", "Ed25519Point"]


@dataclass(frozen=True)
class _Params:
    SUITE_STRING = b"\x03"
    DST = b""

    PRIME_FIELD: Final[int] = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
    ORDER: Final[int] = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    COFACTOR: Final[int] = 8

    GENERATOR_X: Final[int] = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    GENERATOR_Y: Final[int] = 0x6666666666666666666666666666666666666666666666666666666666666658

    EDWARDS_A: Final[int] = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC
    EDWARDS_D: Final[int] = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3

    Z: Final[int] = 5

    BBx: Final[int] = GENERATOR_X
    BBy: Final[int] = GENERATOR_Y


class Ed25519Curve(TECurve):
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


_ED_CURVE = Ed25519Curve()


@dataclass(frozen=True)
class Ed25519Point(TEAffinePoint):
    def __init__(self, x: int, y: int) -> None:
        super().__init__(x, y, _ED_CURVE)

    @classmethod
    def generator_point(cls) -> Self:
        return cls(_Params.GENERATOR_X, _Params.GENERATOR_Y)