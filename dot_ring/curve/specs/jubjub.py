from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve


@dataclass(frozen=True)
class JubJubParams:
    """
    JubJub curve parameters.

    Specification of the JubJub curve in Twisted Edwards form.
    """

    SUITE_STRING = b"JubJub_SHA-512_TAI"  # "Jubjub_XMD:SHA-512_ELL2_RO_"
    DST = b""
    # f_len=q_len=32
    # Curve parameters
    PRIME_FIELD: Final[
        int
    ] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    ORDER: Final[
        int
    ] = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
    COFACTOR: Final[int] = 8

    # Generator point
    GENERATOR_X: Final[
        int
    ] = 8076246640662884909881801758704306714034609987455869804520522091855516602923
    GENERATOR_Y: Final[
        int
    ] = 13262374693698910701929044844600465831413122818447359594527400194675274060458

    # Edwards curve parameters
    EDWARDS_A: Final[int] = -1
    EDWARDS_D: Final[
        int
    ] = 19257038036680949359750312669786877991949435402254120286184196891950884077233

    # Z
    Z: Final[int] = 5
    M: Final[int] = 1
    K: Final[int] = 128
    L: Final[int] = 48  # can define func as well
    S_in_bytes: Final[
        int
    ] = 48  # can be taken as hsh_fn.block_size #not sure as its supposed to be 128 for sha512
    H_A = hashlib.sha512
    ENDIAN = "little"
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
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 32


JubJub_TE_Curve: Final[TECurve] = TECurve(
    PRIME_FIELD=JubJubParams.PRIME_FIELD,
    ORDER=JubJubParams.ORDER,
    GENERATOR_X=JubJubParams.GENERATOR_X,
    GENERATOR_Y=JubJubParams.GENERATOR_Y,
    COFACTOR=JubJubParams.COFACTOR,
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
    UNCOMPRESSED=JubJubParams.UNCOMPRESSED,
    ENDIAN=JubJubParams.ENDIAN,
    POINT_LEN=JubJubParams.POINT_LEN,
    CHALLENGE_LENGTH=JubJubParams.CHALLENGE_LENGTH,
)


class JubJubPoint(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """

    curve: TECurve = JubJub_TE_Curve


JubJub = CurveVariant(name="JubJub", curve=JubJub_TE_Curve, point=JubJubPoint)
