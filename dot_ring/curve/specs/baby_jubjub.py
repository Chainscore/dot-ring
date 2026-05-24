from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve


@dataclass(frozen=True)
class BabyJubJubParams:
    """
    Baby JubJub curve parameters.

    Specification of the Baby JubJub curve in Twisted Edwards form.
    """

    SUITE_STRING = b"BabyJubJub-SHA512-TAI-v1"
    SUITE_ID = b"BabyJubJub-SHA512-TAI-v1"
    DST = b""

    # Curve parameters
    PRIME_FIELD: Final[int] = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    ORDER: Final[int] = 2736030358979909402780800718157159386076813972158567259200215660948447373041
    COFACTOR: Final[int] = 8

    # Generator point
    GENERATOR_X: Final[int] = 19698561148652590122159747500897617769866003486955115824547446575314762165298
    GENERATOR_Y: Final[int] = 19298250018296453272277890825869354524455968081175474282777126169995084727839
    # Edwards curve parameters
    EDWARDS_A: Final[int] = 1
    EDWARDS_D: Final[int] = 9706598848417545097372247223557719406784115219466060233080913168975159366771

    # Z
    Z: Final[int] = 5
    M: Final[int] = 1
    K: Final[int] = 128
    L: Final[int] = 32  # can define func as well
    S_in_bytes: Final[int] = 128  # can be taken as hsh_fn.block_size #not sure as its supposed to be 128 for sha512
    H_A = hashlib.sha512
    ENDIAN = "little"
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    # Challenge length in bytes for VRF (aligned with 128-bit security level)
    CHALLENGE_LENGTH: Final[int] = 16

    # Blinding Base For Pedersen
    BBx: Final[int] = 15549380791300914366206471199568039679131690710803662429646809536753521087193
    BBy: Final[int] = 15218614024055502695611547593111691164731001864276292210438920202280814188379
    ACCUMULATOR_BASE_X: Final[int] = 6402374321243162085389111671722843560682527921646684137786768606010797479351
    ACCUMULATOR_BASE_Y: Final[int] = 9735581299071570006712034490635195155689931359428941496570758703259384062170
    PADDING_X: Final[int] = 11167490195257431015694161063225325511805242064780376648595733691987293447528
    PADDING_Y: Final[int] = 18403369502642103292159933062507105566469227524991433735553439433605496057425
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 32
    TRANSCRIPT_HASH = "sha512"
    HASH_TO_CURVE = "tai"


BabyJubJub_TE_Curve: Final[TECurve] = TECurve(
    PRIME_FIELD=BabyJubJubParams.PRIME_FIELD,
    ORDER=BabyJubJubParams.ORDER,
    GENERATOR_X=BabyJubJubParams.GENERATOR_X,
    GENERATOR_Y=BabyJubJubParams.GENERATOR_Y,
    COFACTOR=BabyJubJubParams.COFACTOR,
    Z=BabyJubJubParams.Z,
    EdwardsA=BabyJubJubParams.EDWARDS_A,
    EdwardsD=BabyJubJubParams.EDWARDS_D,
    SUITE_STRING=BabyJubJubParams.SUITE_STRING,
    DST=BabyJubJubParams.DST,
    E2C=E2C_Variant.TAI,
    BBx=BabyJubJubParams.BBx,
    BBy=BabyJubJubParams.BBy,
    M=BabyJubJubParams.M,
    K=BabyJubJubParams.K,
    L=BabyJubJubParams.L,
    S_in_bytes=BabyJubJubParams.S_in_bytes,
    H_A=BabyJubJubParams.H_A,
    Requires_Isogeny=BabyJubJubParams.Requires_Isogeny,
    Isogeny_Coeffs=BabyJubJubParams.Isogeny_Coeffs,
    UNCOMPRESSED=BabyJubJubParams.UNCOMPRESSED,
    ENDIAN=BabyJubJubParams.ENDIAN,
    POINT_LEN=BabyJubJubParams.POINT_LEN,
    CHALLENGE_LENGTH=BabyJubJubParams.CHALLENGE_LENGTH,
    SUITE_ID=BabyJubJubParams.SUITE_ID,
    TRANSCRIPT_HASH=BabyJubJubParams.TRANSCRIPT_HASH,
    HASH_TO_CURVE=BabyJubJubParams.HASH_TO_CURVE,
    ACCUMULATOR_BASE_X=BabyJubJubParams.ACCUMULATOR_BASE_X,
    ACCUMULATOR_BASE_Y=BabyJubJubParams.ACCUMULATOR_BASE_Y,
    PADDING_X=BabyJubJubParams.PADDING_X,
    PADDING_Y=BabyJubJubParams.PADDING_Y,
)


class BabyJubJubPoint(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """

    curve: TECurve = BabyJubJub_TE_Curve


BabyJubJub = CurveVariant(name="BabyJubJub", curve=BabyJubJub_TE_Curve, point=BabyJubJubPoint)
