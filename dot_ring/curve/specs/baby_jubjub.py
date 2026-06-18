from __future__ import annotations

import hashlib

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve
from .parameters import (
    AuxiliaryPointParams,
    EncodingParams,
    HashToCurveParams,
    TwistedEdwardsCurveParams,
)

BABY_JUBJUB_PARAMS = TwistedEdwardsCurveParams(
    field_modulus=21888242871839275222246405745257275088548364400416034343698204186575808495617,
    subgroup_order=2736030358979909402780800718157159386076813972158567259200215660948447373041,
    cofactor=8,
    suite_id=b"BabyJubJub-SHA512-TAI-v1",
    hash_fn=hashlib.sha512,
    generator=(
        19698561148652590122159747500897617769866003486955115824547446575314762165298,
        19298250018296453272277890825869354524455968081175474282777126169995084727839,
    ),
    a=1,
    d=9706598848417545097372247223557719406784115219466060233080913168975159366771,
    hash_to_curve=HashToCurveParams(
        dst=b"",
        z=5,
        field_extension_degree=1,
        security_level=128,
        field_length=32,
        expand_len=128,
    ),
    encoding=EncodingParams(endian="little", point_len=32, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            15549380791300914366206471199568039679131690710803662429646809536753521087193,
            15218614024055502695611547593111691164731001864276292210438920202280814188379,
        ),
        accumulator_base=(
            6402374321243162085389111671722843560682527921646684137786768606010797479351,
            9735581299071570006712034490635195155689931359428941496570758703259384062170,
        ),
        padding_point=(
            11167490195257431015694161063225325511805242064780376648595733691987293447528,
            18403369502642103292159933062507105566469227524991433735553439433605496057425,
        ),
    ),
)


BabyJubJub = CurveVariant(
    name="BabyJubJub",
    curve=TECurve(params=BABY_JUBJUB_PARAMS, e2c_variant=E2C_Variant.TAI),
    point_type=TEAffinePoint,
)
