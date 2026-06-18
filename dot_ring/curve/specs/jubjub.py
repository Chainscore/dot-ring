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

JUBJUB_PARAMS = TwistedEdwardsCurveParams(
    field_modulus=0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    subgroup_order=0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7,
    cofactor=8,
    suite_id=b"JubJub-SHA512-TAI-v1",
    hash_fn=hashlib.sha512,
    generator=(
        8076246640662884909881801758704306714034609987455869804520522091855516602923,
        13262374693698910701929044844600465831413122818447359594527400194675274060458,
    ),
    a=-1,
    d=19257038036680949359750312669786877991949435402254120286184196891950884077233,
    hash_to_curve=HashToCurveParams(
        dst=b"",
        z=5,
        field_extension_degree=1,
        security_level=128,
        field_length=48,
        expand_len=48,
    ),
    encoding=EncodingParams(endian="little", point_len=32, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            38206460563694846719174258613922853630278999941532690543235578292520143148532,
            34254498978062207918041301829525626783549813531091321004550549786528984401675,
        ),
        accumulator_base=(
            48142684311216766702182564801462043940571084233680216669499475549492432046964,
            34380560660182334518990118617091967209302636551264477863958902286043397647879,
        ),
        padding_point=(
            17348704025397475127937572481155408456556065464328870407269802701696798733683,
            24318278422173803457621119807961883607097742387673491974779969503617097905596,
        ),
    ),
)


JubJub = CurveVariant(
    name="JubJub",
    curve=TECurve(params=JUBJUB_PARAMS, e2c_variant=E2C_Variant.TAI),
    point_type=TEAffinePoint,
)
