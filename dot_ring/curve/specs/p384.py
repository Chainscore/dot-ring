from __future__ import annotations

import hashlib

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..short_weierstrass.sw_curve import SWCurve
from .parameters import (
    AuxiliaryPointParams,
    EncodingParams,
    HashToCurveParams,
    ShortWeierstrassCurveParams,
)

P384_PARAMS = ShortWeierstrassCurveParams[int](
    field_modulus=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    subgroup_order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    cofactor=1,
    suite_id=b"P384_XMD:SHA-384_SSWU_RO_",
    hash_fn=hashlib.sha384,
    generator=(
        0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    ),
    a=-3,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_",
        z=-12,
        field_extension_degree=1,
        security_level=192,
        field_length=72,
        expand_len=128,
    ),
    encoding=EncodingParams(endian="little", point_len=49, challenge_len=24),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
            0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        ),
    ),
)


P384_RO = CurveVariant(
    name="P384_RO",
    curve=SWCurve(params=P384_PARAMS, e2c_variant=E2C_Variant.SSWU),
    point_type=SWAffinePoint,
)

P384_NU = CurveVariant(
    name="P384_NU",
    curve=SWCurve(params=P384_PARAMS, e2c_variant=E2C_Variant.SSWU_NU),
    point_type=SWAffinePoint,
)
