from __future__ import annotations

import hashlib

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..montgomery.mg_affine_point import MGAffinePoint
from ..montgomery.mg_curve import MGCurve
from .parameters import (
    AuxiliaryPointParams,
    EncodingParams,
    HashToCurveParams,
    MontgomeryCurveParams,
)

CURVE448_GENERATOR = (
    5,
    355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362,
)

CURVE448_PARAMS = MontgomeryCurveParams(
    field_modulus=2**448 - 2**224 - 1,
    subgroup_order=2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D,
    cofactor=4,
    suite_id=b"curve448_XOF:SHAKE256_ELL2_RO_",
    hash_fn=hashlib.shake_256,
    generator=CURVE448_GENERATOR,
    a=156326,
    b=1,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_RO_",
        z=-1,
        field_extension_degree=1,
        security_level=224,
        field_length=84,
        expand_len=None,
    ),
    encoding=EncodingParams(
        endian="little",
        point_len=((2**448 - 2**224 - 1).bit_length() + 7) // 8,
        challenge_len=28,
        uncompressed=True,
    ),
    auxiliary_points=AuxiliaryPointParams(blinding_base=CURVE448_GENERATOR),
)


Curve448_NU_Curve = MGCurve(params=CURVE448_PARAMS, e2c_variant=E2C_Variant.ELL2_NU)
Curve448_RO_Curve = MGCurve(params=CURVE448_PARAMS, e2c_variant=E2C_Variant.ELL2)


class Curve448NUPoint(MGAffinePoint):
    curve = Curve448_NU_Curve


class Curve448ROPoint(MGAffinePoint):
    curve = Curve448_RO_Curve


Curve448_NU = CurveVariant(
    name="Curve448_NU",
    curve=Curve448_NU_Curve,
    point_type=Curve448NUPoint,
)

Curve448_RO = CurveVariant(
    name="Curve448_RO",
    curve=Curve448_RO_Curve,
    point_type=Curve448ROPoint,
)
