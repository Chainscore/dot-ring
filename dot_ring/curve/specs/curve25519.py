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

CURVE25519_PARAMS = MontgomeryCurveParams(
    field_modulus=2**255 - 19,
    subgroup_order=2**252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED,
    cofactor=8,
    suite_id=b"curve25519_XMD:SHA-512_ELL2_RO_",
    hash_fn=hashlib.sha512,
    generator=(
        9,
        14781619447589544791020593568409986887264606134616475288964881837755586237401,
    ),
    a=486662,
    b=1,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_",
        z=2,
        field_extension_degree=1,
        security_level=128,
        field_length=48,
        expand_len=128,
    ),
    encoding=EncodingParams(endian="little", point_len=32, challenge_len=16, uncompressed=True),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            9,
            14781619447589544791020593568409986887264606134616475288964881837755586237401,
        ),
    ),
)


Curve25519_NU_Curve = MGCurve(params=CURVE25519_PARAMS, e2c_variant=E2C_Variant.ELL2_NU)
Curve25519_RO_Curve = MGCurve(params=CURVE25519_PARAMS, e2c_variant=E2C_Variant.ELL2)


class Curve25519NUPoint(MGAffinePoint):
    curve = Curve25519_NU_Curve


class Curve25519ROPoint(MGAffinePoint):
    curve = Curve25519_RO_Curve


Curve25519_NU = CurveVariant(
    name="Curve25519_NU",
    curve=Curve25519_NU_Curve,
    point_type=Curve25519NUPoint,
)

Curve25519_RO = CurveVariant(
    name="Curve25519_RO",
    curve=Curve25519_RO_Curve,
    point_type=Curve25519ROPoint,
)
