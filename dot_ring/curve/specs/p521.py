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

P521_PARAMS = ShortWeierstrassCurveParams[int](
    field_modulus=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    subgroup_order=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    cofactor=1,
    suite_id=b"P521_XMD:SHA-512_SSWU_RO_",
    hash_fn=hashlib.sha512,
    generator=(
        0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
        0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
    ),
    a=-3,
    b=0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_",
        z=-4,
        field_extension_degree=1,
        security_level=256,
        field_length=98,
        expand_len=128,
    ),
    encoding=EncodingParams(endian="little", point_len=67, challenge_len=32),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
            0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
        ),
    ),
)


P521_RO_Curve = SWCurve(params=P521_PARAMS, e2c_variant=E2C_Variant.SSWU)
P521_NU_Curve = SWCurve(params=P521_PARAMS, e2c_variant=E2C_Variant.SSWU_NU)


class P521ROPoint(SWAffinePoint):
    curve = P521_RO_Curve


class P521NUPoint(SWAffinePoint):
    curve = P521_NU_Curve


P521_RO = CurveVariant(
    name="P521_RO",
    curve=P521_RO_Curve,
    point_type=P521ROPoint,
)

P521_NU = CurveVariant(
    name="P521_NU",
    curve=P521_NU_Curve,
    point_type=P521NUPoint,
)
