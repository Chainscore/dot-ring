from __future__ import annotations

import hashlib
from typing import Self

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve
from .parameters import (
    AuxiliaryPointParams,
    Elligator2MontgomeryMap,
    EncodingParams,
    HashToCurveParams,
    TwistedEdwardsCurveParams,
)

ED25519_PARAMS = TwistedEdwardsCurveParams(
    field_modulus=0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED,
    subgroup_order=2**252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED,
    cofactor=8,
    suite_id=b"Ed25519-SHA512-TAI-v1",
    hash_fn=hashlib.sha512,
    generator=(
        0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A,
        0x6666666666666666666666666666666666666666666666666666666666666658,
    ),
    a=-1,
    d=0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_",
        z=2,
        field_extension_degree=1,
        security_level=128,
        field_length=48,
        expand_len=128,
        elligator2_map=Elligator2MontgomeryMap(a=486662, b=1),
    ),
    encoding=EncodingParams(endian="little", point_len=32, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            45003173884697328536089278691112838614164406922820087464913813433380838325453,
            31256014272390301975555524011230972931324093235775711248505761870355310252869,
        ),
    ),
)


class Ed25519Point(TEAffinePoint[TECurve]):
    """Point on Ed25519."""

    @classmethod
    def map_to_curve(cls, u: int) -> Self:
        s, t = cls.curve.map_to_curve_ell2(u)
        return cls.mont_to_ed25519(s, t)

    @classmethod
    def mont_to_ed25519(cls, u: int, v: int) -> Self:
        p = cls.curve.params.field_modulus
        sqrt_neg_a_minus_2 = cls.curve.mod_sqrt(-486664 % p)
        y = ((u - 1) * pow(u + 1, -1, p)) % p
        x = (sqrt_neg_a_minus_2 * u * pow(v, -1, p)) % p
        return cls(x, y)


Ed25519_RO_Curve = TECurve(params=ED25519_PARAMS, e2c_variant=E2C_Variant.ELL2)
Ed25519_NU_Curve = TECurve(params=ED25519_PARAMS, e2c_variant=E2C_Variant.ELL2_NU)
Ed25519_TAI_Curve = TECurve(params=ED25519_PARAMS, e2c_variant=E2C_Variant.TAI)


class Ed25519ROPoint(Ed25519Point):
    curve = Ed25519_RO_Curve


class Ed25519NUPoint(Ed25519Point):
    curve = Ed25519_NU_Curve


class Ed25519TAIPoint(Ed25519Point):
    curve = Ed25519_TAI_Curve


Ed25519_RO = CurveVariant(
    name="Ed25519_RO",
    curve=Ed25519_RO_Curve,
    point_type=Ed25519ROPoint,
)

Ed25519_NU = CurveVariant(
    name="Ed25519_NU",
    curve=Ed25519_NU_Curve,
    point_type=Ed25519NUPoint,
)

Ed25519_TAI = CurveVariant(
    name="Ed25519_TAI",
    curve=Ed25519_TAI_Curve,
    point_type=Ed25519TAIPoint,
)
