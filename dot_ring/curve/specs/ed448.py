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

ED448_GENERATOR = (
    117812161263436946737282484343310064665180535357016373416879082147939404277809514858788439644911793978499419995990477371552926308078495,
    19,
)

ED448_PARAMS = TwistedEdwardsCurveParams(
    field_modulus=2**448 - 2**224 - 1,
    subgroup_order=2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D,
    cofactor=4,
    suite_id=b"edwards448_XOF:SHAKE256_ELL2_RO_",
    hash_fn=hashlib.shake_256,
    generator=ED448_GENERATOR,
    a=1,
    d=-39081,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_",
        z=-1,
        field_extension_degree=1,
        security_level=224,
        field_length=84,
        expand_len=None,
        elligator2_map=Elligator2MontgomeryMap(a=156326, b=1),
    ),
    encoding=EncodingParams(
        endian="little",
        point_len=((2**448 - 2**224 - 1).bit_length() + 7) // 8,
        challenge_len=64,
        uncompressed=True,
    ),
    auxiliary_points=AuxiliaryPointParams(blinding_base=ED448_GENERATOR),
)


class Ed448Point(TEAffinePoint[TECurve]):
    """Point on Ed448."""

    @classmethod
    def blinding_base(cls, curve: TECurve) -> Self:
        x, y = curve.params.auxiliary_points.blinding_base or curve.params.generator
        return cls(x, y, curve)

    @classmethod
    def map_to_curve(cls, u: int, curve: TECurve) -> Self:
        s, t = curve.map_to_curve_ell2(u)
        return cls.mont_to_ed448(s, t, curve)

    @classmethod
    def mont_to_ed448(cls, u: int, v: int, curve: TECurve) -> Self:
        p = curve.params.field_modulus
        x_num = (4 * v * ((u * u - 1) % p)) % p
        x_den = (pow(u, 4, p) - 2 * pow(u, 2, p) + 4 * pow(v, 2, p) + 1) % p
        x = (x_num * curve.inv(x_den)) % p

        y_num = -(pow(u, 5, p) - 2 * pow(u, 3, p) - 4 * u * pow(v, 2, p) + u) % p
        y_den = (pow(u, 5, p) - 2 * pow(u, 2, p) * pow(v, 2, p) - 2 * pow(u, 3, p) - 2 * pow(v, 2, p) + u) % p
        y = (y_num * curve.inv(y_den)) % p
        return cls(x, y, curve)


Ed448_NU = CurveVariant(
    name="Ed448_NU",
    curve=TECurve(params=ED448_PARAMS, e2c_variant=E2C_Variant.ELL2_NU),
    point_type=Ed448Point,
)

Ed448_RO = CurveVariant(
    name="Ed448_RO",
    curve=TECurve(params=ED448_PARAMS, e2c_variant=E2C_Variant.ELL2),
    point_type=Ed448Point,
)
