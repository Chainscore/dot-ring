from __future__ import annotations

import hashlib
from typing import Self, cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..short_weierstrass.sw_curve import SWCurve
from .parameters import (
    AuxiliaryPointParams,
    EncodingParams,
    HashToCurveParams,
    RationalIsogeny,
    ShortWeierstrassCurveParams,
    ShortWeierstrassModel,
)

SECP256K1_ISOGENY = RationalIsogeny[int](
    map_curve=ShortWeierstrassModel(
        a=0x3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533,
        b=1771,
    ),
    x_numerator=(
        0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C,
        0x534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262,
        0x7D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581,
        0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7,
    ),
    x_denominator=(
        0x1,
        0xEDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14,
        0xD35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B,
    ),
    y_numerator=(
        0x2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84,
        0x29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931,
        0xC75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3,
        0x4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C,
    ),
    y_denominator=(
        0x1,
        0x6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F,
        0x7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B,
    ),
)


SECP256K1_PARAMS = ShortWeierstrassCurveParams[int](
    field_modulus=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    subgroup_order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    cofactor=1,
    suite_id=b"secp256k1_XMD:SHA-256_SSWU_RO_",
    hash_fn=hashlib.sha256,
    generator=(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    a=0,
    b=7,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
        z=-11,
        field_extension_degree=1,
        security_level=128,
        field_length=48,
        expand_len=64,
        isogeny=SECP256K1_ISOGENY,
    ),
    encoding=EncodingParams(endian="little", point_len=33, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0,
            0x31D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38904,
        ),
    ),
)


class Secp256k1Point(SWAffinePoint):
    """Point on secp256k1."""

    def __mul__(self, scalar: int) -> Self:
        if scalar == 0:
            return cast(Self, self.identity())

        if scalar < 0:
            return cast(Self, (-self).__mul__(-scalar))

        scalar %= self.curve.params.subgroup_order
        return cast(Self, super().__mul__(scalar))


Secp256k1_RO_Curve = SWCurve(params=SECP256K1_PARAMS, e2c_variant=E2C_Variant.SSWU)
Secp256k1_NU_Curve = SWCurve(params=SECP256K1_PARAMS, e2c_variant=E2C_Variant.SSWU_NU)


class Secp256k1ROPoint(Secp256k1Point):
    curve = Secp256k1_RO_Curve


class Secp256k1NUPoint(Secp256k1Point):
    curve = Secp256k1_NU_Curve


Secp256k1_RO = CurveVariant(
    name="Secp256k1_RO",
    curve=Secp256k1_RO_Curve,
    point_type=Secp256k1ROPoint,
)

Secp256k1_NU = CurveVariant(
    name="Secp256k1_NU",
    curve=Secp256k1_NU_Curve,
    point_type=Secp256k1NUPoint,
)
