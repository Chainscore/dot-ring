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

P256_PARAMS = ShortWeierstrassCurveParams[int](
    field_modulus=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    subgroup_order=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    cofactor=1,
    suite_id=b"Secp256r1-SHA256-TAI-v1",
    hash_fn=hashlib.sha256,
    generator=(
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
        z=-10,
        field_extension_degree=1,
        security_level=128,
        field_length=48,
        expand_len=64,
    ),
    encoding=EncodingParams(endian="big", point_len=33, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            100063053743935619201936855760019111820847755970243670581468062459849338000,
            113675507039234898358330549589155441528265243038226986303017485279501143145422,
        ),
    ),
)


class P256Point(SWAffinePoint):
    """
    Point on the NIST P-256 curve.

    Implements point operations specific to the P-256 curve.
    """

    def point_to_string(self, compressed: bool = True) -> bytes:
        if self.curve.e2c_variant != E2C_Variant.TAI:
            return super().point_to_string()

        if self.x is None and self.y is None:
            return bytes([0] * 32 + [0x40])

        p = self.curve.params.field_modulus
        x_bytes = int(self.x).to_bytes(32, "little")
        flag = 0x80 if int(self.y) > (-int(self.y) % p) else 0x00
        return x_bytes + bytes([flag])

    @classmethod
    def string_to_point(cls, data: str | bytes):
        curve = cls.curve
        if isinstance(data, str):
            data = bytes.fromhex(data)

        if curve.e2c_variant != E2C_Variant.TAI:
            return super().string_to_point(data)
        elif len(data) == 33 and data[0] in (0x02, 0x03):
            # Canonical SW encodings put flags in the final byte, so external
            # vectors can coincidentally start with SEC1 marker bytes.
            try:
                return cls._string_to_canonical_point(data)
            except ValueError:
                return super().string_to_point(data)

        if len(data) != 33:
            raise ValueError(f"Invalid compressed point length: expected 33, got {len(data)}")
        return cls._string_to_canonical_point(data)

    @classmethod
    def _string_to_canonical_point(cls, data: bytes):
        curve = cls.curve
        flag = data[-1]
        is_negative = (flag >> 7) & 1
        is_infinity = (flag >> 6) & 1
        if flag & 0x3F:
            raise ValueError("Invalid canonical point flags")
        if is_infinity:
            if is_negative or any(data[:-1]):
                raise ValueError("Invalid infinity encoding")
            return cls.identity()

        x = int.from_bytes(data[:-1], "little")
        if x >= curve.params.field_modulus:
            raise ValueError("x-coordinate is not in field")
        y_candidates = cls._y_recover(x)
        if y_candidates is None:
            raise ValueError("Invalid point")
        y, y_neg = y_candidates
        return cls(x, y_neg if is_negative else y)

    @classmethod
    def _y_recover(cls, x: int) -> tuple[int, int] | None:
        curve = cls.curve
        p = curve.params.field_modulus
        y_square = (pow(x, 3, p) + curve.params.a * x + curve.params.b) % p
        try:
            y = curve.mod_sqrt(y_square)
        except ValueError:
            return None
        neg_y = -y % p
        return (y, neg_y) if y <= neg_y else (neg_y, y)


P256_RO_Curve = SWCurve(params=P256_PARAMS, e2c_variant=E2C_Variant.SSWU)
P256_NU_Curve = SWCurve(params=P256_PARAMS, e2c_variant=E2C_Variant.SSWU_NU)
P256_TAI_Curve = SWCurve(params=P256_PARAMS, e2c_variant=E2C_Variant.TAI)


class P256ROPoint(P256Point):
    curve = P256_RO_Curve


class P256NUPoint(P256Point):
    curve = P256_NU_Curve


class P256TAIPoint(P256Point):
    curve = P256_TAI_Curve


P256_RO = CurveVariant(
    name="P256_RO",
    curve=P256_RO_Curve,
    point_type=P256ROPoint,
)

P256_NU = CurveVariant(
    name="P256_NU",
    curve=P256_NU_Curve,
    point_type=P256NUPoint,
)

P256_TAI = CurveVariant(
    name="P256_TAI",
    curve=P256_TAI_Curve,
    point_type=P256TAIPoint,
)
