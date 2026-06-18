from __future__ import annotations

import hashlib
from typing import Literal, Self, cast

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

BANDERSNATCH_SW_PARAMS = ShortWeierstrassCurveParams[int](
    field_modulus=52435875175126190479447740508185965837690552500527637822603658699938581184513,
    subgroup_order=0x1CFB69D4CA675F520CCE760202687600FF8F87007419047174FD06B52876E7E1,
    cofactor=4,
    suite_id=b"Bandersnatch-SW-SHA512-TAI-v1",
    hash_fn=hashlib.sha512,
    generator=(
        30900340493481298850216505686589334086208278925799850409469406976849338430199,
        12663882780877899054958035777720958383845500985908634476792678820121468453298,
    ),
    a=10773120815616481058602537765553212789256758185246796157495669123169359657269,
    b=29569587568322301171008055308580903175558631321415017492731745847794083609535,
    hash_to_curve=HashToCurveParams(
        dst=b"",
        z=-11,
        field_extension_degree=1,
        security_level=1,
        field_length=64,
        expand_len=64,
    ),
    encoding=EncodingParams(endian="little", point_len=33, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            28115362618644671219696075022370511395136332234538034358311199318506963235315,
            3900851469868158154936962463930962496000252801946757953905982128670530185313,
        ),
        accumulator_base=(
            13189182432637108534251278524663360416811744717379968387043749958796254980045,
            14483286006782706188671626508232161325054303360192563232232823772738911894793,
        ),
        padding_point=(
            20496180070424734470560955314776462366297546779079302509428101119888111900885,
            8839106592405352067483360946162273985142890146060814748321063063028225641813,
        ),
    ),
)


class BandersnatchSWPoint(SWAffinePoint):
    """Point on Bandersnatch in short-Weierstrass form."""

    def point_to_string(self, compressed: bool = False) -> bytes:
        p = self.curve.params.field_modulus
        field_bit_len = p.bit_length()
        output_byte_len = (field_bit_len + 2 + 7) // 8

        if self.x is None and self.y is None:
            result = bytearray(output_byte_len)
            result[-1] |= 1 << 6
            return bytes(result)

        if self.x is None or self.y is None:
            raise ValueError("Cannot serialize identity point")

        y_int = cast(int, self.y)
        flag = 0 if y_int <= (-y_int % p) else 1 << 7
        x_bytes = int(cast(int, self.x)).to_bytes((field_bit_len + 7) // 8, cast(Literal["little", "big"], self.curve.encoding_endian()))

        result = bytearray(output_byte_len)
        result[: len(x_bytes)] = x_bytes
        result[-1] |= flag
        return bytes(result)

    @classmethod
    def _y_recover(cls, x: int, curve: SWCurve) -> tuple[int, int] | None:
        p = curve.params.field_modulus
        y_square = (pow(x, 3, p) + curve.params.a * x + curve.params.b) % p
        try:
            y = curve.mod_sqrt(y_square)
        except ValueError:
            return None

        if not y:
            return None
        neg_y = -y % p
        if isinstance(y, int) and y <= (p - 1) // 2:
            return y, neg_y
        return neg_y, y

    @classmethod
    def string_to_point(cls, data: str | bytes, curve: SWCurve) -> Self:
        if isinstance(data, str):
            data = bytes.fromhex(data)

        if len(data) == 0:
            raise ValueError("Empty octet string")

        x_bytes = data[:-1]
        x = int.from_bytes(x_bytes, curve.encoding_endian())
        y_candidates = cls._y_recover(x, curve)
        if not y_candidates:
            raise ValueError("Invalid point: no y-coordinate found for x")
        y, y_neg = y_candidates

        flag = data[-1]
        if flag & 0x3F:
            raise ValueError("Invalid canonical point flags")
        is_negative = (flag >> 7) & 1
        is_infinity = (flag >> 6) & 1

        if is_infinity:
            if is_negative:
                raise ValueError("Invalid infinity point: negative flag is set")
            raise ValueError("Invalid infinity point: not supported")

        try:
            return cls(x, y_neg if is_negative else y, curve)
        except ValueError:
            raise ValueError("Invalid point") from None


Bandersnatch_SW = CurveVariant(
    name="Bandersnatch_SW",
    curve=SWCurve(params=BANDERSNATCH_SW_PARAMS, e2c_variant=E2C_Variant.TAI),
    point_type=BandersnatchSWPoint,
)
