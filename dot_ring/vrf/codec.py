"""Bandersnatch VRF spec section 1.5 codec functions."""

from __future__ import annotations

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint


def scalar_len(curve: CurveVariant) -> int:
    return (curve.curve.params.subgroup_order.bit_length() + 7) // 8


def point_len(curve: CurveVariant) -> int:
    encoding = curve.curve.params.encoding
    return encoding.point_len * (2 if encoding.uncompressed else 1)


def enc_scalar(curve: CurveVariant, value: int) -> bytes:
    return int(value % curve.curve.params.subgroup_order).to_bytes(scalar_len(curve), "little")


def dec_scalar(curve: CurveVariant, value: bytes) -> int:
    if len(value) != scalar_len(curve):
        raise ValueError(f"scalar must be exactly {scalar_len(curve)} bytes")
    scalar = int.from_bytes(value, "little")
    if scalar >= curve.curve.params.subgroup_order:
        raise ValueError("scalar is not canonical")
    return scalar


def dec_scalar_mod(curve: CurveVariant, value: bytes) -> int:
    return int.from_bytes(value, "little") % curve.curve.params.subgroup_order


def enc_point(point: CurvePoint) -> bytes:
    return point.point_to_string()


def dec_point(curve: CurveVariant, value: bytes) -> CurvePoint:
    if len(value) != point_len(curve):
        raise ValueError(f"point must be exactly {point_len(curve)} bytes")
    point = curve.point_type.string_to_point(value)
    if not curve.curve.valid_point(point):
        raise ValueError("point is not a valid nonidentity subgroup point")
    return point


def enc_64(value: int) -> bytes:
    if not 0 <= value < 1 << 64:
        raise ValueError("value does not fit in uint64")
    return value.to_bytes(8, "little")
