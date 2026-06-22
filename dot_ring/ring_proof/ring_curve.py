from __future__ import annotations

from typing import cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.curve.twisted_edwards.te_curve import TECurve

_BANDERSNATCH_MONT_A_OVER_THREE = 9992940898322946442093665462003920523391277922024982836398934612730118446984
_BANDERSNATCH_MONT_B = 25465760566081946422412445027709227188579564747101592991722834452325077642517


def _bandersnatch_sw_to_te(point: tuple[int, int]) -> tuple[int, int]:
    prime = Bandersnatch.curve.params.field_modulus
    sw_x, sw_y = point
    mont_x = (_BANDERSNATCH_MONT_B * sw_x - _BANDERSNATCH_MONT_A_OVER_THREE) % prime
    mont_y = (_BANDERSNATCH_MONT_B * sw_y) % prime
    v = mont_x * pow(mont_y, -1, prime)
    w = (mont_x - 1) * pow((mont_x + 1) % prime, -1, prime)
    return v % prime, w % prime


def ring_proof_curve(public_curve: CurveVariant) -> CurveVariant:
    if public_curve.name == "Bandersnatch_SW":
        return Bandersnatch
    return public_curve


def ring_coords(public_curve: CurveVariant, point: CurvePoint | tuple[int, int]) -> tuple[int, int]:
    if isinstance(point, tuple):
        coords = int(point[0]), int(point[1])
    else:
        coords = int(cast(int, point.x)), int(cast(int, point.y))
    if public_curve.name == "Bandersnatch_SW":
        return _bandersnatch_sw_to_te(coords)
    return coords


def ring_auxiliary_point(public_curve: CurveVariant, name: str) -> tuple[int, int]:
    curve = ring_proof_curve(public_curve)
    point = getattr(curve.curve.params.auxiliary_points, name)
    if point is None:
        raise ValueError(f"{public_curve.name} ring proofs require auxiliary point {name}")
    return int(point[0]), int(point[1])


def validate_ring_curve(public_curve: CurveVariant, prime: int) -> None:
    curve = ring_proof_curve(public_curve)
    if not isinstance(curve.curve, TECurve):
        raise ValueError(f"{public_curve.name} ring proofs require a Twisted Edwards ring curve")
    if curve.curve.params.field_modulus != prime:
        raise ValueError(f"{public_curve.name} ring proofs require field modulus {prime}")
    for name in ("blinding_base", "accumulator_base", "padding_point"):
        ring_auxiliary_point(public_curve, name)
