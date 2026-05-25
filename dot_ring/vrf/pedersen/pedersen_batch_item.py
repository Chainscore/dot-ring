from __future__ import annotations

from dataclasses import dataclass

from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import VrfIo


@dataclass
class PedersenBatchItem:
    c: int
    ios: list[VrfIo]
    zs: list[int]
    pk_com: CurvePoint
    r: CurvePoint
    ok: CurvePoint
    s: int
    sb: int
