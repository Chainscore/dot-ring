from __future__ import annotations

from dataclasses import dataclass

from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import VrfIo


@dataclass
class ThinBatchItem:
    c: int
    ios: list[VrfIo]
    zs: list[int]
    r: CurvePoint
    s: int
