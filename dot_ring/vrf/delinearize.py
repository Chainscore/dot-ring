from __future__ import annotations

from typing import TYPE_CHECKING

from dot_ring.curve.curve import CurveVariant

from .domain import DomSep
from .transcript import CHALLENGE_LEN

if TYPE_CHECKING:
    from .transcript import VrfTranscript


class DelinearizeScalars:
    def __init__(self, curve: CurveVariant, transcript: VrfTranscript) -> None:
        self.curve = curve
        self.transcript = transcript.copy()
        self.transcript.absorb(bytes([DomSep.DELINEARIZE]))
        self.first = True

    def next(self) -> int:
        if self.first:
            self.first = False
            return 1
        return int.from_bytes(self.transcript.squeeze(CHALLENGE_LEN), "little") % self.curve.curve.params.subgroup_order

    def take(self, n: int) -> list[int]:
        return [self.next() for _ in range(n)]
