from __future__ import annotations

from typing import cast

from dot_ring.curve.curve import CurveVariant

from .domain import DomSep
from .spec_transcript import SpecTranscript
from .transcript_constants import CHALLENGE_LEN


class DelinearizeScalars:
    def __init__(self, curve: CurveVariant, transcript: SpecTranscript) -> None:
        self.curve = curve
        self.transcript = transcript.clone()
        self.transcript.absorb_raw(bytes([DomSep.DELINEARIZE]))
        self.first = True

    def next(self) -> int:
        if self.first:
            self.first = False
            return 1
        return int.from_bytes(self.transcript.squeeze_raw(CHALLENGE_LEN), "little") % cast(int, self.curve.curve.ORDER)

    def take(self, n: int) -> list[int]:
        return [self.next() for _ in range(n)]
