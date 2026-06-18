from __future__ import annotations

from dataclasses import dataclass

from .protocol import G1Commitment
from .utils import Scalar


@dataclass(slots=True, frozen=True)
class Opening:
    proof: G1Commitment
    y: Scalar
