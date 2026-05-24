from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .utils import Scalar


@dataclass(slots=True, frozen=True)
class Opening:
    proof: Any
    y: Scalar
