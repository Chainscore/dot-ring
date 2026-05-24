from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .ring import Ring
from .ring_root import RingRoot

if TYPE_CHECKING:
    from .ring_vrf import RingVRF


@dataclass
class RingBatchItem:
    proof: RingVRF
    input: bytes
    ad: bytes
    ring: Ring
    ring_root: RingRoot
