from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dot_ring.curve.curve import CurveVariant
from dot_ring.ring_proof.params import RingProofParams

from .ring import Ring
from .ring_keys import parse_concatenated_keys
from .ring_root import RingRoot

if TYPE_CHECKING:
    from .ring_verifier_key_builder import RingVerifierKeyBuilder

RingSetup = RingProofParams


@dataclass(frozen=True)
class RingContext:
    setup: RingSetup

    @classmethod
    def from_ring_size(cls, ring_size: int, *, test_vectors: bool = False, cv: CurveVariant | None = None) -> RingContext:
        return cls(RingSetup.from_ring_size(ring_size, test_vectors=test_vectors, cv=cv or RingSetup().cv))

    @property
    def max_ring_size(self) -> int:
        return self.setup.max_ring_size

    def ring(self, keys: Sequence[bytes | str] | bytes) -> Ring:
        if isinstance(keys, bytes):
            return Ring(parse_concatenated_keys(keys, self.setup.cv), self.setup)
        return Ring(keys, self.setup)

    def ring_root(self, ring: Ring | Sequence[bytes | str] | bytes) -> RingRoot:
        if not isinstance(ring, Ring):
            ring = self.ring(ring)
        return RingRoot.from_ring(ring, self.setup)

    def verifier_key(self, ring: Ring | Sequence[bytes | str] | bytes) -> RingRoot:
        return self.ring_root(ring)

    def verifier_key_from_commitment(self, commitment: RingRoot | bytes) -> RingRoot:
        if isinstance(commitment, RingRoot):
            return commitment
        return RingRoot.from_bytes(commitment, self.setup)

    def verifier_key_builder(self) -> RingVerifierKeyBuilder:
        from .ring_verifier_key_builder import RingVerifierKeyBuilder

        return RingVerifierKeyBuilder(self)
