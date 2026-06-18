from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from dot_ring.curve.curve import CurveVariant
from dot_ring.ring_proof.params import RingProofParams

from .members import Ring, parse_concatenated_keys
from .root import RingRoot

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
        return RingVerifierKeyBuilder(self)


@dataclass
class RingVerifierKeyBuilder:
    context: RingContext
    keys: list[bytes] = field(default_factory=list)
    _root: RingRoot | None = field(default=None, init=False, repr=False)

    def push(self, key: bytes) -> None:
        self.extend([key])

    def append(self, keys: list[bytes] | bytes) -> None:
        self.extend(keys)

    def extend(self, keys: list[bytes] | bytes) -> None:
        if isinstance(keys, bytes):
            keys = parse_concatenated_keys(keys, self.context.setup.cv)
        if len(self.keys) + len(keys) > self.context.max_ring_size:
            raise ValueError("too many keys for ring verifier-key builder")
        self.keys.extend(keys)
        self._root = None
        if len(self.keys) == self.context.max_ring_size:
            self._root = self.context.verifier_key(self.keys)

    def finalize(self) -> RingRoot:
        if self._root is None:
            self._root = self.context.verifier_key(self.keys)
        return self._root
