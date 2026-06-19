from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from dot_ring.curve.curve import CurveVariant
from dot_ring.ring_proof.params import RingProofParams

from .members import Ring, parse_concatenated_keys
from .root import RingRoot


@dataclass(frozen=True)
class RingContext:
    params: RingProofParams

    @classmethod
    def from_ring_size(cls, ring_size: int, *, test_vectors: bool = False, cv: CurveVariant | None = None) -> RingContext:
        default_params = RingProofParams()
        return cls(RingProofParams.from_ring_size(ring_size, test_vectors=test_vectors, cv=cv or default_params.cv))

    @property
    def max_ring_size(self) -> int:
        return self.params.max_ring_size

    def ring(self, keys: Sequence[bytes | str] | bytes) -> Ring:
        if isinstance(keys, bytes):
            return Ring(parse_concatenated_keys(keys, self.params.cv), self.params)
        return Ring(keys, self.params)

    def ring_root(self, ring: Ring | Sequence[bytes | str] | bytes) -> RingRoot:
        if not isinstance(ring, Ring):
            ring = self.ring(ring)
        return RingRoot.from_ring(ring, self.params)

    def decode_ring_root(self, commitment: RingRoot | bytes) -> RingRoot:
        if isinstance(commitment, RingRoot):
            return commitment
        return RingRoot.decode(commitment, self.params)

    def ring_root_builder(self) -> RingRootBuilder:
        return RingRootBuilder(self)


@dataclass
class RingRootBuilder:
    context: RingContext
    keys: list[bytes] = field(default_factory=list)
    _root: RingRoot | None = field(default=None, init=False, repr=False)

    def push(self, key: bytes) -> None:
        self.extend([key])

    def append(self, keys: list[bytes] | bytes) -> None:
        self.extend(keys)

    def extend(self, keys: list[bytes] | bytes) -> None:
        if isinstance(keys, bytes):
            keys = parse_concatenated_keys(keys, self.context.params.cv)
        if len(self.keys) + len(keys) > self.context.max_ring_size:
            raise ValueError("too many keys for ring root builder")
        self.keys.extend(keys)
        self._root = None
        if len(self.keys) == self.context.max_ring_size:
            self._root = self.context.ring_root(self.keys)

    def finalize(self) -> RingRoot:
        if self._root is None:
            self._root = self.context.ring_root(self.keys)
        return self._root
