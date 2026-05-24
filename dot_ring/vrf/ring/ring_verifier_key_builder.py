from __future__ import annotations

from dataclasses import dataclass, field

from .ring_context import RingContext
from .ring_keys import parse_concatenated_keys
from .ring_root import RingRoot


@dataclass
class RingVerifierKeyBuilder:
    context: RingContext
    keys: list[bytes] = field(default_factory=list)

    def push(self, key: bytes) -> None:
        self.keys.append(key)

    def extend(self, keys: list[bytes] | bytes) -> None:
        if isinstance(keys, bytes):
            keys = parse_concatenated_keys(keys, self.context.setup.cv)
        self.keys.extend(keys)

    def finalize(self) -> RingRoot:
        return self.context.verifier_key(self.keys)
