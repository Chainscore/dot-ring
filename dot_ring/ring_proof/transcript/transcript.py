from __future__ import annotations

import hashlib
import math
import struct
from typing import Any

__all__ = ["FiatShamirTranscript"]

_CHALLENGE_FOOTER = b"\x00\x00\x00\x09"


def _label_prefix(label: bytes) -> bytes:
    return label + struct.pack(">I", len(label))


def _challenge_prefix(label: bytes) -> bytes:
    return _label_prefix(label) + b"challenge"


class FiatShamirTranscript:
    """Fiat-Shamir transcript used by the ring proof."""

    def __init__(self, modulus: int, initial: bytes):
        self.modulus = modulus
        self._shake = hashlib.shake_128()
        self._length: int | None = None
        self._challenge_bytes = math.ceil((self.modulus.bit_length() + 128) / 8)
        self.label(initial)

    def copy(self) -> FiatShamirTranscript:
        """Return an independent copy of the current transcript state."""
        clone = FiatShamirTranscript.__new__(FiatShamirTranscript)
        clone.modulus = self.modulus
        clone._shake = self._shake.copy()
        clone._length = self._length
        clone._challenge_bytes = self._challenge_bytes
        return clone

    def _separate(self) -> None:
        if self._length is not None:
            self._shake.update(struct.pack(">I", self._length))
        self._length = None

    def _write(self, data: bytes) -> None:
        if self._length is None:
            self._length = 0
        self._shake.update(data)
        self._length += len(data)

    def _write_bytes(self, data: bytes) -> None:
        HIGH = 1 << 31
        idx = 0
        total_len = len(data)
        while idx < total_len:
            if self._length is None:
                self._length = 0
            remaining_allowed = (HIGH - 1) - self._length
            to_take = min(remaining_allowed, total_len - idx)

            chunk = data[idx : idx + to_take]
            self._write(chunk)

            idx += to_take

            if idx >= total_len:
                return

            if self._length is not None:
                self._length |= HIGH

            self._separate()

    def label(self, lbl: bytes) -> None:
        """Add a domain separation label."""
        self._separate()
        self._shake.update(_label_prefix(lbl))
        self._length = None

    def absorb_labeled(self, label: bytes, data: bytes) -> None:
        """Absorb one explicitly serialized value under a transcript label."""
        if len(data) >= 1 << 31:
            self.label(label)
            self._separate()
            self._write_bytes(data)
            self._separate()
            return

        self._separate()
        self._shake.update(_label_prefix(label) + data + struct.pack(">I", len(data)))
        self._length = None

    def challenge(self, label: bytes) -> int:
        """Generate a challenge value with the given label."""
        return self._challenge_direct(label)

    def challenges(self, label: bytes, n: int) -> list[int]:
        """Generate n challenge values with the given label."""
        return self._repeated_challenges(label, n)

    def _repeated_challenges(self, label: bytes, n: int) -> list[int]:
        if n <= 0:
            return []
        if self._length is not None:
            self._shake.update(struct.pack(">I", self._length))
            self._length = None
        return self._repeated_challenges_from_shake(self._shake, label, n)

    def _repeated_challenges_from_shake(self, shake: Any, label: bytes, n: int) -> list[int]:
        out = [0] * n
        challenge_bytes = self._challenge_bytes
        modulus = self.modulus
        challenge_prefix = _challenge_prefix(label)
        challenge_footer = _CHALLENGE_FOOTER
        challenge_footer_prefix = challenge_footer + challenge_prefix
        update = shake.update
        digest = shake.digest
        int_from_bytes = int.from_bytes
        update(challenge_prefix)
        for index in range(n):
            rnd = digest(challenge_bytes)
            out[index] = int_from_bytes(rnd, "big") % modulus
            update(challenge_footer if index == n - 1 else challenge_footer_prefix)
        return out

    def _challenge_direct(self, label: bytes) -> int:
        shake = self._shake
        update = shake.update
        if self._length is not None:
            update(struct.pack(">I", self._length))
        update(_challenge_prefix(label))
        rnd = shake.digest(self._challenge_bytes)
        value = int.from_bytes(rnd, "big") % self.modulus
        update(_CHALLENGE_FOOTER)
        self._length = None
        return value
