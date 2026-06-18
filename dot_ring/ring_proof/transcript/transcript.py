# transcript.py
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

    def separate(self) -> None:
        """Write length footer if needed and reset counter."""
        if self._length is not None:
            self._shake.update(struct.pack(">I", self._length))
        self._length = None

    def write(self, data: bytes) -> None:
        """Write data to the transcript."""
        if self._length is None:
            self._length = 0
        self._shake.update(data)
        self._length += len(data)

    def write_bytes(self, data: bytes) -> None:
        """
        Write `data` into the transcript, breaking into <=2^31-1 chunks
        and inserting length-footers between them.
        """
        HIGH = 1 << 31
        idx = 0
        total_len = len(data)
        while idx < total_len:
            # Initialize or fetch the byte-counter since last separator
            if self._length is None:
                self._length = 0
            # How many bytes can we consume before hitting (2^31-1)
            remaining_allowed = (HIGH - 1) - self._length
            to_take = min(remaining_allowed, total_len - idx)

            # Absorb that slice
            chunk = data[idx : idx + to_take]
            self.write(chunk)

            # Advance
            idx += to_take

            # If we're done, exit
            if idx >= total_len:
                return

            # Otherwise we hit the chunk-size limit: set the MSB flag
            if self._length is not None:
                self._length |= HIGH

            # Emit a separator and loop for the rest
            self.separate()

    def label(self, lbl: bytes) -> None:
        """Add a domain separation label."""
        self.separate()
        self._shake.update(_label_prefix(lbl))
        self._length = None

    def challenge(self, label: bytes) -> int:
        """Generate a challenge value with the given label."""
        return self._challenge_direct(label)

    def _read_xof(self, n: int) -> bytes:
        """Read n bytes from the sponge."""
        return self._shake.digest(n)

    def append(self, data: bytes) -> None:
        """Append data with domain separation."""
        self.separate()
        self.write_bytes(data)
        self.separate()

    def add_serialized(self, label: bytes, data: bytes) -> None:
        """Add labeled serialized object to transcript."""
        self.label(label)
        self.append(data)

    def add_serialized_bytes(self, label: bytes, data: bytes) -> None:
        """Add already-serialized small bytes without generic write dispatch."""
        if len(data) >= 1 << 31:
            self.add_serialized(label, data)
            return

        self.separate()
        self._shake.update(_label_prefix(label) + data + struct.pack(">I", len(data)))
        self._length = None

    def read_reduce(self) -> int:
        """Read a value and reduce it modulo the field size."""
        rnd = self._read_xof(self._challenge_bytes)
        val = int.from_bytes(rnd, "big")
        return val % self.modulus

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

    def get_constraints_aggregation_coeffs(self, n: int) -> list[int]:
        """Get n constraint aggregation coefficients."""
        return self._repeated_challenges(b"constraints_aggregation", n)

    def get_evaluation_point(self, n: int = 1) -> list[int]:
        """Get n evaluation points."""
        out = []
        out.append(self.challenge(b"evaluation_point"))
        return out

    def get_kzg_aggregation_challenges(self, n: int) -> list[int]:
        """Get n KZG aggregation challenges."""
        return self._repeated_challenges(b"kzg_aggregation", n)
