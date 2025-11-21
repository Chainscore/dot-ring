# transcript.py
from __future__ import annotations

import hashlib
import math
import struct
from typing import List

__all__ = ["Transcript"]


class Transcript:
    """Direct implementation of the Transcript class matching the original code."""

    def __init__(self, modulus: int, initial: bytes):
        self.modulus = modulus
        self._shake = hashlib.shake_128()
        self._length = None
        self.label(initial)

    def separate(self):
        """Write length footer if needed and reset counter."""
        if self._length is not None:
            self._shake.update(struct.pack(">I", self._length))
        self._length = None

    def write(self, data: bytes):
        """Write data to the transcript."""
        if self._length is None:
            self._length = 0
        self._shake.update(data)
        self._length += len(data)

    def write_bytes(self, data: bytes):
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
            self._length |= HIGH

            # Emit a separator and loop for the rest
            self.separate()

    def label(self, lbl: bytes):
        """Add a domain separation label."""
        self.separate()
        self.write(lbl)
        self.separate()

    def challenge(self, label: bytes) -> int:
        """Generate a challenge value with the given label."""
        self.label(label)
        self.write(b"challenge")
        ret = self.read_reduce()
        self.separate()
        return ret

    def _read_xof(self, n: int) -> bytes:
        """Read n bytes from the sponge."""
        shake_copy = self._shake.copy()
        return shake_copy.digest(n)

    def append(self, data: bytes):
        """Append data with domain separation."""
        self.separate()
        self.write_bytes(data)
        self.separate()

    def add_serialized(self, label: bytes, data: bytes):
        """Add labeled serialized object to transcript."""
        self.label(label)
        self.append(data)

    def read_reduce(self) -> int:
        """Read a value and reduce it modulo the field size."""
        n = math.ceil((self.modulus.bit_length() + 128) / 8)
        rnd = self._read_xof(n)
        # reverse for BE→LE
        val = int.from_bytes(rnd[::-1], "little")
        return val % self.modulus

    def get_constraints_aggregation_coeffs(self, n: int) -> List[int]:
        """Get n constraint aggregation coefficients."""
        out = []
        for _ in range(n):
            out.append(self.challenge(b"constraints_aggregation"))
        return out

    def get_evaluation_point(self, n: int = 1) -> List[int]:
        """Get n evaluation points."""
        out = []
        out.append(self.challenge(b"evaluation_point"))
        return out

    def get_kzg_aggregation_challenges(self, n: int) -> List[int]:
        """Get n KZG aggregation challenges."""
        out = []
        for _ in range(n):
            out.append(self.challenge(b"kzg_aggregation"))
        return out
