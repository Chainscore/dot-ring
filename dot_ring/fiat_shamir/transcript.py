"""Generic Fiat-Shamir transcript backed by SHAKE128 (compatible with ark-transcript).

This file is a verbatim migration of the transcript implementation that
previously lived under ``dot_ring.ring_proof.transcript`` so that other
packages can depend on a standalone transcript layer without pulling the
whole ring-proof stack.
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import List

__all__ = ["Transcript"]


class Transcript:
    """Extendable-output Fiat–Shamir transcript."""

    def __init__(self, modulus: int, initial: bytes):
        self.modulus = modulus
        self._shake = hashlib.shake_128()
        self._length: int | None = None
        self.label(initial)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def separate(self) -> None:
        """Insert length footer if needed; reset length counter."""
        if self._length is not None:
            self._shake.update(struct.pack(">I", self._length))
        self._length = None

    def write(self, data: bytes) -> None:
        if self._length is None:
            self._length = 0
        self._shake.update(data)
        self._length += len(data)

    def write_bytes(self, data: bytes) -> None:
        """Write arbitrarily long byte string using 2^31-1 chunking."""
        HIGH = 1 << 31
        idx = 0
        total_len = len(data)
        while idx < total_len:
            if self._length is None:
                self._length = 0
            remaining_allowed = (HIGH - 1) - self._length
            to_take = min(remaining_allowed, total_len - idx)
            chunk = data[idx : idx + to_take]
            self.write(chunk)
            idx += to_take
            if idx >= total_len:
                return
            # mark footer with MSB, emit separator
            self._length |= HIGH
            self.separate()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def label(self, lbl: bytes) -> None:
        """Domain separation label."""
        self.separate()
        self.write(lbl)
        self.separate()

    def append(self, data: bytes) -> None:
        self.separate()
        self.write_bytes(data)
        self.separate()

    def add_serialized(self, label: bytes, data: bytes) -> None:
        self.label(label)
        self.append(data)

    def _read_xof(self, n: int) -> bytes:
        return self._shake.copy().digest(n)

    def read_reduce(self) -> int:
        n = math.ceil((self.modulus.bit_length() + 128) / 8)
        rnd = self._read_xof(n)
        val = int.from_bytes(rnd[::-1], "little")
        return val % self.modulus

    def challenge(self, label: bytes) -> int:
        self.label(label)
        self.write(b"challenge")
        ret = self.read_reduce()
        self.separate()
        return ret

    # Conveniences specific to ring-proof usage (kept for compat) --------

    def get_constraints_aggregation_coeffs(self, n: int) -> List[int]:
        return [self.challenge(b"constraints_aggregation") for _ in range(n)]

    def get_evaluation_point(self, n: int = 1) -> List[int]:
        return [self.challenge(b"evaluation_point")]

    def get_kzg_aggregation_challenges(self, n: int) -> List[int]:
        return [self.challenge(b"kzg_aggregation") for _ in range(n)]