"""Serialization helpers for Transcript data.

Moved from ``dot_ring.ring_proof.transcript`` to standalone package so other
libraries can reuse the same byte-format conventions.
"""

from __future__ import annotations

from typing import Any

from dot_ring.ring_proof.constants import S_PRIME  # Re-use constant for now.

__all__ = ["serialize"]


def serialize(obj: Any) -> bytes:  # noqa: C901 – complex but unchanged
    if isinstance(obj, int):
        byte_len = (obj.bit_length() + 7) // 8
        if byte_len <= 32:
            return obj.to_bytes(32, "little")
        if byte_len <= 48:
            return obj.to_bytes(48, "big")
        raise ValueError("Integer too large to serialize in 48 bytes")

    if isinstance(obj, tuple):
        if len(obj) == 2 and (obj[0].bit_length() // 8 + obj[1].bit_length() // 8) > 64:
            x, y = obj
            return serialize(x) + serialize(y)
        x, y = obj
        flag = b"\x01" if x > (S_PRIME - 1) // 2 else b""
        return serialize(x) + serialize(y) + flag

    if isinstance(obj, list):
        return b"".join(serialize(item) for item in obj)

    if isinstance(obj, dict):
        result = b""
        if "g1" in obj and "g2" in obj:
            result += serialize(obj["g1"])
            for g2_item in obj["g2"]:
                result += serialize(g2_item)
        if "commitments" in obj:
            for commitment in obj["commitments"]:
                result += serialize(commitment)
        return result

    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj)

    raise TypeError(f"Unsupported object type for serialization: {type(obj)}")