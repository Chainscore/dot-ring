# serializer.py
from __future__ import annotations

from typing import Any

from dot_ring.ring_proof.constants import S_PRIME

__all__ = ["serialize"]


def serialize(obj: Any) -> bytes:
    """Serialize objects into bytes format exactly as in the original implementation."""
    # Handle Scalar types by converting to int
    if type(obj).__name__ == 'Scalar':
        return serialize(int(obj))

    if isinstance(obj, int):
        byte_len = (obj.bit_length() + 7) // 8
        if byte_len <= 32:
            return obj.to_bytes(32, "little")
        elif byte_len <= 48:
            return obj.to_bytes(48, "big")
        else:
            raise ValueError("Integer too large to serialize in 48 bytes")

    elif isinstance(obj, tuple):
        if len(obj) == 2 and (obj[0].bit_length() // 8 + obj[1].bit_length() // 8) > 64:
            # G1 point (x, y) where both are integers
            x, y = obj
            return serialize(x) + serialize(y)
        else:
            x, y = obj
            # Uncompressed: serialize x, y, and flag
            b"\x01" if x > (S_PRIME - 1) // 2 else b""
            return serialize(x) + serialize(y)

    elif isinstance(obj, list):
        # List of items
        result = b""
        for item in obj:
            result += serialize(item)
        return result

    elif isinstance(obj, dict):
        # Handle dictionary (like verifier key)
        result = b""
        if "g1" in obj and "g2" in obj:
            # Serialize g1 point
            result += serialize(obj["g1"])
            # Handle g2 as a list
            g2_list = obj["g2"]
            for g2_item in g2_list:
                result += serialize(g2_item)

        # Add commitments if present
        if "commitments" in obj:
            commitments = obj["commitments"]
            for commitment in commitments:
                result += serialize(commitment)

        return result

    elif isinstance(obj, bytes):
        return obj

    elif isinstance(obj, bytearray):
        return bytes(obj)

    else:
        raise TypeError(f"Unsupported object type for serialization: {type(obj)}")
