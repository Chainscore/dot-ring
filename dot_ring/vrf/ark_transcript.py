from __future__ import annotations

import hashlib

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint


def _scalar_len(curve: CurveVariant) -> int:
    return (curve.curve.ORDER.bit_length() + 7) // 8


class ArkTranscript:
    def __init__(self, label: bytes, hash_name: str = "sha512") -> None:
        self.hash_name = hash_name
        self._absorbed = bytearray(label)
        self._seed: bytes | None = None
        self._squeeze_offset = 0

    def clone(self) -> ArkTranscript:
        other = ArkTranscript(b"", self.hash_name)
        other._absorbed = bytearray(self._absorbed)
        other._seed = self._seed
        other._squeeze_offset = self._squeeze_offset
        return other

    def absorb_raw(self, data: bytes) -> None:
        if self._seed is not None:
            raise ValueError("cannot absorb after squeeze")
        self._absorbed.extend(data)

    def absorb_point(self, point: CurvePoint) -> None:
        self.absorb_raw(point.point_to_string())

    def absorb_scalar(self, curve: CurveVariant, value: int) -> None:
        self.absorb_raw(int(value % curve.curve.ORDER).to_bytes(_scalar_len(curve), "little"))

    def squeeze_raw(self, size: int) -> bytes:
        if self.hash_name == "shake128":
            return self._squeeze_shake128(size)
        return self._squeeze_digest_xof(size)

    def _digest(self, data: bytes) -> bytes:
        if self.hash_name == "sha256":
            return hashlib.sha256(data).digest()
        if self.hash_name == "sha512":
            return hashlib.sha512(data).digest()
        raise ValueError(f"unsupported transcript hash {self.hash_name!r}")

    def _squeeze_digest_xof(self, size: int) -> bytes:
        if self._seed is None:
            self._seed = self._digest(bytes(self._absorbed))
        start = self._squeeze_offset
        end = start + size
        block_size = len(self._seed)
        first_block = start // block_size
        last_block = (end + block_size - 1) // block_size
        stream = b"".join(self._digest(self._seed + counter.to_bytes(8, "little")) for counter in range(first_block, last_block))
        self._squeeze_offset = end
        return stream[start % block_size : start % block_size + size]

    def _squeeze_shake128(self, size: int) -> bytes:
        if self._seed is None:
            self._seed = bytes(self._absorbed)
        start = self._squeeze_offset
        end = start + size
        xof = hashlib.shake_128()
        xof.update(self._seed)
        out = xof.digest(end)
        self._squeeze_offset = end
        return out[start:end]
