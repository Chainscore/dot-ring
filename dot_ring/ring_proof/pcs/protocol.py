from __future__ import annotations

from typing import Any, ClassVar, Protocol

from .utils import CoeffVector, Scalar

G1Commitment = object


class PCS(Protocol):
    commitment_size: ClassVar[int]
    scalar_modulus: ClassVar[int]
    srs: ClassVar[Any]

    @classmethod
    def normalize_g1(cls, point: G1Commitment) -> tuple[int, int]: ...

    @classmethod
    def compress_g1(cls, point: G1Commitment) -> bytes: ...

    @classmethod
    def serialize_g1_uncompressed(cls, point: G1Commitment) -> bytes: ...

    @classmethod
    def decompress_g1(cls, data: bytes) -> G1Commitment: ...

    @classmethod
    def msm_g1(cls, points: list[G1Commitment], scalars: list[int]) -> G1Commitment: ...

    @classmethod
    def commit(cls, coeffs: CoeffVector) -> G1Commitment: ...

    @classmethod
    def open(cls, coeffs: CoeffVector, x: Scalar) -> Any: ...

    @classmethod
    def verify(cls, commitment: G1Commitment, proof: G1Commitment, point: Scalar, value: Scalar) -> bool: ...

    @classmethod
    def batch_verify(cls, verifications: list[tuple[G1Commitment, G1Commitment, Scalar, Scalar]]) -> bool: ...
