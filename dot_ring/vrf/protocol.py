from __future__ import annotations

from abc import abstractmethod
from typing import Protocol, TypeVar

from ..curve.curve import CurveVariant
from ..curve.point import CurvePoint

C = TypeVar("C", bound=CurveVariant)
P = TypeVar("P", bound=CurvePoint)


class VRFProtocol(Protocol[C, P]):
    """Protocol defining the interface for VRF implementations."""

    curve: C
    point_type: type[P]

    @abstractmethod
    def proof(self, alpha: bytes, secret_key: int, additional_data: bytes) -> tuple[P, tuple[int, int]]:
        """Generate VRF proof."""
        ...

    @abstractmethod
    def verify(
        self,
        public_key: P,
        input_point: P,
        additional_data: bytes,
        output_point: P,
        proof: tuple[int, int],
    ) -> bool:
        """Verify VRF proof."""
        ...
