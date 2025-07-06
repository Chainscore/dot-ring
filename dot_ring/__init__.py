"""
Dot Ring Suite meta-package.

This namespace package aggregates the four sub-packages:
- dot_ring.curves
- dot_ring.fiat_shamir
- dot_ring.ring_proof
- dot_ring.vrf
"""

from importlib import metadata as _metadata, import_module as _import_module
from types import ModuleType as _ModuleType
from typing import Any as _Any

try:
    __version__ = _metadata.version("dot_ring")
except _metadata.PackageNotFoundError:  # pragma: no cover
    # Local development fallback when the package metadata is unavailable.
    __version__ = "0.0.0.dev0"


def __getattr__(name: str) -> _Any:  # type: ignore[override]
    """Dynamically import top-level sub-packages on first access."""
    if name in {"curves", "fiat_shamir", "ring_proof", "vrf"}:
        return _import_module(f"dot_ring.{name}")
    raise AttributeError(name)


__all__ = ["curves", "fiat_shamir", "ring_proof", "vrf"]