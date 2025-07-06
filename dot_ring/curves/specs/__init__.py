"""Concrete curve instantiations (Bandersnatch, Jubjub, Ed25519, …) now
available under `dot_ring.curves.specs`.

During migration we re-export the existing implementations from the legacy
location so external imports can switch immediately.
"""

from importlib import import_module as _import_module

_bsn_mod = _import_module("dot_ring.curve.specs.bandersnatch")
_jub_mod = _import_module("dot_ring.curve.specs.jubjub")
_ed_mod = _import_module("dot_ring.curve.specs.ed25519")
_bjb_mod = _import_module("dot_ring.curve.specs.baby_jubjub")

BandersnatchCurve = _bsn_mod.BandersnatchCurve  # type: ignore[attr-defined]
JubJubCurve = _jub_mod.JubJubCurve  # type: ignore[attr-defined]
Ed25519Curve = _ed_mod.Ed25519Curve  # type: ignore[attr-defined]
BabyJubJubCurve = _bjb_mod.BabyJubJubCurve  # type: ignore[attr-defined]

__all__ = [
    "BandersnatchCurve",
    "JubJubCurve",
    "Ed25519Curve",
    "BabyJubJubCurve",
]