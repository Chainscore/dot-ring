"""Twisted Edwards curves (Bandersnatch, Jubjub, etc.) helpers placed under the new
`dot_ring.curves` namespace.

During the transition period this sub-package simply re-exports the classes
defined in the legacy `dot_ring.curve.twisted_edwards` package so that new
import paths already work:

    from dot_ring.curves.twisted_edwards import TECurve, TEAffinePoint
"""

from importlib import import_module as _import_module

_TECurve_mod = _import_module("dot_ring.curve.twisted_edwards.te_curve")
_TEAffine_mod = _import_module("dot_ring.curve.twisted_edwards.te_affine_point")

TECurve = _TECurve_mod.TECurve  # type: ignore[attr-defined]
TEAffinePoint = _TEAffine_mod.TEAffinePoint  # type: ignore[attr-defined]

# Optional projective variant (stubbed in legacy code)
try:
    _TEProj_mod = _import_module("dot_ring.curve.twisted_edwards.te_projective_point")
    TEProjectivePoint = _TEProj_mod.TEProjectivePoint  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover
    TEProjectivePoint = None  # type: ignore

__all__ = [
    "TECurve",
    "TEAffinePoint",
    "TEProjectivePoint",
]