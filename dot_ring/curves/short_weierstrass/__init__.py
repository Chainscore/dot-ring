"""Short-Weierstrass form of Bandersnatch (and related curves) under the
`dot_ring.curves` namespace.
"""

from importlib import import_module as _import_module

_SW_mod = _import_module("dot_ring.curve.short_weierstrass.curve")
ShortWeierstrassCurve = _SW_mod.ShortWeierstrassCurve  # type: ignore[attr-defined]

__all__ = ["ShortWeierstrassCurve"]