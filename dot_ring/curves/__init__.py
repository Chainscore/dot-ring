"""
dot_ring.curves

Low-level elliptic curve primitives.

This sub-package is intentionally minimal at this stage and will be
populated with concrete field and curve implementations in future commits.
"""

__all__: list[str] = []

# Temporary compatibility re-exports while code is migrated
import sys as _sys
import importlib as _importlib
from types import ModuleType as _ModuleType

# Map of legacy sub-modules that should appear under the new namespace
_legacy_modules = {
    "curve": "dot_ring.curve.curve",
    "point": "dot_ring.curve.point",
    "glv": "dot_ring.curve.glv",
    "e2c": "dot_ring.curve.e2c",
    "twisted_edwards": "dot_ring.curve.twisted_edwards",
    "specs": "dot_ring.curve.specs",
    "short_weierstrass": "dot_ring.curve.short_weierstrass",
    "bls12_381": "dot_ring.curve.bls12_381",
}

for _new_name, _old_path in _legacy_modules.items():
    _module: _ModuleType = _importlib.import_module(_old_path)
    _sys.modules[f"{__name__}.{_new_name}"] = _module
    # Re-export top-level names for convenience if they exist.
    for _attr in getattr(_module, "__all__", []):
        globals()[_attr] = getattr(_module, _attr)

# Ensure `Curve` base class is reachable directly
try:
    from dot_ring.curve.curve import Curve as _Curve

    globals()["Curve"] = _Curve
    __all__.append("Curve")
except Exception:  # pragma: no cover
    pass

# Public re-exports for convenience
from dot_ring.curves.e2c import E2C_Variant  # noqa: E402
from dot_ring.curves.glv import GLVSpecs, DisabledGLV  # noqa: E402
from dot_ring.curves.curve import Curve  # noqa: E402

__all__ += [
    "E2C_Variant",
    "GLVSpecs",
    "DisabledGLV",
    "Curve",
]