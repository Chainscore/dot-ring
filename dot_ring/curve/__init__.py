import importlib as _importlib
import sys as _sys

_new_root = "dot_ring.curves"

# List of modules that moved.
_moved = [
    "curve",
    "point",
    "glv",
    "e2c",
]

for _name in _moved:
    _module = _importlib.import_module(f"{_new_root}.{_name}")
    _sys.modules[f"dot_ring.curve.{_name}"] = _module

# Re-export symbols so `from dot_ring.curve import Curve` keeps working.
from dot_ring.curves.curve import Curve  # noqa: F401,E402