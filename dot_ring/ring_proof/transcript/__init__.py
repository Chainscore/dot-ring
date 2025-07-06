"""Deprecated location for transcript helpers.

Import from ``dot_ring.fiat_shamir`` instead.
"""

from importlib import import_module as _import_module
import sys as _sys

_new = _import_module("dot_ring.fiat_shamir.transcript")
_sys.modules[__name__ + ".transcript"] = _new
_sys.modules[__name__ + ".serialize"] = _import_module("dot_ring.fiat_shamir.serialize")
_sys.modules[__name__ + ".phases"] = _import_module("dot_ring.fiat_shamir.phases")

from dot_ring.fiat_shamir.transcript import Transcript  # noqa: F401