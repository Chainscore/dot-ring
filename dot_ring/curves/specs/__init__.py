"""Concrete curve instantiations (Bandersnatch, Jubjub, Ed25519, …) now
available under `dot_ring.curves.specs`.

During migration we re-export the existing implementations from the legacy
location so external imports can switch immediately.
"""

from importlib import import_module as _import_module

Bander = _import_module("dot_ring.curves.specs.bandersnatch")
Jub = _import_module("dot_ring.curves.specs.jubjub")
Ed = _import_module("dot_ring.curves.specs.ed25519")

BandersnatchCurve = Bander.BandersnatchCurve
BandersnatchPoint = Bander.BandersnatchPoint
JubJubCurve = Jub.JubJubCurve
JubJubPoint = Jub.JubJubPoint
Ed25519Curve = Ed.Ed25519Curve
Ed25519Point = Ed.Ed25519Point

__all__ = [
    "BandersnatchCurve",
    "BandersnatchPoint",
    "JubJubCurve",
    "JubJubPoint",
    "Ed25519Curve",
    "Ed25519Point",
]