"""E2C (Encode-to-Curve) variants supported by Dot Ring Suite."""

from enum import Enum


class E2C_Variant(Enum):
    ELL2 = "Hash2Suite_Elligator2"
    TAI = "TryAndIncrement"