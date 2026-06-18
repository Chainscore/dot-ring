from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, Literal, TypeVar

Coord = TypeVar("Coord")
HashConstructor = Callable[[], Any]


@dataclass(frozen=True, kw_only=True)
class ShortWeierstrassModel(Generic[Coord]):
    """Short-Weierstrass coefficients for an auxiliary map curve."""

    a: Coord
    b: Coord


@dataclass(frozen=True, kw_only=True)
class Elligator2MontgomeryMap:
    """Montgomery curve used by Elligator 2 before target-curve conversion."""

    a: int
    b: int



@dataclass(frozen=True, kw_only=True)
class RationalIsogeny(Generic[Coord]):
    """Rational isogeny map from an auxiliary curve to the target curve."""

    map_curve: ShortWeierstrassModel[Coord]
    x_numerator: tuple[Coord, ...]
    x_denominator: tuple[Coord, ...]
    y_numerator: tuple[Coord, ...]
    y_denominator: tuple[Coord, ...]


@dataclass(frozen=True, kw_only=True)
class HashToCurveParams(Generic[Coord]):
    """Hash-to-curve constants for a curve suite."""

    dst: bytes
    z: Coord
    field_extension_degree: int
    security_level: int
    field_length: int
    expand_len: int | None
    hash_fn: HashConstructor | None = None
    isogeny: RationalIsogeny[Coord] | None = None
    elligator2_map: Elligator2MontgomeryMap | None = None


@dataclass(frozen=True, kw_only=True)
class EncodingParams:
    """Point/scalar encoding constants."""

    endian: Literal["little", "big"]
    point_len: int
    challenge_len: int
    uncompressed: bool = False


@dataclass(frozen=True, kw_only=True)
class AuxiliaryPointParams(Generic[Coord]):
    """Non-generator points used by VRF/ring-proof protocols."""

    blinding_base: tuple[Coord, Coord] | None = None
    accumulator_base: tuple[Coord, Coord] | None = None
    padding_point: tuple[Coord, Coord] | None = None


@dataclass(frozen=True, kw_only=True)
class CurveParams(Generic[Coord]):
    """Base constants shared by all curve forms."""

    field_modulus: int
    subgroup_order: int
    cofactor: int
    suite_id: bytes
    hash_fn: HashConstructor
    generator: tuple[Coord, Coord]
    hash_to_curve: HashToCurveParams[Coord]
    encoding: EncodingParams
    auxiliary_points: AuxiliaryPointParams[Coord] = AuxiliaryPointParams()


@dataclass(frozen=True, kw_only=True)
class ShortWeierstrassCurveParams(CurveParams[Coord]):
    """Parameters for curves of the form y^2 = x^3 + ax + b."""

    a: Coord
    b: Coord


@dataclass(frozen=True, kw_only=True)
class TwistedEdwardsCurveParams(CurveParams[int]):
    """Parameters for curves of the form ax^2 + y^2 = 1 + dx^2y^2."""

    a: int
    d: int


@dataclass(frozen=True, kw_only=True)
class MontgomeryCurveParams(CurveParams[int]):
    """Parameters for curves of the form Bv^2 = u^3 + Au^2 + u."""

    a: int
    b: int
