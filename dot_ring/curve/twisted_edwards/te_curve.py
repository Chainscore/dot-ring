from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import invert as _invert
from gmpy2 import mpz as _mpz

from dot_ring.curve.curve import Curve
from dot_ring.curve.specs.parameters import TwistedEdwardsCurveParams


@dataclass(frozen=True, kw_only=True)
class TECurve(Curve[int]):
    """
    Twisted Edwards Curve implementation.

    A Twisted Edwards curve is defined by the equation:
    ax² + y² = 1 + dx²y²

    where a, d are distinct, non-zero elements of the field.

    Attributes:
        params: Twisted Edwards curve-suite constants.
    """

    params: TwistedEdwardsCurveParams

    def __post_init__(self) -> None:
        """Validate curve parameters after initialization."""
        super().__post_init__()
        self._validate()

    def _validate(self):
        """
        Validate Twisted Edwards specific parameters.

        Returns:
            bool: True if parameters are valid
        """
        if not (
            self.params.a != 0
            and self.params.d != 0
            and self.params.a != self.params.d
            and all(x < self.params.field_modulus for x in (self.params.a, self.params.d))
        ):
            raise ValueError("Invalid Twisted Edwards curve parameters")

    def map_to_curve_ell2(self, u: int) -> tuple[int, int]:
        """
        Elligator 2 map to curve implementation.

        Args:
            u: Field element to map

        Returns:
            Point: Point on Montgomery curve
        """
        p = self.params.field_modulus
        map_curve = self.params.hash_to_curve.elligator2_map
        if map_curve is None:
            raise ValueError("Elligator 2 requires hash_to_curve.elligator2_map")
        montgomery_a_over_b = (map_curve.a * pow(map_curve.b, -1, p)) % p
        inv_b_squared = pow((map_curve.b * map_curve.b) % p, -1, p)

        pm = _mpz(p)
        um = _mpz(u)
        a_over_b = _mpz(montgomery_a_over_b)
        inv_b_squared_m = _mpz(inv_b_squared)
        map_b = _mpz(map_curve.b)
        zm = _mpz(self.params.hash_to_curve.z)

        tv1 = (zm * um * um) % pm
        if tv1 == -1 or tv1 == pm - 1:
            tv1 = _mpz(0)

        x1 = (-a_over_b * _invert(tv1 + 1, pm)) % pm
        gx1 = (((x1 + a_over_b) * x1 + inv_b_squared_m) * x1) % pm
        x2 = (-x1 - a_over_b) % pm
        gx2 = (tv1 * gx1) % pm

        e2 = self.is_square(int(gx1))
        if e2:
            x = x1
            y2 = gx1
        else:
            x = x2
            y2 = gx2

        y = self.mod_sqrt(int(y2))
        ym = _mpz(y)
        e3 = (ym % 2) == 1
        if e2 ^ e3:
            ym = -ym % pm

        return int((x * map_b) % pm), int((ym * map_b) % pm)