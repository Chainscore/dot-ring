from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, cast

from dot_ring.curve.native_field.vector_ops import vect_add, vect_mul, vect_sub
from dot_ring.curve.specs.bandersnatch import BandersnatchParams
from dot_ring.ring_proof.constants import S_PRIME, SeedPoint
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.polynomial.fft import evaluate_poly_fft
from dot_ring.ring_proof.polynomial.ops import lagrange_basis_polynomial


def _to_radix(vec: Sequence[int], radix_domain_size: int, radix_omega: int) -> list[int]:
    """Convert a radix‑2 evaluation vector to radix‑domain evaluations."""
    return cast(list[int], evaluate_poly_fft(list(vec), radix_domain_size, radix_omega, S_PRIME))


def _shift(vec: Sequence[int], shift: int) -> list[int]:
    """Rotate vector right by shift (≈ multiply index by ω)."""
    return list(vec[shift:]) + list(vec[:shift])


@lru_cache(maxsize=16)
def _constraint_context(params: RingProofParams) -> dict[str, Any]:
    domain = params.domain
    radix_domain = params.radix_domain
    last_index = params.last_index
    not_last = vect_sub(radix_domain, pow(params.omega, last_index, S_PRIME), S_PRIME)
    l0_coeffs = lagrange_basis_polynomial(domain, 0, S_PRIME)
    ln_coeffs = lagrange_basis_polynomial(domain, last_index, S_PRIME)
    l0_radix = cast(list[int], evaluate_poly_fft(l0_coeffs, params.radix_domain_size, params.radix_omega, S_PRIME))
    ln_radix = cast(list[int], evaluate_poly_fft(ln_coeffs, params.radix_domain_size, params.radix_omega, S_PRIME))
    return {
        "radix_domain": radix_domain,
        "shift": params.radix_shift,
        "not_last": not_last,
        "l0_radix": l0_radix,
        "ln_radix": ln_radix,
    }


@dataclass(slots=True)
class RingConstraintBuilder:
    """Compute c₁ₓ … c₇ₓ evaluation vectors from column evaluations."""

    Result_plus_Seed: Any
    # radix‑2 evaluation vectors coming from Column objects
    px: Sequence[int]
    py: Sequence[int]
    s: Sequence[int]
    b: Sequence[int]
    acc_x: Sequence[int]
    acc_y: Sequence[int]
    acc_ip: Sequence[int]
    params: RingProofParams = field(default_factory=RingProofParams, repr=False)

    _px4: list[int] = field(init=False, repr=False)
    _py4: list[int] = field(init=False, repr=False)
    _s4: list[int] = field(init=False, repr=False)
    _b4: list[int] = field(init=False, repr=False)
    _accx4: list[int] = field(init=False, repr=False)
    _accy4: list[int] = field(init=False, repr=False)
    _accip4: list[int] = field(init=False, repr=False)
    _ctx: dict[str, Any] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._ctx = _constraint_context(self.params)
        radix_domain = self._ctx["radix_domain"]
        self._px4 = _to_radix(self.px, len(radix_domain), self.params.radix_omega)
        self._py4 = _to_radix(self.py, len(radix_domain), self.params.radix_omega)
        self._s4 = _to_radix(self.s, len(radix_domain), self.params.radix_omega)
        self._b4 = _to_radix(self.b, len(radix_domain), self.params.radix_omega)
        self._accx4 = _to_radix(self.acc_x, len(radix_domain), self.params.radix_omega)
        self._accy4 = _to_radix(self.acc_y, len(radix_domain), self.params.radix_omega)
        self._accip4 = _to_radix(self.acc_ip, len(radix_domain), self.params.radix_omega)

    # convenient classmethod for Column builders
    @classmethod
    def from_columns(cls, columns: Mapping[str, Sequence[int]], Result_plus_Seed: Any) -> RingConstraintBuilder:
        return cls(
            Result_plus_Seed=Result_plus_Seed,
            acc_ip=columns["accip"],
            b=columns["b"],
            s=columns["s"],
            acc_x=columns["accx"],
            acc_y=columns["accy"],
            px=columns["Px"],
            py=columns["Py"],
        )

    def compute(self) -> dict[str, list[int]]:
        return {
            "c1x": self._c1(),
            "c2x": self._c2()[0],
            "c3x": self._c2()[1],
            "c4x": self._c4(),
            "c5x": self._c5()[0],
            "c6x": self._c5()[1],
            "c7x": self._c7(),
        }

    compute_all = compute  # alias

    def _c1(self) -> list[int]:
        accip_w = _shift(self._accip4, self._ctx["shift"])
        constraint = vect_sub(
            vect_sub(accip_w, self._accip4, S_PRIME),
            vect_mul(self._b4, self._s4, S_PRIME),
            S_PRIME,
        )
        c1x = vect_mul(constraint, self._ctx["not_last"], S_PRIME)
        return c1x

    def _c2(self) -> list[list[int]]:
        bx = self._b4

        accx_w = _shift(self._accx4, self._ctx["shift"])
        accy_w = _shift(self._accy4, self._ctx["shift"])
        te_coeff_a = BandersnatchParams.EDWARDS_A  # BandersnatchParams.EDWARDS_A % S_PRIME
        b = bx
        x1, x2, x3 = self._accx4, self._px4, accx_w
        y1, y2, y3 = self._accy4, self._py4, accy_w
        # b(x_3(y_1. y_2 + ax_1 .x_2) - x_1.y_1 - y_2.x_2) + (1 - b)(x_3 - x_1) = 0
        # => b(x_3(y_1. y_2 + ax_1 .x_2) - (x_1.y_1 + y_2.x_2)) + (1 - b)(x_3 - x_1) = 0

        y1_y2 = vect_mul(y1, y2, S_PRIME)
        a_x1_x2 = vect_mul(te_coeff_a, vect_mul(x1, x2, S_PRIME), S_PRIME)
        x1_y1 = vect_mul(x1, y1, S_PRIME)
        y2_x2 = vect_mul(y2, x2, S_PRIME)
        one_m_b = vect_sub(1, b, S_PRIME)
        x3_m_x1 = vect_sub(x3, x1, S_PRIME)

        term1 = vect_mul(x3, vect_add(y1_y2, a_x1_x2, S_PRIME), S_PRIME)
        term2 = vect_mul(b, vect_sub(term1, vect_add(x1_y1, y2_x2, S_PRIME), S_PRIME), S_PRIME)
        term3 = vect_add(term2, vect_mul(one_m_b, x3_m_x1, S_PRIME), S_PRIME)
        c2x = vect_mul(term3, self._ctx["not_last"], S_PRIME)

        # print("c2x here", c2x)
        # accx_m_px = vect_sub(self._accx4, self._px4, S_PRIME)
        # accx_m_px_sq = vect_mul(accx_m_px, accx_m_px, S_PRIME)
        # py_m_accy = vect_sub(self._py4, self._accy4, S_PRIME)
        # accx_w_m_accx = vect_sub(accx_w, self._accx4, S_PRIME)
        # term1 = vect_mul(
        #     accx_m_px_sq,
        #     vect_add(vect_add(self._accx4, self._px4, S_PRIME), accx_w, S_PRIME),
        #     S_PRIME,
        # )
        #
        # term2 = vect_mul(py_m_accy, py_m_accy, S_PRIME)
        # c2_base = vect_add(
        #     vect_mul(bx, vect_sub(term1, term2, S_PRIME), S_PRIME),
        #     vect_mul(one_m_bx, vect_sub(accx_w, self._accx4, S_PRIME), S_PRIME),
        #     S_PRIME,
        # )
        #
        # c2x = vect_mul(c2_base, _NOT_LAST, S_PRIME)
        # c3_base = vect_add(
        #     vect_mul(
        #         bx,
        #         vect_sub(
        #             vect_mul(accx_m_px, vect_add(accy_w, self._accy4, S_PRIME), S_PRIME),
        #             vect_mul(py_m_accy, accx_w_m_accx, S_PRIME),
        #             S_PRIME,
        #         ),
        #         S_PRIME,
        #     ),
        #     vect_mul(one_m_bx, accx_w_m_accx, S_PRIME),
        #     S_PRIME,
        # )
        # c3x = vect_mul(c3_base, _NOT_LAST, S_PRIME)

        # // b(y_3(x_1.y_2 - x_2.y_1) - x_1.y_1 + x_2.y_2) + (1 - b)(y_3 - y_1) = 0
        # => b(y_3(x_1.y_2 - x_2.y_1) - (x_1.y_1 - x_2.y_2) + (1 - b)(y_3 - y_1) = 0

        x1_y2 = vect_mul(x1, y2, S_PRIME)
        x2_y1 = vect_mul(x2, y1, S_PRIME)
        y3_m_y1 = vect_sub(y3, y1, S_PRIME)

        term1 = vect_mul(y3, vect_sub(x1_y2, x2_y1, S_PRIME), S_PRIME)
        term2 = vect_mul(b, vect_sub(term1, vect_sub(x1_y1, y2_x2, S_PRIME), S_PRIME), S_PRIME)
        term3 = vect_add(term2, vect_mul(one_m_b, y3_m_y1, S_PRIME), S_PRIME)
        c3x = vect_mul(term3, self._ctx["not_last"], S_PRIME)
        return [c2x, c3x]

    def _c4(self) -> list[int]:
        one_m_bx = vect_sub(1, self._b4, S_PRIME)
        c4x = vect_mul(self._b4, one_m_bx, S_PRIME)
        return c4x

    def _c5(self) -> list[list[int]]:
        # seed_x, seed_y = sw.from_twisted_edwards(SeedPoint)
        seed_x, seed_y = SeedPoint

        # print("seed_here",(seed_x, seed_y))

        rx_psx, ry_psy = self.Result_plus_Seed  # try using Relation to proove

        # print("result here:", rx_psx, ry_psy)

        l0_rad4 = self._ctx["l0_radix"]
        ln4_rad4 = self._ctx["ln_radix"]

        c5x = vect_add(
            vect_mul(vect_sub(self._accx4, seed_x, S_PRIME), l0_rad4, S_PRIME),
            vect_mul(vect_sub(self._accx4, rx_psx, S_PRIME), ln4_rad4, S_PRIME),
            S_PRIME,
        )

        c6x = vect_add(
            vect_mul(vect_sub(self._accy4, seed_y, S_PRIME), l0_rad4, S_PRIME),
            vect_mul(vect_sub(self._accy4, ry_psy, S_PRIME), ln4_rad4, S_PRIME),
            S_PRIME,
        )

        return [c5x, c6x]

    def _c7(self) -> list[int]:
        l0_rad4 = self._ctx["l0_radix"]
        ln4_rad4 = self._ctx["ln_radix"]

        c7x = vect_add(
            vect_mul(self._accip4, l0_rad4, S_PRIME),
            vect_mul(vect_sub(self._accip4, 1, S_PRIME), ln4_rad4, S_PRIME),
            S_PRIME,
        )
        return c7x


__all__ = ["RingConstraintBuilder"]
