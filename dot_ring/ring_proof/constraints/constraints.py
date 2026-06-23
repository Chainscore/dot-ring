from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.polynomial.fft import evaluate_poly_fft
from dot_ring.ring_proof.polynomial.ops import lagrange_basis_polynomial


def _to_radix(vec: Sequence[int], radix_domain_size: int, radix_omega: int, prime: int) -> list[int]:
    """Convert a radix‑2 evaluation vector to radix‑domain evaluations."""
    return evaluate_poly_fft(list(vec), radix_domain_size, radix_omega, prime)


@dataclass(slots=True)
class RingConstraintBuilder:
    """Compute c₁ₓ … c₇ₓ evaluation vectors from column evaluations."""

    result_plus_seed: tuple[int, int]
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
    _shift: int = field(init=False, repr=False)
    _not_last: list[int] = field(init=False, repr=False)
    _l0_radix: list[int] = field(init=False, repr=False)
    _ln_radix: list[int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        domain = self.params.domain
        radix_domain = self.params.radix_domain
        last_index = self.params.last_index
        last_root = pow(self.params.omega, last_index, self.params.prime)
        l0_coeffs = lagrange_basis_polynomial(domain, 0, self.params.prime)
        ln_coeffs = lagrange_basis_polynomial(domain, last_index, self.params.prime)

        self._shift = self.params.radix_shift
        self._not_last = [(x - last_root) % self.params.prime for x in radix_domain]
        self._l0_radix = evaluate_poly_fft(l0_coeffs, len(radix_domain), self.params.radix_omega, self.params.prime)
        self._ln_radix = evaluate_poly_fft(ln_coeffs, len(radix_domain), self.params.radix_omega, self.params.prime)

        self._px4 = _to_radix(self.px, len(radix_domain), self.params.radix_omega, self.params.prime)
        self._py4 = _to_radix(self.py, len(radix_domain), self.params.radix_omega, self.params.prime)
        self._s4 = _to_radix(self.s, len(radix_domain), self.params.radix_omega, self.params.prime)
        self._b4 = _to_radix(self.b, len(radix_domain), self.params.radix_omega, self.params.prime)
        self._accx4 = _to_radix(self.acc_x, len(radix_domain), self.params.radix_omega, self.params.prime)
        self._accy4 = _to_radix(self.acc_y, len(radix_domain), self.params.radix_omega, self.params.prime)
        self._accip4 = _to_radix(self.acc_ip, len(radix_domain), self.params.radix_omega, self.params.prime)

    def compute(self) -> dict[str, list[int]]:
        c2x, c3x = self._c2_c3()
        c5x, c6x = self._c5_c6()
        return {
            "c1x": self._c1(),
            "c2x": c2x,
            "c3x": c3x,
            "c4x": self._c4(),
            "c5x": c5x,
            "c6x": c6x,
            "c7x": self._c7(),
        }

    def _shifted_index(self, index: int) -> int:
        shifted = index + self._shift
        if shifted >= len(self._px4):
            shifted -= len(self._px4)
        return shifted

    def _c1(self) -> list[int]:
        """Inner-product accumulator transition."""
        prime = self.params.prime
        result: list[int] = []
        for i, (accip_i, b_i, s_i, not_last_i) in enumerate(zip(self._accip4, self._b4, self._s4, self._not_last, strict=True)):
            accip_w = self._accip4[self._shifted_index(i)]
            result.append(((accip_w - accip_i - b_i * s_i) * not_last_i) % prime)
        return result

    def _c2_c3(self) -> tuple[list[int], list[int]]:
        """Twisted-Edwards x/y accumulator transition constraints."""
        prime = self.params.prime
        te_coeff_a = self.params.cv.curve.params.a
        c2: list[int] = []
        c3: list[int] = []

        for i in range(len(self._px4)):
            shifted = self._shifted_index(i)
            x1 = self._accx4[i]
            y1 = self._accy4[i]
            x2 = self._px4[i]
            y2 = self._py4[i]
            x3 = self._accx4[shifted]
            y3 = self._accy4[shifted]
            b_i = self._b4[i]
            not_last_i = self._not_last[i]

            one_minus_b = (1 - b_i) % prime
            x1_y1 = (x1 * y1) % prime
            y2_x2 = (y2 * x2) % prime

            x_transition = (y1 * y2 + te_coeff_a * x1 * x2) % prime
            x_transition = (x3 * x_transition - (x1_y1 + y2_x2)) % prime
            x_transition = (b_i * x_transition + one_minus_b * (x3 - x1)) % prime
            c2.append((x_transition * not_last_i) % prime)

            y_transition = (x1 * y2 - x2 * y1) % prime
            y_transition = (y3 * y_transition - (x1_y1 - y2_x2)) % prime
            y_transition = (b_i * y_transition + one_minus_b * (y3 - y1)) % prime
            c3.append((y_transition * not_last_i) % prime)

        return c2, c3

    def _c4(self) -> list[int]:
        """Booleanity constraint for b."""
        prime = self.params.prime
        return [(b_i * (1 - b_i)) % prime for b_i in self._b4]

    def _c5_c6(self) -> tuple[list[int], list[int]]:
        """Accumulator boundary constraints for x/y coordinates."""
        prime = self.params.prime
        seed_x, seed_y = self.params.cv.curve.params.auxiliary_points.accumulator_base
        result_x, result_y = self.result_plus_seed
        c5: list[int] = []
        c6: list[int] = []

        for accx_i, accy_i, l0_i, ln_i in zip(self._accx4, self._accy4, self._l0_radix, self._ln_radix, strict=True):
            c5.append(((accx_i - seed_x) * l0_i + (accx_i - result_x) * ln_i) % prime)
            c6.append(((accy_i - seed_y) * l0_i + (accy_i - result_y) * ln_i) % prime)

        return c5, c6

    def _c7(self) -> list[int]:
        """Inner-product accumulator boundary constraint."""
        prime = self.params.prime
        result: list[int] = []
        for accip_i, l0_i, ln_i in zip(self._accip4, self._l0_radix, self._ln_radix, strict=True):
            result.append((accip_i * l0_i + (accip_i - 1) * ln_i) % prime)
        return result


__all__ = ["RingConstraintBuilder"]
