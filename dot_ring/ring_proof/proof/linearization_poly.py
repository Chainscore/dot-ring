from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.polynomial.ops import poly_add, poly_evaluate_single, poly_scalar_mul
from dot_ring.ring_proof.transcript.phases import phase2_eval_point
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript


class LAggPoly:
    def __init__(
        self,
        cur_t: FiatShamirTranscript,
        C_q: list[int],
        fixed_cols: list[Column],
        witness_res: list[Column],
        alphas: list[int],
        domain: list[int],
        omega: int,
        prime: int = S_PRIME,
        padding_rows: int = 4,
        edwards_a: int = -5,
    ) -> None:
        self.t, self.zeta = phase2_eval_point(cur_t, C_q)
        self.prime = prime
        self.zeta_omega = (self.zeta * omega) % self.prime
        last_index = len(domain) - padding_rows
        self.scalar_term = (self.zeta - domain[last_index]) % self.prime
        self.fs = fixed_cols
        self.wts = witness_res
        self.alphas = alphas
        self.a = edwards_a

    def evaluate_polys_at_zeta(self) -> None:
        if self.fs[0].coeffs is None or self.fs[1].coeffs is None or self.fs[2].coeffs is None:
            raise ValueError("Fixed columns not interpolated")
        if self.wts[0].coeffs is None or self.wts[1].coeffs is None or self.wts[2].coeffs is None or self.wts[3].coeffs is None:
            raise ValueError("Witness columns not interpolated")

        self.P_x_zeta = poly_evaluate_single(self.fs[0].coeffs, self.zeta, self.prime)
        self.P_y_zeta = poly_evaluate_single(self.fs[1].coeffs, self.zeta, self.prime)
        self.s_zeta = poly_evaluate_single(self.fs[2].coeffs, self.zeta, self.prime)
        self.b_zeta = poly_evaluate_single(self.wts[0].coeffs, self.zeta, self.prime)
        self.acc_ip_zeta = poly_evaluate_single(self.wts[3].coeffs, self.zeta, self.prime)
        self.acc_x_zeta = poly_evaluate_single(self.wts[1].coeffs, self.zeta, self.prime)
        self.acc_y_zeta = poly_evaluate_single(self.wts[2].coeffs, self.zeta, self.prime)

    def compute_l1(self) -> list[int]:
        if self.wts[3].coeffs is None:
            raise ValueError("Witness column 3 not interpolated")
        return poly_scalar_mul(self.wts[3].coeffs, self.scalar_term, self.prime)

    def compute_l2(self) -> list[int]:
        x1, y1 = self.acc_x_zeta, self.acc_y_zeta
        x2, y2 = self.P_x_zeta, self.P_y_zeta
        b = self.b_zeta
        coeff_a = self.a

        C_acc_x = (b * (y1 * y2 + (coeff_a * x1 * x2)) % self.prime + (1 - b) % self.prime) % self.prime
        C_acc_x_f = C_acc_x * self.scalar_term

        if self.wts[1].coeffs is None or self.wts[2].coeffs is None:
            raise ValueError("Witness columns not interpolated")
        return poly_scalar_mul(self.wts[1].coeffs, C_acc_x_f, self.prime)

    def compute_l3(self) -> list[int]:
        b = self.b_zeta
        x1, y1 = self.acc_x_zeta, self.acc_y_zeta
        x2, y2 = self.P_x_zeta, self.P_y_zeta
        C_acc_y = ((b * (x1 * y2 - x2 * y1)) % self.prime + (1 - b) % self.prime) % self.prime
        C_acc_y *= self.scalar_term

        if self.wts[1].coeffs is None or self.wts[2].coeffs is None:
            raise ValueError("Witness columns not interpolated")
        return poly_scalar_mul(self.wts[2].coeffs, C_acc_y, self.prime)

    def linearize(self, l1: list[int], l2: list[int], l3: list[int]) -> list[int]:
        l_agg = [0]
        for poly, scalar in zip([l1, l2, l3], self.alphas[:3], strict=True):
            l_agg = poly_add(l_agg, poly_scalar_mul(poly, scalar, self.prime), self.prime)
        return l_agg

    def l_agg_poly(self) -> tuple[FiatShamirTranscript, int, dict[str, int], list[int], int, int]:
        self.evaluate_polys_at_zeta()  # fills P_x_zeta … acc_y_zeta
        l1 = self.compute_l1()
        l2 = self.compute_l2()
        l3 = self.compute_l3()
        l_agg = self.linearize(l1, l2, l3)

        l_agg_zeta_omega = poly_evaluate_single(l_agg, self.zeta_omega, self.prime)
        return (
            self.t,
            self.zeta,
            {
                # "Zeta":self.zeta,
                "P_x_zeta": self.P_x_zeta,
                "P_y_zeta": self.P_y_zeta,
                "s_zeta": self.s_zeta,
                "b_zeta": self.b_zeta,
                "acc_ip_zeta": self.acc_ip_zeta,
                "acc_x_zeta": self.acc_x_zeta,
                "acc_y_zeta": self.acc_y_zeta,
                # "l_agg_zeta_omega": l_agg_zeta_omega,
            },
            l_agg,
            self.zeta_omega,
            l_agg_zeta_omega,
        )
