from typing import Any, cast

from py_ecc.optimized_bls12_381 import curve_order  # type: ignore[import-untyped]
from py_ecc.optimized_bls12_381 import normalize as nm  # type: ignore[import-untyped]

from dot_ring import blst as _blst  # type: ignore[import-untyped]
from dot_ring.curve.specs.bandersnatch import BandersnatchParams
from dot_ring.ring_proof.constants import D_512 as D
from dot_ring.ring_proof.constants import OMEGA, S_PRIME, SIZE
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.utils import g1_to_blst
from dot_ring.ring_proof.transcript.phases import (
    phase1_alphas,
    phase2_eval_point,
    phase3_nu_vector,
)
from dot_ring.ring_proof.transcript.transcript import Transcript

blst = cast(Any, _blst)


def blst_msm(points: list, scalars: list) -> Any:
    """
    Multi-scalar multiplication using Pippenger's algorithm via blst.
    Much faster than individual scalar_mul + add operations.
    """
    if not points:
        return blst.P1()

    # Use Pippenger MSM
    memory = blst.P1_Affines.as_memory(points)
    return blst.P1_Affines.mult_pippenger(memory, scalars)


def lagrange_at_zeta(domain_size: int, index: int, zeta: int, omega: int, prime: int) -> int:
    """
    Compute L_i(zeta) using closed-form formula for roots of unity domain.

    L_i(zeta) = (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)

    This is O(1) instead of O(n) polynomial evaluation!
    """
    n = domain_size
    omega_i = pow(omega, index, prime)

    # zeta^n - 1
    zeta_n_minus_1 = (pow(zeta, n, prime) - 1) % prime

    # zeta - omega^i
    zeta_minus_omega_i = (zeta - omega_i) % prime

    # Handle special case when zeta == omega^i
    if zeta_minus_omega_i == 0:
        return 1  # L_i(omega^i) = 1

    # omega^i / n
    inv_n = pow(n, -1, prime)
    omega_i_over_n = (omega_i * inv_n) % prime

    # Final: (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)
    numerator = (omega_i_over_n * zeta_n_minus_1) % prime
    result = (numerator * pow(zeta_minus_omega_i, -1, prime)) % prime

    return result


class Verify:
    def __init__(self, proof: tuple, vk: dict, fixed_cols: list, rl_to_proove: tuple, rps: tuple, seed_point: tuple, Domain: list) -> None:
        (
            self.Cb,
            self.Caccip,
            self.Caccx,
            self.Caccy,
            self.px_zeta,
            self.py_zeta,
            self.s_zeta,
            self.b_zeta,
            self.accip_zeta,
            self.accx_zeta,
            self.accy_zeta,
            self.Cq,
            self.l_zeta_omega,
            self.Phi_zeta,
            self.Phi_zeta_omega,
        ) = proof

        self.proof_ptr = proof
        self.verifier_key = vk
        self.Cpx, self.Cpy, self.Cs = fixed_cols
        self.relation_to_proove = rl_to_proove
        self.Result_plus_Seed, self.sp, self.D = rps, seed_point, Domain

        self.Cb_blst = g1_to_blst(self.Cb)
        self.Caccip_blst = g1_to_blst(self.Caccip)
        self.Caccx_blst = g1_to_blst(self.Caccx)
        self.Caccy_blst = g1_to_blst(self.Caccy)
        self.Cq_blst = g1_to_blst(self.Cq)
        self.Phi_zeta_blst = g1_to_blst(self.Phi_zeta)
        self.Phi_zeta_omega_blst = g1_to_blst(self.Phi_zeta_omega)

        self.Cpx_blst = g1_to_blst(self.Cpx)
        self.Cpy_blst = g1_to_blst(self.Cpy)
        self.Cs_blst = g1_to_blst(self.Cs)

        # can even put as separate function
        self.t = Transcript(S_PRIME, b"Bandersnatch_SHA-512_ELL2")
        self.cur_t, self.alpha_list = phase1_alphas(
            self.t,
            self.verifier_key,
            self.relation_to_proove,
            list(H.to_int(nm(cmt)) for cmt in self.proof_ptr[:4]),
        )  # cb, caccip, caccx, caccy

        self.cur_t, self.zeta_p = phase2_eval_point(self.cur_t, H.to_int(nm(self.proof_ptr[-4])))
        self.V_list = phase3_nu_vector(self.cur_t, list(self.proof_ptr[4:11]), self.proof_ptr[-3])

    def contributions_to_constraints_eval_at_zeta(self) -> tuple[int, int, int, int, int, int, int]:
        zeta = self.zeta_p
        sp = self.sp
        sx, sy = sp
        MOD = curve_order

        # Precompute common values
        zeta_minus_d4 = (zeta - D[-4]) % MOD

        # Use O(1) Lagrange evaluation instead of O(n) polynomial construction + evaluation
        L_0_zeta = lagrange_at_zeta(SIZE, 0, zeta, OMEGA, MOD)
        L_N_4_zeta = lagrange_at_zeta(SIZE, SIZE - 4, zeta, OMEGA, MOD)

        # Constraint 1
        term1 = (self.b_zeta * self.s_zeta) % MOD
        inner_sum = (self.accip_zeta + term1) % MOD
        negated = (-inner_sum) % MOD
        c1_zeta = (negated * zeta_minus_d4) % MOD

        # constraint 2 and 3
        x1, y1 = self.accx_zeta, self.accy_zeta
        x2, y2 = self.px_zeta, self.py_zeta
        b = self.b_zeta
        one_minus_b = (1 - b) % MOD

        # Precompute common subexpressions
        (y1 * y2) % MOD
        (x1 * x2) % MOD
        x1_y1 = (x1 * y1) % MOD
        x2_y2 = (x2 * y2) % MOD

        c2 = (b * (-(x1_y1 + x2_y2)) + one_minus_b * (-x1)) % MOD
        c2_zeta = (c2 * zeta_minus_d4) % MOD

        c3 = (b * (-(x1_y1 - x2_y2)) + one_minus_b * (-y1)) % MOD
        c3_zeta = (c3 * zeta_minus_d4) % MOD

        # Constraint 4
        c4_zeta = (self.b_zeta * (1 - self.b_zeta)) % MOD

        # Constraint 5
        term1 = ((self.accx_zeta - sx) * L_0_zeta) % MOD
        term2 = ((self.accx_zeta - self.Result_plus_Seed[0]) * L_N_4_zeta) % MOD
        c5_zeta = (term1 + term2) % MOD

        # Constraint 6
        term1 = ((self.accy_zeta - sy) * L_0_zeta) % MOD
        term2 = ((self.accy_zeta - self.Result_plus_Seed[1]) * L_N_4_zeta) % MOD
        c6_zeta = (term1 + term2) % MOD

        # Constraint 7
        term1 = (self.accip_zeta * L_0_zeta) % MOD
        term2 = ((self.accip_zeta - 1) * L_N_4_zeta) % MOD
        c7_zeta = (term1 + term2) % MOD
        return c1_zeta, c2_zeta, c3_zeta, c4_zeta, c5_zeta, c6_zeta, c7_zeta

    def divide(self, numr: int, denom: int) -> int:
        # Use built-in pow with -1 exponent for modular inverse (faster than sympy)
        denominator_inv = pow(denom, -1, curve_order)
        q_zeta = (numr * denominator_inv) % curve_order
        return int(q_zeta)

    def is_valid(self) -> bool:
        """If both the verifications are true then sign is valid"""
        verification1 = self._prepare_quotient_poly_verification()
        verification2 = self._prepare_linearization_poly_verification()
        return KZG.batch_verify([verification1, verification2])

    def _prepare_quotient_poly_verification(self) -> tuple[Any, Any, int, int]:
        """Prepare KZG verification data for quotient polynomial"""
        alphas_list, zeta, v_list = self.alpha_list, self.zeta_p, self.V_list

        cs = self.contributions_to_constraints_eval_at_zeta()

        # Precompute vanishing polynomial evaluation
        prod_sum = 1
        for k in range(1, 4):
            cur = (zeta - self.D[-k]) % curve_order
            prod_sum = (prod_sum * cur) % curve_order

        # Accumulate constraint contributions
        s_sum = 0
        for i in range(len(alphas_list)):
            s_sum = (s_sum + alphas_list[i] * cs[i]) % curve_order

        s_sum = (s_sum + self.l_zeta_omega) % curve_order

        # Compute quotient polynomial evaluation
        zeta_pow_size_minus_1 = (pow(zeta, SIZE, curve_order) - 1) % curve_order
        q_zeta = self.divide((s_sum * prod_sum) % curve_order, zeta_pow_size_minus_1)

        C_a_blst = [
            self.Cpx_blst,
            self.Cpy_blst,
            self.Cs_blst,
            self.Cb_blst,
            self.Caccip_blst,
            self.Caccx_blst,
            self.Caccy_blst,
            self.Cq_blst,
        ]

        # Use Pippenger MSM instead of loop (much faster)
        C_agg = blst_msm(C_a_blst, v_list)

        MOD = curve_order

        terms = [
            (v_list[0] * self.px_zeta) % MOD,
            (v_list[1] * self.py_zeta) % MOD,
            (v_list[2] * self.s_zeta) % MOD,
            (v_list[3] * self.b_zeta) % MOD,
            (v_list[4] * self.accip_zeta) % MOD,
            (v_list[5] * self.accx_zeta) % MOD,
            (v_list[6] * self.accy_zeta) % MOD,
            (v_list[7] * q_zeta) % MOD,
        ]

        Agg_zeta = sum(terms) % MOD

        return (C_agg, self.Phi_zeta_blst, zeta, Agg_zeta)

    def _prepare_linearization_poly_verification(self) -> tuple[Any, Any, int, int]:
        """Prepare KZG verification data for linearization polynomial"""
        alphas_list, zeta, _v_list = self.alpha_list, self.zeta_p, self.V_list

        zeta_minus_d4 = (zeta - self.D[-4]) % curve_order

        # Cl1 scalar
        scalar_cl1 = zeta_minus_d4

        # Cl2 scalars
        x1, y1 = self.accx_zeta, self.accy_zeta
        x2, y2 = self.px_zeta, self.py_zeta
        b = self.b_zeta
        coeff_a = BandersnatchParams.EDWARDS_A

        C_acc_x_cl2 = (b * (y1 * y2 + (coeff_a * x1 * x2)) % S_PRIME + (1 - b) % S_PRIME) % S_PRIME
        C_acc_x_f_cl2 = (C_acc_x_cl2 * zeta_minus_d4) % curve_order

        # Cl3 scalars
        C_acc_y_cl3 = ((b * (x1 * y2 - x2 * y1)) % S_PRIME + (1 - b) % S_PRIME) % S_PRIME
        C_acc_y_f_cl3 = (C_acc_y_cl3 * zeta_minus_d4) % curve_order

        # Combined scalars
        scalar_accip = (alphas_list[0] * scalar_cl1) % curve_order
        scalar_accx = (alphas_list[1] * C_acc_x_f_cl2) % curve_order
        scalar_accy = (alphas_list[2] * C_acc_y_f_cl3) % curve_order

        # Use MSM for the final combination
        points = [self.Caccip_blst, self.Caccx_blst, self.Caccy_blst]
        scalars = [scalar_accip, scalar_accx, scalar_accy]
        Cl = blst_msm(points, scalars)

        zeta_omega = (zeta * OMEGA) % curve_order

        return (Cl, self.Phi_zeta_omega_blst, zeta_omega, self.l_zeta_omega)

    # Legacy methods for backwards compatibility
    def evaluation_of_quotient_poly_at_zeta(self) -> bool:
        """Legacy method - use is_valid() with batch verification instead"""
        verification = self._prepare_quotient_poly_verification()
        return KZG.verify(*verification)

    def evaluation_of_linearization_poly_at_zeta_omega(self) -> bool:
        """Legacy method - use is_valid() with batch verification instead"""
        verification = self._prepare_linearization_poly_verification()
        return KZG.verify(*verification)
