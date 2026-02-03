from functools import cache
from typing import Any, cast

from py_ecc.optimized_bls12_381 import (  # type: ignore[import-untyped]
    curve_order,
)
from py_ecc.optimized_bls12_381 import (
    normalize as nm,
)

from dot_ring import blst as _blst
from dot_ring.curve.native_field.scalar import Scalar
from dot_ring.curve.specs.bandersnatch import BandersnatchParams
from dot_ring.ring_proof.constants import D_512 as D
from dot_ring.ring_proof.constants import OMEGA_512 as OMEGA, OMEGA_2048, S_PRIME
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

# Pre-compute Scalar constants
ONE_S = Scalar(1)
ZERO_S = Scalar(0)
EDWARDS_A_S = Scalar(BandersnatchParams.EDWARDS_A)


def blst_msm(points: list, scalars: list) -> Any:
    """
    Multi-scalar multiplication using Pippenger's algorithm via blst.
    Much faster than individual scalar_mul + add operations.
    """
    if not points:
        return blst.P1()

    return blst.P1_Affines.mult_pippenger(blst.P1_Affines.as_memory(points), scalars)


@cache
def lagrange_at_zeta(domain_size: int, index: int, zeta: int, omega: int, prime: int) -> Scalar:
    """
    Compute L_i(zeta) using closed-form formula for roots of unity domain.

    L_i(zeta) = (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)

    This is O(1) instead of O(n) polynomial evaluation!
    """
    # Use Scalar for optimized arithmetic
    zeta_s = Scalar(zeta)

    omega_s = Scalar(omega)
    # omega^i
    if index == 0:
        omega_i = ONE_S
    else:
        omega_i = omega_s**index

    # zeta - omega^i
    zeta_minus_omega_i = zeta_s - omega_i

    # Handle special case when zeta == omega^i
    if zeta_minus_omega_i == ZERO_S:
        return ONE_S  # L_i(omega^i) = 1

    # zeta^n - 1
    zeta_n_minus_1 = (zeta_s**domain_size) - ONE_S

    # omega^i / n
    inv_size = Scalar(domain_size) ** -1
    omega_i_over_n = omega_i * inv_size

    # Final: (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)
    result = omega_i_over_n * zeta_n_minus_1 * (zeta_minus_omega_i**-1)

    return result


class Verify:
    def __init__(
        self,
        proof: tuple,
        vk: dict | bytes,
        fixed_cols: list,
        rl_to_proove: tuple | bytes,
        rps: tuple,
        seed_point: tuple,
        Domain: list,
        raw_proof_bytes: dict | None = None,
        transcript_challenge: bytes = b"Bandersnatch_SHA-512_ELL2",
        padding_rows: int = 4,
    ) -> None:
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
        self.padding_rows = padding_rows
        if self.padding_rows < 1 or self.padding_rows >= len(self.D):
            raise ValueError("padding_rows must be >= 1 and less than domain size")
        self.last_index = len(self.D) - self.padding_rows

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

        self.t = Transcript(S_PRIME, transcript_challenge)

        # Absorb into transcript
        self.t, self.alpha_list = phase1_alphas(
            self.t,
            self.verifier_key,
            self.relation_to_proove,
            list(H.to_int(nm(cmt)) for cmt in self.proof_ptr[:4]),
        )

        # Add quotient and get zeta
        self.t, self.zeta_p = phase2_eval_point(self.t, H.to_int(nm(self.proof_ptr[-4])))

        # Phase 3: Add evaluations and get ν challenges
        evals_bytes = b"".join(v.to_bytes(32, "little") for v in self.proof_ptr[4:11])
        lin_eval_bytes = self.proof_ptr[-3].to_bytes(32, "little")

        self.V_list = phase3_nu_vector(self.t, evals_bytes, lin_eval_bytes)

        # Save transcript
        self.cur_t = self.t

    def contributions_to_constraints_eval_at_zeta(
        self,
    ) -> tuple[Scalar, Scalar, Scalar, Scalar, Scalar, Scalar, Scalar]:
        # Convert to Scalar for optimized arithmetic
        zeta = Scalar(self.zeta_p)
        sx, sy = Scalar(self.sp[0]), Scalar(self.sp[1])

        # Precompute common values
        zeta_minus_d4 = zeta - Scalar(self.D[self.last_index])

        # Inline lagrange_at_zeta for index=0 and index=SIZE-4
        # L_i(zeta) = (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)

        # Shared term: zeta^n - 1
        domain_size = len(self.D)
        zeta_n_minus_1 = (zeta**domain_size) - ONE_S

        # L_0: index=0, omega^0 = 1
        # omega^0 / n = 1/n = INV_SIZE_S
        # zeta - omega^0 = zeta - 1
        inv_size = Scalar(domain_size) ** -1
        zeta_minus_1 = zeta - ONE_S
        if zeta_minus_1 == ZERO_S:
            L_0_zeta = ONE_S
        else:
            L_0_zeta = inv_size * zeta_n_minus_1 * (zeta_minus_1**-1)

        # L_N_4: index=SIZE-4, omega^(SIZE-4) from the domain
        # omega^(SIZE-4) / n
        omega_i_N_4 = Scalar(self.D[self.last_index])
        omega_i_over_n_N_4 = omega_i_N_4 * inv_size
        zeta_minus_omega_i_N_4 = zeta - omega_i_N_4
        if zeta_minus_omega_i_N_4 == ZERO_S:
            L_N_4_zeta = ONE_S
        else:
            L_N_4_zeta = omega_i_over_n_N_4 * zeta_n_minus_1 * (zeta_minus_omega_i_N_4**-1)

        # Pre-fetch instance variables and convert to Scalar
        b = Scalar(self.b_zeta)
        accx = Scalar(self.accx_zeta)
        accy = Scalar(self.accy_zeta)
        accip = Scalar(self.accip_zeta)
        px = Scalar(self.px_zeta)
        py = Scalar(self.py_zeta)
        s = Scalar(self.s_zeta)
        rps0 = Scalar(self.Result_plus_Seed[0])
        rps1 = Scalar(self.Result_plus_Seed[1])

        # Constraint 1 - combined operations
        c1_zeta = -(accip + b * s) * zeta_minus_d4

        # Constraints 2 and 3 - reuse calculations
        x1_y1 = accx * accy
        x2_y2 = px * py
        one_minus_b = ONE_S - b

        c2 = b * -(x1_y1 + x2_y2) + one_minus_b * -accx
        c2_zeta = c2 * zeta_minus_d4

        c3 = b * -(x1_y1 - x2_y2) + one_minus_b * -accy
        c3_zeta = c3 * zeta_minus_d4

        # Constraint 4 - simplified
        c4_zeta = b * (ONE_S - b)

        # Constraints 5-7 - combined operations
        c5_zeta = (accx - sx) * L_0_zeta + (accx - rps0) * L_N_4_zeta
        c6_zeta = (accy - sy) * L_0_zeta + (accy - rps1) * L_N_4_zeta
        c7_zeta = accip * L_0_zeta + (accip - ONE_S) * L_N_4_zeta

        return (
            c1_zeta,
            c2_zeta,
            c3_zeta,
            c4_zeta,
            c5_zeta,
            c6_zeta,
            c7_zeta,
        )

    def divide(self, numr: int, denom: int) -> int:
        # Inlined modular division - use built-in pow (faster than external call)
        return (numr * pow(denom, -1, curve_order)) % curve_order

    def is_valid(self) -> bool:
        """If both the verifications are true then sign is valid"""
        verification1 = self._prepare_quotient_poly_verification()
        verification2 = self._prepare_linearization_poly_verification()
        return KZG.batch_verify([verification1, verification2])

    def _prepare_quotient_poly_verification(self) -> tuple[Any, Any, int, int]:
        """Prepare KZG verification data for quotient polynomial"""
        alphas_list = [Scalar(a) for a in self.alpha_list]
        zeta = Scalar(self.zeta_p)
        v_list = [Scalar(v) for v in self.V_list]

        # cs are now Scalars
        cs = self.contributions_to_constraints_eval_at_zeta()

        # Precompute vanishing polynomial evaluation - combine pow operations
        prod_sum = ONE_S
        for k in range(1, 4):
            prod_sum = prod_sum * (zeta - Scalar(self.D[-k]))

        # Calculate numerator efficiently
        linear_combination = ZERO_S
        for alpha, c in zip(alphas_list, cs, strict=False):
            linear_combination = linear_combination + alpha * c

        # Re-calculating based on original quotient definition, but with optimized s_sum
        s_sum = linear_combination + Scalar(self.l_zeta_omega)
        domain_size = len(self.D)
        zeta_pow_size_minus_1 = (zeta**domain_size) - ONE_S

        # q_zeta = (s_sum * prod_sum) / zeta_pow_size_minus_1
        q_zeta = (s_sum * prod_sum) * (zeta_pow_size_minus_1**-1)

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
        # Use self.V_list (ints) directly for blst_msm
        C_agg = blst_msm(C_a_blst, self.V_list)

        # Use Scalars for terms calculation
        px = Scalar(self.px_zeta)
        py = Scalar(self.py_zeta)
        s = Scalar(self.s_zeta)
        b = Scalar(self.b_zeta)
        accip = Scalar(self.accip_zeta)
        accx = Scalar(self.accx_zeta)
        accy = Scalar(self.accy_zeta)
        q = q_zeta  # Scalar

        terms = [
            v_list[0] * px,
            v_list[1] * py,
            v_list[2] * s,
            v_list[3] * b,
            v_list[4] * accip,
            v_list[5] * accx,
            v_list[6] * accy,
            v_list[7] * q,
        ]

        Agg_zeta = Scalar(0)
        for t in terms:
            Agg_zeta = Agg_zeta + t

        return (C_agg, self.Phi_zeta_blst, int(zeta), int(Agg_zeta))

    def _prepare_linearization_poly_verification(self) -> tuple[Any, Any, int, int]:
        """Prepare KZG verification data for linearization polynomial"""
        alphas_list = [Scalar(a) for a in self.alpha_list]
        zeta = Scalar(self.zeta_p)

        zeta_minus_d4 = zeta - Scalar(self.D[self.last_index])

        # Cl1 scalar
        scalar_cl1 = zeta_minus_d4

        # Cl2 scalars
        x1, y1 = Scalar(self.accx_zeta), Scalar(self.accy_zeta)
        x2, y2 = Scalar(self.px_zeta), Scalar(self.py_zeta)
        b = Scalar(self.b_zeta)
        coeff_a = EDWARDS_A_S

        # S_PRIME is scalar field modulus, which Scalar handles implicitly

        C_acc_x_cl2 = b * (y1 * y2 + (coeff_a * x1 * x2)) + (ONE_S - b)
        C_acc_x_f_cl2 = C_acc_x_cl2 * zeta_minus_d4

        # Cl3 scalars
        C_acc_y_cl3 = (b * (x1 * y2 - x2 * y1)) + (ONE_S - b)
        C_acc_y_f_cl3 = C_acc_y_cl3 * zeta_minus_d4

        # Combined scalars
        scalar_accip = alphas_list[0] * scalar_cl1
        scalar_accx = alphas_list[1] * C_acc_x_f_cl2
        scalar_accy = alphas_list[2] * C_acc_y_f_cl3

        # Use MSM for the final combination
        points = [self.Caccip_blst, self.Caccx_blst, self.Caccy_blst]
        scalars = [int(scalar_accip), int(scalar_accx), int(scalar_accy)]
        Cl = blst_msm(points, scalars)

        # Compute omega for the actual domain size
        domain_size = len(self.D)
        if domain_size == 512:
            omega = OMEGA
        elif domain_size == 1024:
            omega = pow(OMEGA_2048, 2048 // 1024, S_PRIME)
        elif domain_size == 2048:
            omega = OMEGA_2048
        else:
            # Fallback: compute from OMEGA_2048
            omega = pow(OMEGA_2048, 2048 // domain_size, S_PRIME)

        zeta_omega = zeta * Scalar(omega)

        return (Cl, self.Phi_zeta_omega_blst, int(zeta_omega), int(Scalar(self.l_zeta_omega)))

    # Legacy methods for backwards compatibility
    def evaluation_of_quotient_poly_at_zeta(self) -> bool:
        """Legacy method - use is_valid() with batch verification instead"""
        raise NotImplementedError("Use is_valid() with batch verification instead")

    def evaluation_of_linearization_poly_at_zeta_omega(self) -> bool:
        """Legacy method - use is_valid() with batch verification instead"""
        raise NotImplementedError("Use is_valid() with batch verification instead")
