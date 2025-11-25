from dot_ring.curve.specs.bandersnatch import BandersnatchParams
from sympy import mod_inverse
from dot_ring.ring_proof.constants import S_PRIME, SIZE, D_512 as D, OMEGA
from dot_ring.ring_proof.transcript.transcript import Transcript
from dot_ring.ring_proof.transcript.phases import (
    phase1_alphas,
    phase2_eval_point,
    phase3_nu_vector,
)
from dot_ring.ring_proof.polynomial.ops import lagrange_basis_polynomial, poly_evaluate
from py_ecc.optimized_bls12_381 import normalize as nm
from dot_ring.ring_proof.pcs.kzg import KZG
from py_ecc.optimized_bls12_381 import multiply, add, Z1, curve_order
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.utils import py_ecc_point_to_blst
from pyblst import BlstP1Element


class Verify:
    def __init__(self, proof, vk, fixed_cols: list, rl_to_proove, rps, seed_point, Domain):
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

        # Pre-convert points to pyblst 
        self.Cb_blst = py_ecc_point_to_blst(self.Cb)
        self.Caccip_blst = py_ecc_point_to_blst(self.Caccip)
        self.Caccx_blst = py_ecc_point_to_blst(self.Caccx)
        self.Caccy_blst = py_ecc_point_to_blst(self.Caccy)
        self.Cq_blst = py_ecc_point_to_blst(self.Cq)
        self.Phi_zeta_blst = py_ecc_point_to_blst(self.Phi_zeta)
        self.Phi_zeta_omega_blst = py_ecc_point_to_blst(self.Phi_zeta_omega)
        
        self.Cpx_blst = py_ecc_point_to_blst(self.Cpx)
        self.Cpy_blst = py_ecc_point_to_blst(self.Cpy)
        self.Cs_blst = py_ecc_point_to_blst(self.Cs)

        # can even put as separate function
        self.t = Transcript(S_PRIME, b"Bandersnatch_SHA-512_ELL2")
        self.cur_t, self.alpha_list = phase1_alphas(
            self.t,
            self.verifier_key,
            self.relation_to_proove,
            list(H.to_int(nm(cmt)) for cmt in self.proof_ptr[:4]),
        )  # cb, caccip, caccx, caccy

        self.cur_t, self.zeta_p = phase2_eval_point(
            self.cur_t, H.to_int(nm(self.proof_ptr[-4]))
        )
        self.V_list = phase3_nu_vector(
            self.cur_t, list(self.proof_ptr[4:11]), self.proof_ptr[-3]
        )

    def contributions_to_constraints_eval_at_zeta(self):
        zeta = self.zeta_p
        sp = self.sp
        sx, sy = sp
        MOD = curve_order
        
        # Precompute common values
        zeta_minus_d4 = (zeta - D[-4]) % MOD
        
        # Compute Lagrange basis evaluations once
        L_0_x = lagrange_basis_polynomial(self.D, 0, S_PRIME)
        L_0_zeta = poly_evaluate(L_0_x, zeta, S_PRIME) % MOD
        L_N_4_x = lagrange_basis_polynomial(self.D, SIZE - 4, S_PRIME)
        L_N_4_zeta = poly_evaluate(L_N_4_x, zeta, S_PRIME) % MOD

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
        coeff_a = BandersnatchParams.EDWARDS_A
        
        # Precompute common subexpressions
        y1_y2 = (y1 * y2) % MOD
        x1_x2 = (x1 * x2) % MOD
        x1_y1 = (x1 * y1) % MOD
        x2_y2 = (x2 * y2) % MOD
        
        c2 = (b * (-(x1_y1 + x2_y2)) + one_minus_b * (-x1)) % MOD
        c2_zeta = (c2 * zeta_minus_d4) % MOD
        
        x1_y2_minus_x2_y1 = ((x1 * y2) - (x2 * y1)) % MOD
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

    def divide(self, numr, denom):
        # Compute inverse
        denominator_inv = mod_inverse(
            denom, curve_order
        )  # which prime modulus need o be taken!

        # Compute final result
        q_zeta = numr * denominator_inv % curve_order  # field_modulus

        return q_zeta

    def evaluation_of_quotient_poly_at_zeta(self):
        """
        input: commitments, alphas, zeta,
        output:
        """

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
        
        # MSM using pyblst
        # C_agg = sum(C_a[i] * v_list[i])
        C_agg = BlstP1Element() 
        for i in range(len(C_a_blst)):
            term = C_a_blst[i].scalar_mul(v_list[i])
            C_agg = C_agg + term
            
        # Pass blst point to kzg.verify
        # kzg.verify handles BlstP1Element now

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
        
        verification = KZG.verify(C_agg, self.Phi_zeta_blst, zeta, Agg_zeta)
            
        return verification  # , cs

    def evaluation_of_linearization_poly_at_zeta_omega(self):
        alphas_list, zeta, v_list = self.alpha_list, self.zeta_p, self.V_list
        
        scalar_cl1 = (zeta - self.D[-4]) % curve_order
        
        Cl1 = self.Caccip_blst.scalar_mul(scalar_cl1)

        # Cl2
        x1, y1 = self.accx_zeta, self.accy_zeta
        x2, y2 = self.px_zeta, self.py_zeta
        b = self.b_zeta
        coeff_a = BandersnatchParams.EDWARDS_A
        #
        C_acc_x = (
            b * (y1 * y2 + (coeff_a * x1 * x2)) % S_PRIME + (1 - b) % S_PRIME
        ) % S_PRIME
        C_acc_y = 0
        C_acc_x_f = C_acc_x * (zeta - self.D[-4]) % curve_order
        C_acc_y_f = C_acc_y * (zeta - self.D[-4]) % curve_order
        #
        term1 = self.Caccx_blst.scalar_mul(C_acc_x_f)
        term2 = self.Caccy_blst.scalar_mul(C_acc_y_f)
        Cl2 = term1 + term2

        # c3
        b = self.b_zeta
        x1, y1 = self.accx_zeta, self.accy_zeta
        x2, y2 = self.px_zeta, self.py_zeta
        C_acc_x = 0
        C_acc_y = ((b * (x1 * y2 - x2 * y1)) % S_PRIME + (1 - b) % S_PRIME) % S_PRIME
        C_acc_x *= (zeta - self.D[-4]) % curve_order
        C_acc_y *= (zeta - self.D[-4]) % curve_order

        term1 = self.Caccx_blst.scalar_mul(C_acc_x)
        term2 = self.Caccy_blst.scalar_mul(C_acc_y)
        Cl3 = term1 + term2

        Cl_list = [Cl1, Cl2, Cl3]

        Cl = BlstP1Element()
        for i in range(3):
            Cl = Cl + Cl_list[i].scalar_mul(alphas_list[i])
            
        verified = KZG.verify(
            Cl, self.Phi_zeta_omega_blst, zeta * OMEGA % curve_order, self.l_zeta_omega
        )

        return verified

    def is_signtaure_valid(self):
        """If both the verifications are true then sign is valid"""
        # Evaluate both in sequence to avoid short-circuit if first fails
        # This ensures consistent timing
        result1 = self.evaluation_of_quotient_poly_at_zeta()
        result2 = self.evaluation_of_linearization_poly_at_zeta_omega()
        return result1 and result2
