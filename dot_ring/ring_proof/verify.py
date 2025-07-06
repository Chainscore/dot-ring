# mypy: ignore-errors
from dot_ring.curves.specs.bandersnatch import _Params as BandersnatchParams
from sympy import mod_inverse
from dot_ring.ring_proof.constants import S_PRIME, SIZE, D_512 as D, OMEGA
from dot_ring.fiat_shamir.transcript import Transcript
from dot_ring.fiat_shamir.phases import (
    phase1_alphas,
    phase2_eval_point,
    phase3_nu_vector,
)
from dot_ring.ring_proof.polynomial.ops import lagrange_basis_polynomial, poly_evaluate
from py_ecc.optimized_bls12_381 import  normalize as nm
from dot_ring.ring_proof.pcs.kzg import KZG
from py_ecc.optimized_bls12_381 import multiply, add, Z1, curve_order
from dot_ring.ring_proof.helpers import Helpers as H
kzg= KZG.default()

class Verify:

    def __init__(self, proof, vk, fixed_cols, rl_to_proove, rps, seed_point, Domain):

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
            self.Phi_zeta_omega
        ) = proof

        self.proof_ptr= proof
        self.verifier_key= vk
        if hasattr(fixed_cols[0], 'commitment'):
            self.Cpx, self.Cpy, self.Cs = fixed_cols[0].commitment, fixed_cols[1].commitment, fixed_cols[2].commitment
        else:
            self.Cpx, self.Cpy, self.Cs = fixed_cols
        self.relation_to_proove= rl_to_proove
        self.Result_plus_Seed, self.sp, self.D =rps, seed_point, Domain

        # Initialise transcript and derive Fiat-Shamir challenges
        self.t = Transcript(S_PRIME, b"Bandersnatch_SHA-512_ELL2")

        self.alpha_list = phase1_alphas(
            self.t,
            self.verifier_key,
            self.relation_to_proove,
            list(H.to_int(nm(cmt)) for cmt in self.proof_ptr[:4]),
        )

        self.zeta_p = phase2_eval_point(self.t, H.to_int(nm(self.proof_ptr[-4])))

        self.V_list = phase3_nu_vector(
            self.t,
            self.proof_ptr[4:11],
            self.proof_ptr[-3],
        )

    def contributions_to_constraints_eval_at_zeta(self):

        L_0_x = lagrange_basis_polynomial(self.D, 0)
        zeta= self.zeta_p
        L_0_zeta = poly_evaluate(L_0_x, zeta, S_PRIME) % curve_order
        L_N_4_x = lagrange_basis_polynomial(self.D, SIZE - 4)
        L_N_4_zeta = poly_evaluate(L_N_4_x, zeta, S_PRIME) % curve_order
        sp= self.sp
        sx, sy = sp
        MOD = curve_order

        # Constraint 1
        term1 = (self.b_zeta * self.s_zeta) % MOD
        inner_sum = (self.accip_zeta + term1) % MOD  # Ensures result is positive in the field
        negated = (-inner_sum) % MOD  # Ensures result is positive in the field
        vanishing_term = (zeta - D[-4]) % MOD
        c1_zeta = (negated * vanishing_term) % MOD

        #constraint 1 and 2 new
        x1, y1 = self.accx_zeta, self.accy_zeta
        x2, y2 = self.px_zeta, self.py_zeta
        x3, y3=0,0
        b = self.b_zeta
        coeff_a = BandersnatchParams.EDWARDS_A
        c2= (b * (x3 * (y1 * y2 + coeff_a * x1 * x2) - (x1 * y1 + x2 * y2))+ (1- b) *(x3 - x1) ) %MOD
        c2_zeta= (c2 * (zeta- D[-4])%MOD) %MOD
        c3 =(b * (y3 * (x1 * y2 - x2 * y1) - (x1 * y1 - x2 * y2)) + (1 - b) *(y3 - y1)) % MOD
        c3_zeta=( c3 *(zeta- D[-4])%MOD) %MOD

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

    def divide(self,numr, denom):
        # Compute inverse
        denominator_inv = mod_inverse(denom, curve_order)  # which prime modulus need o be taken!

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


        C_a = [self.Cpx, self.Cpy, self.Cs, self.Cb, self.Caccip, self.Caccx, self.Caccy, self.Cq]  # commitments which are in bls12 field form

        prod_sum = 1
        for k in range(1, 4):
            cur = zeta - self.D[-k] % curve_order
            prod_sum *= cur % curve_order

        s_sum = 0
        for i in range(len(alphas_list)):
            s_sum += (alphas_list[i] * cs[i] % curve_order) % curve_order

        s_sum += self.l_zeta_omega % curve_order

        q_zeta = self.divide((s_sum * prod_sum) % curve_order,
                        (pow(zeta, SIZE, curve_order) - 1) % curve_order)

        C_agg = Z1
        for i in range(len(C_a)):
            C_agg = add(C_agg, multiply(C_a[i], v_list[i]))

        MOD = curve_order

        terms = [
            (v_list[0] * self.px_zeta) % MOD,
            (v_list[1] * self.py_zeta) % MOD,
            (v_list[2] * self.s_zeta) % MOD,
            (v_list[3] * self.b_zeta) % MOD,
            (v_list[4] * self.accip_zeta) % MOD,
            (v_list[5] * self.accx_zeta) % MOD,
            (v_list[6] * self.accy_zeta) % MOD,
            (v_list[7] * q_zeta) % MOD
        ]

        Agg_zeta = sum(terms) % MOD
        verification = kzg.verify(C_agg, self.Phi_zeta, zeta, Agg_zeta)
        return verification#, cs


    def evaluation_of_linearization_poly_at_zeta_omega(self):
        alphas_list, zeta, v_list= self.alpha_list, self.zeta_p, self.V_list
        Cl1 = multiply(self.Caccip, (zeta - self.D[-4]) % curve_order)

        #Cl2
        x1, y1 = self.accx_zeta, self.accy_zeta
        x2, y2= self.px_zeta, self.py_zeta
        b= self.b_zeta
        coeff_a= BandersnatchParams.EDWARDS_A
        #
        C_acc_x= (b *(y1*y2 + (coeff_a * x1 *x2)) % S_PRIME + (1-b) %S_PRIME ) % S_PRIME
        C_acc_y=0
        C_acc_x_f= C_acc_x * (zeta - self.D[-4]) % curve_order
        C_acc_y_f = C_acc_y* (zeta - self.D[-4]) % curve_order
        #
        term1= multiply( self.Caccx, C_acc_x_f)
        term2= multiply(self.Caccy,C_acc_y_f)

        Cl2=add(term1, term2)

        #c3
        b= self.b_zeta
        x1, y1= self.accx_zeta, self.accy_zeta
        x2, y2= self.px_zeta, self.py_zeta
        C_acc_x=0
        C_acc_y=((b*(x1*y2 - x2*y1)) %S_PRIME+(1- b) %S_PRIME) %S_PRIME
        C_acc_x *=(zeta - self.D[-4]) % curve_order
        C_acc_y*=(zeta - self.D[-4]) % curve_order

        term1= multiply(self.Caccx, C_acc_x)
        term2=multiply(self.Caccy, C_acc_y)
        Cl3= add(term1, term2)


        Cl_list = [Cl1, Cl2, Cl3]

        Cl = Z1
        for i in range(3):
            Cl = add(Cl, multiply(Cl_list[i], alphas_list[i]))

        verified = kzg.verify(Cl, self.Phi_zeta_omega, zeta * OMEGA % curve_order, self.l_zeta_omega)

        return verified

    def is_signtaure_valid(self):
        """If both the verifications are true then sign is valid"""
        return self.evaluation_of_quotient_poly_at_zeta() and self.evaluation_of_linearization_poly_at_zeta_omega()
