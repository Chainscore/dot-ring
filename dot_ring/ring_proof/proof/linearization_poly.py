import sys  # mypy: ignore-errors
import time

from dot_ring.curves.specs.bandersnatch import _Params as BandersnatchParams
from dot_ring.ring_proof.constants import OMEGA as omega, D_512 as D, S_PRIME
from dot_ring.ring_proof.polynomial.ops import (
    poly_add, poly_scalar, vect_mul, poly_multiply
)
from dot_ring.ring_proof.polynomial.ops import poly_evaluate
from dot_ring.fiat_shamir.phases import phase2_eval_point

# mypy: ignore-errors
class LAggPoly:

    def __init__(self, cur_t, C_q, fixed_cols, witness_res, alphas):
        self.zeta = phase2_eval_point(cur_t, C_q)
        self.t = cur_t
        self.zeta_omega = (self.zeta * omega) % S_PRIME
        self.scalar_term = (self.zeta - D[-4]) % S_PRIME
        self.fs= fixed_cols
        self.wts= witness_res
        self.alphas= alphas
        self.a= BandersnatchParams.EDWARDS_A

    def evaluate_polys_at_zeta(self):
        self.P_x_zeta = poly_evaluate(self.fs[0].coeffs, self.zeta, S_PRIME)
        self.P_y_zeta = poly_evaluate(self.fs[1].coeffs, self.zeta, S_PRIME)
        self.s_zeta = poly_evaluate(self.fs[2].coeffs, self.zeta, S_PRIME)
        self.b_zeta = poly_evaluate(self.wts[0].coeffs, self.zeta, S_PRIME)
        self.acc_ip_zeta = poly_evaluate(self.wts[3].coeffs, self.zeta, S_PRIME)
        self.acc_x_zeta = poly_evaluate(self.wts[1].coeffs, self.zeta, S_PRIME)
        self.acc_y_zeta = poly_evaluate(self.wts[2].coeffs, self.zeta, S_PRIME)

    def compute_l1(self):
        return poly_scalar(self.wts[3].coeffs, self.scalar_term, S_PRIME)

    def compute_l2(self):

        x1, y1= self.acc_x_zeta, self. acc_y_zeta
        x2, y2= self.P_x_zeta, self.P_y_zeta
        b= self.b_zeta
        coeff_a= self.a

        C_acc_x= (b *(y1*y2 + (coeff_a * x1 *x2)) % S_PRIME + (1-b) %S_PRIME ) % S_PRIME
        C_acc_y=0
        C_acc_x_f= C_acc_x * self.scalar_term
        C_acc_y_f = C_acc_y* self.scalar_term

        term1= vect_mul( self.wts[1].coeffs, C_acc_x_f, S_PRIME)
        term2= vect_mul(self.wts[2].coeffs,C_acc_y_f, S_PRIME)
        res=poly_add(term1, term2, S_PRIME)
        return res

        # inner = (self.b_zeta * pow((self.acc_x_zeta - self.P_x_zeta) % S_PRIME, 2, S_PRIME)) % S_PRIME
        # left = poly_scalar(self.wts[1].coeffs, inner, S_PRIME)
        # right = poly_scalar(self.wts[2].coeffs, (1 - self.b_zeta) % S_PRIME, S_PRIME)
        # return poly_scalar(poly_add(left, right, S_PRIME), self.scalar_term, S_PRIME)


    def compute_l3(self):

        b= self.b_zeta
        x1, y1= self.acc_x_zeta, self.acc_y_zeta
        x2, y2= self.P_x_zeta, self.P_y_zeta
        C_acc_x=0
        C_acc_y=((b*(x1*y2 - x2*y1)) %S_PRIME+(1- b) %S_PRIME) %S_PRIME
        C_acc_x *=self.scalar_term
        C_acc_y*=self.scalar_term

        term1= poly_scalar(self.wts[1].coeffs , C_acc_x, S_PRIME)
        term2=poly_scalar(self.wts[2].coeffs, C_acc_y, S_PRIME)
        res= poly_add(term1, term2, S_PRIME)
        return res

        # term1_scalar = (self.b_zeta * ((self.acc_y_zeta - self.P_y_zeta) % S_PRIME) + (1 - self.b_zeta)) % S_PRIME
        # term2_scalar = (self.b_zeta * ((self.acc_x_zeta - self.P_x_zeta) % S_PRIME)) % S_PRIME
        # term1 = poly_scalar(self.wts[1].coeffs, term1_scalar, S_PRIME)
        # term2 = poly_scalar(self.wts[2].coeffs, term2_scalar, S_PRIME)
        # return poly_scalar(poly_add(term1, term2, S_PRIME), self.scalar_term, S_PRIME)

    def linearize(self, l1, l2, l3):
        l_agg = [0]
        for i, li in enumerate([l1, l2, l3]):
            l_agg = poly_add(l_agg, poly_scalar(li, self.alphas[i], S_PRIME), S_PRIME)
        return l_agg

    def l_agg_poly(self):
        l_start=time.time()
        self.evaluate_polys_at_zeta()  # fills P_x_zeta … acc_y_zeta
        l1 = self.compute_l1()
        l2 = self.compute_l2()
        l3 = self.compute_l3()
        l_agg = self.linearize(l1, l2, l3)


        l_agg_zeta_omega = poly_evaluate(l_agg, self.zeta_omega, S_PRIME)
        l_end = time.time()
        # print("l_ploly:", l_end-l_start)
        return self.t, self.zeta, {
            # "Zeta":self.zeta,
            "P_x_zeta": self.P_x_zeta,
            "P_y_zeta": self.P_y_zeta,
            "s_zeta": self.s_zeta,
            "b_zeta": self.b_zeta,
            "acc_ip_zeta": self.acc_ip_zeta,
            "acc_x_zeta": self.acc_x_zeta,
            "acc_y_zeta": self.acc_y_zeta,
            # "l_agg_zeta_omega": l_agg_zeta_omega,
        }, l_agg, self.zeta_omega, l_agg_zeta_omega


