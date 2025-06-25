from py_ecc.optimized_bls12_381 import normalize as nm

from dot_ring.ring_proof.constants import SIZE
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.polynomial.ops import poly_division_general
kzg=KZG.default()

class QuotientPoly:

    @staticmethod
    def poly_vector_xn_minus_1(n):
        vec = [0] * (n + 1)
        vec[0] = -1
        vec[n] = 1
        # print("vect:", vec)
        return vec

    @staticmethod
    def quotient_poly_commitment(q_x):
        """
        input: quotient polynomial
        output: commitment to quotient polynomial
        """
        c_q =kzg.commit(q_x)
        return c_q


    def quotient_poly(self, C_agg):
        qnt_poly=poly_division_general(C_agg,self.poly_vector_xn_minus_1(SIZE))
        # print("q_p:", qnt_poly)
        C_qp=self.quotient_poly_commitment(qnt_poly)
        # C_qp_nm=nm(C_qp)
        return qnt_poly,C_qp




