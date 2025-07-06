# mypy: ignore-errors
import time
start_time=time.time()
from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.polynomial.ops import poly_add, poly_scalar
from dot_ring.fiat_shamir.phases import phase3_nu_vector
# from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.helpers import  Helpers as H

# kzg=KZG.default()


class AggPoly:

    def __init__(self, cur_t, zta, fixed_cols, witness_cols, quotient_poly, quotient_cmt, poly_evals, l_Agg, zw, l_agg_zw,kzg):

        self.zeta= zta
        self.kzg = kzg
        (self.P_x_zeta, self.P_y_zeta, self.s_zeta, self.b_zeta,
         self.acc_ip_zeta, self.acc_x_zeta, self.acc_y_zeta)= list(poly_evals.values())
        self.l_agg = l_Agg
        self.zeta_omega = zw
        self.l_agg_at_zeta_omega= l_agg_zw
        self.cf_vectors= phase3_nu_vector(cur_t,list(poly_evals.values()), l_agg_zw)
        self.fs= fixed_cols
        self.ws= witness_cols
        self.Q_p= quotient_poly
        self.C_q= quotient_cmt


    # get the aggregated poly
    def aggregated_poly(self):

        poly_I = [self.fs[0].coeffs, self.fs[1].coeffs,self.fs[2].coeffs, self.ws[0].coeffs, self.ws[3].coeffs ,self.ws[1].coeffs,self.ws[2].coeffs, self.Q_p]
        V_list = self.cf_vectors
        agg_poly = [0]
        for i in range(len(poly_I)):
            agg_poly = poly_add(agg_poly, poly_scalar(poly_I[i], V_list[i], S_PRIME), S_PRIME)
        return agg_poly

    #two proof openings
    def proof_contents_phi(self):
        """
        input:agg_poly, liner_poly, zeta, zeta_omega
        output: Phi_zeta, phi_zeta_omega
        """
        agg_p=self.aggregated_poly()
        phi_z_opening = self.kzg.open(agg_p, self.zeta)  # take only proof
        phi_zw_opening= self.kzg.open(self.l_agg, self.zeta_omega)  # take only proof
        return phi_z_opening, phi_zw_opening,phi_z_opening.proof, phi_zw_opening.proof

    def construct_proof(self ):
        """
        input: commitments, poly_evaluations
        output: proof
        """
        opening1, opening2, phi_z, phi_zw= self.proof_contents_phi()
        C_b, C_acc_ip,C_acc_x, C_acc_y= self.ws[0].commitment, self.ws[3].commitment, self.ws[1].commitment, self.ws[2].commitment

        #Proof point representation
        Proof_P_rpr= [C_b, C_acc_ip, C_acc_x, C_acc_y, self.P_x_zeta, self.P_y_zeta, self.s_zeta, self.b_zeta, self.acc_ip_zeta, self.acc_x_zeta, self.acc_y_zeta,self.C_q, self.l_agg_at_zeta_omega, phi_z, phi_zw]

        #Proof Byte String Representation
        Proof_B_Str_rpr= H.bls_g1_compress(C_b)+H.bls_g1_compress(C_acc_ip)+ H.bls_g1_compress(C_acc_x)+ H.bls_g1_compress(C_acc_y)+ H.to_bytes(self.P_x_zeta)+ H.to_bytes(self.P_y_zeta)+ H.to_bytes(self.s_zeta)+H.to_bytes( self.b_zeta)+ H.to_bytes(self.acc_ip_zeta)+ H.to_bytes(self.acc_x_zeta)+H.to_bytes( self.acc_y_zeta) +H.bls_g1_compress(self.C_q)+ H.to_bytes(self.l_agg_at_zeta_omega)+ H.bls_g1_compress(phi_z)+ H.bls_g1_compress(phi_zw)
        return self.cf_vectors, Proof_P_rpr,Proof_B_Str_rpr #, fs[0].commitment, fs[1].commitment, fs[2].commitment
