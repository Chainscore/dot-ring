from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.polynomial.ops import poly_add, poly_scalar
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.pcs.kzg import KZG

class AggPoly:
    # get the aggregated poly
    @classmethod
    def aggregated_poly(cls, fixed_cols, witness_cols, Q_p, cf_vectors):
        poly_I = [
            fixed_cols[0].coeffs,
            fixed_cols[1].coeffs,
            fixed_cols[2].coeffs,
            witness_cols[0].coeffs,
            witness_cols[3].coeffs,
            witness_cols[1].coeffs,
            witness_cols[2].coeffs,
            Q_p,
        ]
        V_list = cf_vectors
        agg_poly = [0]
        for i in range(len(poly_I)):
            agg_poly = poly_add(
                agg_poly, poly_scalar(poly_I[i], V_list[i], S_PRIME), S_PRIME
            )
        return agg_poly

    # two proof openings
    @classmethod
    def proof_contents_phi(cls, zeta, zeta_omega, l_agg, fixed_cols, witness_cols, Q_p, cf_vectors):
        """
        input:agg_poly, liner_poly, zeta, zeta_omega
        output: Phi_zeta, phi_zeta_omega
        """
        agg_p = cls.aggregated_poly(fixed_cols, witness_cols, Q_p, cf_vectors)
        phi_z_opening = KZG.open(agg_p, zeta)  # take only proof
        phi_zw_opening = KZG.open(l_agg, zeta_omega)  # take only proof
        return phi_z_opening, phi_zw_opening, phi_z_opening.proof, phi_zw_opening.proof
