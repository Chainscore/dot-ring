from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.protocol import PCS
from dot_ring.ring_proof.polynomial.ops import poly_add, poly_scalar_mul


class AggPoly:
    # get the aggregated poly
    @classmethod
    def aggregated_poly(cls, fixed_cols: list, witness_cols: list, Q_p: list[int], cf_vectors: list[int], prime: int = S_PRIME) -> list[int]:
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
        agg_poly = [0]
        for poly, scalar in zip(poly_I, cf_vectors, strict=True):
            agg_poly = poly_add(agg_poly, poly_scalar_mul(poly, scalar, prime), prime)
        return agg_poly

    # two proof openings
    @classmethod
    def proof_contents_phi(
        cls,
        zeta: int,
        zeta_omega: int,
        l_agg: list[int],
        fixed_cols: list,
        witness_cols: list,
        Q_p: list[int],
        cf_vectors: list[int],
        prime: int = S_PRIME,
        pcs: type[PCS] = KZG,
    ) -> tuple:
        """
        input:agg_poly, liner_poly, zeta, zeta_omega
        output: Phi_zeta, phi_zeta_omega
        """
        agg_p = cls.aggregated_poly(fixed_cols, witness_cols, Q_p, cf_vectors, prime)
        phi_z_opening = pcs.open(agg_p, zeta)  # take only proof
        phi_zw_opening = pcs.open(l_agg, zeta_omega)  # take only proof
        return phi_z_opening, phi_zw_opening, phi_z_opening, phi_zw_opening
