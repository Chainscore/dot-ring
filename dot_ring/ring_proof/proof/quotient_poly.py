from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.protocol import PCS, G1Commitment
from dot_ring.ring_proof.polynomial.ops import poly_divide_by_vanishing


class QuotientPoly:
    def __init__(self, domain_size: int, pcs: type[PCS] = KZG, prime: int | None = None) -> None:
        self.domain_size = domain_size
        self.pcs = pcs
        self.prime = prime

    @staticmethod
    def poly_vector_xn_minus_1(n: int) -> list[int]:
        vec = [0] * (n + 1)
        vec[0] = -1
        vec[n] = 1
        # print("vect:", vec)
        return vec

    def quotient_poly_commitment(self, q_x: list[int]) -> G1Commitment:
        """
        input: quotient polynomial
        output: commitment to quotient polynomial
        """
        c_q = self.pcs.commit(q_x)
        return c_q

    def quotient_poly(self, C_agg: list[int]) -> tuple[list[int], G1Commitment]:
        if self.prime is None:
            raise ValueError("quotient polynomial division requires a prime field modulus")
        qnt_poly = poly_divide_by_vanishing(C_agg, self.domain_size, self.prime)
        # print("q_p:", qnt_poly)
        C_qp = self.quotient_poly_commitment(qnt_poly)
        # C_qp_nm=nm(C_qp)
        return qnt_poly, C_qp
