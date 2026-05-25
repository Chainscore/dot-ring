from __future__ import annotations

from typing import cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.ring_proof.columns.columns import Column, WitnessColumnBuilder, require_commitment
from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.pcs.protocol import G1Commitment
from dot_ring.ring_proof.proof.aggregation_poly import AggPoly
from dot_ring.ring_proof.proof.linearization_poly import LAggPoly
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.transcript.phases import phase1_alphas, phase3_nu_vector
from dot_ring.ring_proof.transcript.transcript import Transcript

from .ring import Ring
from .ring_proof_payload import RingProofPayload
from .ring_root import RingRoot
from .ring_serialization import transcript_g1, transcript_vk


class RingProofBuilder:
    def __init__(
        self,
        curve: CurveVariant,
        blinding_factor: int,
        producer_key: bytes | str,
        ring: Ring,
        transcript_challenge: bytes | None = None,
        ring_root: RingRoot | None = None,
    ) -> None:
        self.curve = curve
        self.blinding_factor = blinding_factor
        self.producer_key = producer_key
        self.ring = ring
        self.ring_root = ring_root
        self.transcript_challenge = transcript_challenge or curve.curve.SUITE_ID or curve.curve.SUITE_STRING

    def build(self) -> RingProofPayload:
        params = self.ring.params
        ring_root = self.ring_root or RingRoot.from_ring(self.ring, params)
        producer_index = self.ring.index_of(self.producer_key)

        witness_builder = WitnessColumnBuilder.from_params(
            self.ring.nm_points,
            ring_root.s.evals,
            producer_index,
            self.blinding_factor,
            params,
        )
        witness_columns = witness_builder.build()
        relation_point = witness_builder.result(params.blinding_base)
        relation_plus_seed = witness_builder.result_p_seed(relation_point)

        constraints = RingConstraintBuilder(
            Result_plus_Seed=relation_plus_seed,
            px=cast(list[int], ring_root.px.coeffs),
            py=cast(list[int], ring_root.py.coeffs),
            s=cast(list[int], ring_root.s.coeffs),
            b=cast(list[int], witness_columns[0].coeffs),
            acc_x=cast(list[int], witness_columns[1].coeffs),
            acc_y=cast(list[int], witness_columns[2].coeffs),
            acc_ip=cast(list[int], witness_columns[3].coeffs),
            params=params,
            seed_point=params.seed_point,
        )
        transcript, alpha = self._phase1_transcript(ring_root, relation_point, witness_columns)
        constraint_polys = list(constraints.compute().values())
        c_agg = aggregate_constraints(constraint_polys, alpha, params.radix_omega, params.prime, domain=params.domain)

        quotient_poly = QuotientPoly(params.domain_size, params.pcs)
        q_poly, c_q = quotient_poly.quotient_poly(c_agg)
        c_q_column = Column(name="C_q", evals=[], commitment=c_q)

        l_agg = LAggPoly(
            transcript,
            transcript_g1(params, c_q),
            [ring_root.px, ring_root.py, ring_root.s],
            list(witness_columns),
            alpha,
            domain=params.domain,
            omega=params.omega,
            prime=params.prime,
            padding_rows=params.padding_rows,
            edwards_a=params.ring_edwards_a,
        )
        current_transcript, zeta, relation_evals, l_agg_poly, zeta_omega, l_zeta_omega = l_agg.l_agg_poly()
        _, _, phi_zeta, phi_zeta_omega = AggPoly.proof_contents_phi(
            zeta,
            zeta_omega,
            l_agg_poly,
            [ring_root.px, ring_root.py, ring_root.s],
            list(witness_columns),
            q_poly,
            phase3_nu_vector(current_transcript, list(relation_evals.values()), l_zeta_omega),
            prime=params.prime,
            pcs=params.pcs,
        )
        (
            px_zeta,
            py_zeta,
            s_zeta,
            b_zeta,
            accip_zeta,
            accx_zeta,
            accy_zeta,
        ) = relation_evals.values()
        c_b, c_accx, c_accy, c_accip = witness_columns

        return RingProofPayload(
            c_b=c_b,
            c_accip=c_accip,
            c_accx=c_accx,
            c_accy=c_accy,
            px_zeta=px_zeta,
            py_zeta=py_zeta,
            s_zeta=s_zeta,
            b_zeta=b_zeta,
            accip_zeta=accip_zeta,
            accx_zeta=accx_zeta,
            accy_zeta=accy_zeta,
            c_q=c_q_column,
            l_zeta_omega=l_zeta_omega,
            open_agg_zeta=phi_zeta,
            open_l_zeta_omega=phi_zeta_omega,
        )

    def _phase1_transcript(
        self,
        ring_root: RingRoot,
        relation_point: tuple[int, int],
        witness_columns: tuple[Column, Column, Column, Column],
    ) -> tuple[Transcript, list[int]]:
        params = self.ring.params
        c_b, c_accx, c_accy, c_accip = witness_columns
        witness_commitments = [
            transcript_g1(params, require_commitment(c_b)),
            transcript_g1(params, require_commitment(c_accip)),
            transcript_g1(params, require_commitment(c_accx)),
            transcript_g1(params, require_commitment(c_accy)),
        ]
        transcript = Transcript(params.prime, self.transcript_challenge)
        return cast(
            tuple[Transcript, list[int]],
            phase1_alphas(
                transcript,
                transcript_vk(params, _commitments(ring_root.px, ring_root.py, ring_root.s)),
                relation_point,
                witness_commitments,
            ),
        )


def _commitments(*columns: Column) -> list[G1Commitment]:
    return [require_commitment(column) for column in columns]
