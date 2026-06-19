from __future__ import annotations

from collections.abc import Sequence

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.columns.columns import Column, WitnessColumnBuilder, require_commitment
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.polynomial.fft import inverse_fft
from dot_ring.ring_proof.polynomial.ops import poly_add, poly_divide_by_vanishing, poly_evaluate_single, poly_multiply, poly_scalar_mul
from dot_ring.ring_proof.transcript.phases import phase1_alphas_after_vk, phase2_eval_point, phase3_nu_vector
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript

from .members import Ring
from .proof_payload import RingProofPayload
from .root import RingRoot


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
        self.transcript_challenge = transcript_challenge or curve.curve.params.suite_id

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
        relation_point = witness_builder.result(params.cv.curve.params.auxiliary_points.blinding_base)
        seed_point = params.cv.curve.params.auxiliary_points.accumulator_base
        relation_plus_seed_point = relation_point + params.cv.point(seed_point)
        relation_plus_seed = int(relation_plus_seed_point.x), int(relation_plus_seed_point.y)

        constraints = RingConstraintBuilder(
            result_plus_seed=relation_plus_seed,
            px=self._coeffs(ring_root.px),
            py=self._coeffs(ring_root.py),
            s=self._coeffs(ring_root.s),
            b=self._coeffs(witness_columns[0]),
            acc_x=self._coeffs(witness_columns[1]),
            acc_y=self._coeffs(witness_columns[2]),
            acc_ip=self._coeffs(witness_columns[3]),
            params=params,
        )
        transcript, alpha = self._phase1_transcript(ring_root, relation_point, witness_columns)
        constraint_polys = list(constraints.compute().values())
        c_agg = self._aggregate_constraints(constraint_polys, alpha)

        q_poly = poly_divide_by_vanishing(c_agg, params.domain_size)
        c_q = params.pcs.commit(q_poly)
        c_q_column = Column(name="C_q", evals=[], commitment=c_q)

        fixed_columns = (ring_root.px, ring_root.py, ring_root.s)

        current_transcript, zeta, relation_evals, l_agg_poly, zeta_omega, l_zeta_omega = self._linearization_poly(
            transcript,
            c_q,
            fixed_columns,
            witness_columns,
            alpha,
        )
        phi_zeta, phi_zeta_omega = self._opening_proofs(
            zeta,
            zeta_omega,
            l_agg_poly,
            fixed_columns,
            witness_columns,
            q_poly,
            phase3_nu_vector(
                current_transcript,
                list(relation_evals.values()),
                l_zeta_omega,
            ),
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
            open_agg_zeta=phi_zeta.proof,
            open_l_zeta_omega=phi_zeta_omega.proof,
        )

    def _phase1_transcript(
        self,
        ring_root: RingRoot,
        relation_point: CurvePoint,
        witness_columns: tuple[Column, Column, Column, Column],
    ) -> tuple[FiatShamirTranscript, list[int]]:
        params = self.ring.params
        c_b, c_accx, c_accy, c_accip = witness_columns
        witness_commitments = [
            params.pcs.serialize_g1_uncompressed(require_commitment(c_b)),
            params.pcs.serialize_g1_uncompressed(require_commitment(c_accip)),
            params.pcs.serialize_g1_uncompressed(require_commitment(c_accx)),
            params.pcs.serialize_g1_uncompressed(require_commitment(c_accy)),
        ]
        transcript = ring_root.verifier_transcript_prefix(params, self.transcript_challenge).copy()
        return phase1_alphas_after_vk(
            transcript,
            relation_point,
            witness_commitments,
        )

    def _aggregate_constraints(
        self,
        constraint_evals: Sequence[Sequence[int]],
        alphas: Sequence[int],
    ) -> list[int]:
        params = self.ring.params
        if not constraint_evals:
            return []

        aggregated_evals = [0] * len(constraint_evals[0])
        for constraint, alpha in zip(constraint_evals, alphas, strict=False):
            if len(constraint) != len(aggregated_evals):
                raise ValueError("constraint evaluation lengths must match")
            for index, value in enumerate(constraint):
                aggregated_evals[index] = (aggregated_evals[index] + value * alpha) % params.prime

        aggregated_poly = inverse_fft(aggregated_evals, params.radix_omega, params.prime)
        c_agg = poly_multiply(aggregated_poly, self._tail_vanishing_polynomial(), params.prime)

        last_nonzero = len(c_agg) - 1
        while last_nonzero >= 0 and c_agg[last_nonzero] == 0:
            last_nonzero -= 1
        return c_agg[: last_nonzero + 1]

    def _tail_vanishing_polynomial(self, k: int = 3) -> list[int]:
        params = self.ring.params
        vanishing = [1]
        for offset in range(1, k + 1):
            vanishing = poly_multiply(vanishing, [-params.domain[-offset], 1], params.prime)
        return vanishing

    def _linearization_poly(
        self,
        transcript: FiatShamirTranscript,
        c_q_commitment: object,
        fixed_columns: Sequence[Column],
        witness_columns: tuple[Column, Column, Column, Column],
        alphas: Sequence[int],
    ) -> tuple[FiatShamirTranscript, int, dict[str, int], list[int], int, int]:
        params = self.ring.params
        current_transcript, zeta = phase2_eval_point(
            transcript,
            params.pcs.serialize_g1_uncompressed(c_q_commitment),
        )
        zeta_omega = (zeta * params.omega) % params.prime
        last_index = params.domain_size - params.padding_rows
        scalar_term = (zeta - params.domain[last_index]) % params.prime

        relation_evals = self._relation_evals_at_zeta(fixed_columns, witness_columns, zeta)
        l1 = poly_scalar_mul(self._coeffs(witness_columns[3]), scalar_term, params.prime)
        l2 = poly_scalar_mul(
            self._coeffs(witness_columns[1]),
            self._acc_x_constraint_factor(relation_evals, scalar_term),
            params.prime,
        )
        l3 = poly_scalar_mul(
            self._coeffs(witness_columns[2]),
            self._acc_y_constraint_factor(relation_evals, scalar_term),
            params.prime,
        )

        l_agg = [0]
        for poly, scalar in zip((l1, l2, l3), alphas[:3], strict=True):
            l_agg = poly_add(l_agg, poly_scalar_mul(poly, scalar, params.prime), params.prime)

        l_zeta_omega = poly_evaluate_single(l_agg, zeta_omega, params.prime)
        return current_transcript, zeta, relation_evals, l_agg, zeta_omega, l_zeta_omega

    def _relation_evals_at_zeta(
        self,
        fixed_columns: Sequence[Column],
        witness_columns: tuple[Column, Column, Column, Column],
        zeta: int,
    ) -> dict[str, int]:
        params = self.ring.params
        c_b, c_accx, c_accy, c_accip = witness_columns
        return {
            "P_x_zeta": poly_evaluate_single(self._coeffs(fixed_columns[0]), zeta, params.prime),
            "P_y_zeta": poly_evaluate_single(self._coeffs(fixed_columns[1]), zeta, params.prime),
            "s_zeta": poly_evaluate_single(self._coeffs(fixed_columns[2]), zeta, params.prime),
            "b_zeta": poly_evaluate_single(self._coeffs(c_b), zeta, params.prime),
            "acc_ip_zeta": poly_evaluate_single(self._coeffs(c_accip), zeta, params.prime),
            "acc_x_zeta": poly_evaluate_single(self._coeffs(c_accx), zeta, params.prime),
            "acc_y_zeta": poly_evaluate_single(self._coeffs(c_accy), zeta, params.prime),
        }

    def _acc_x_constraint_factor(self, evals: dict[str, int], scalar_term: int) -> int:
        params = self.ring.params
        b = evals["b_zeta"]
        x1, y1 = evals["acc_x_zeta"], evals["acc_y_zeta"]
        x2, y2 = evals["P_x_zeta"], evals["P_y_zeta"]
        point_relation = y1 * y2 + params.cv.curve.params.a * x1 * x2
        return (b * point_relation + (1 - b)) * scalar_term % params.prime

    def _acc_y_constraint_factor(self, evals: dict[str, int], scalar_term: int) -> int:
        params = self.ring.params
        b = evals["b_zeta"]
        x1, y1 = evals["acc_x_zeta"], evals["acc_y_zeta"]
        x2, y2 = evals["P_x_zeta"], evals["P_y_zeta"]
        point_relation = x1 * y2 - x2 * y1
        return (b * point_relation + (1 - b)) * scalar_term % params.prime

    def _opening_proofs(
        self,
        zeta: int,
        zeta_omega: int,
        l_agg: list[int],
        fixed_columns: Sequence[Column],
        witness_columns: tuple[Column, Column, Column, Column],
        q_poly: list[int],
        opening_challenges: Sequence[int],
    ):
        params = self.ring.params
        aggregated_poly = self._aggregated_opening_poly(
            fixed_columns,
            witness_columns,
            q_poly,
            opening_challenges,
        )
        return params.pcs.open(aggregated_poly, zeta), params.pcs.open(l_agg, zeta_omega)

    def _aggregated_opening_poly(
        self,
        fixed_columns: Sequence[Column],
        witness_columns: tuple[Column, Column, Column, Column],
        q_poly: list[int],
        opening_challenges: Sequence[int],
    ) -> list[int]:
        params = self.ring.params
        c_b, c_accx, c_accy, c_accip = witness_columns
        polynomials = [
            self._coeffs(fixed_columns[0]),
            self._coeffs(fixed_columns[1]),
            self._coeffs(fixed_columns[2]),
            self._coeffs(c_b),
            self._coeffs(c_accip),
            self._coeffs(c_accx),
            self._coeffs(c_accy),
            q_poly,
        ]
        aggregated_poly = [0]
        for poly, scalar in zip(polynomials, opening_challenges, strict=True):
            aggregated_poly = poly_add(
                aggregated_poly,
                poly_scalar_mul(poly, scalar, params.prime),
                params.prime,
            )
        return aggregated_poly

    @staticmethod
    def _coeffs(column: Column) -> list[int]:
        if column.coeffs is None:
            raise ValueError(f"{column.name} column is not interpolated")
        return column.coeffs
