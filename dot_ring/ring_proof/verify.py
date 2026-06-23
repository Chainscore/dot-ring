from typing import Any, NamedTuple

from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.params import ROOT_OF_UNITY_2048, RingProofParams
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.protocol import PCS
from dot_ring.ring_proof.pcs.utils import (
    LinearPcsVerification,
    g1_to_blst,
)
from dot_ring.ring_proof.transcript.phases import (
    derive_challenges_after_vk,
)
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript


class RingProofFields(NamedTuple):
    c_b: Any
    c_accip: Any
    c_accx: Any
    c_accy: Any
    px_zeta: int
    py_zeta: int
    s_zeta: int
    b_zeta: int
    accip_zeta: int
    accx_zeta: int
    accy_zeta: int
    c_q: Any
    l_zeta_omega: int
    phi_zeta: Any
    phi_zeta_omega: Any

    @property
    def evaluations(self) -> tuple[int, int, int, int, int, int, int]:
        return (
            self.px_zeta,
            self.py_zeta,
            self.s_zeta,
            self.b_zeta,
            self.accip_zeta,
            self.accx_zeta,
            self.accy_zeta,
        )

    @property
    def witness_commitments(self) -> tuple[Any, Any, Any, Any]:
        return (self.c_b, self.c_accip, self.c_accx, self.c_accy)


def _compute_quotient_and_linearization_terms(
    alpha_list: list[int],
    v_list: list[int],
    zeta_value: int,
    proof: RingProofFields,
    seed: CurvePoint,
    result_seed: CurvePoint,
    domain: list[int],
    edwards_a_value: int,
    omega: int,
    prime: int,
) -> tuple[int, int, int, int, int, int]:
    if len(alpha_list) < 7 or len(v_list) < 8:
        raise ValueError("expected at least 7 alpha values and 8 aggregation values")

    domain_size_inv = pow(len(domain), -1, prime)

    alphas = [int(value) % prime for value in alpha_list[:7]]
    v_values = [int(value) % prime for value in v_list[:8]]
    zeta = int(zeta_value) % prime

    zeta_n_minus_1 = (pow(zeta, len(domain), prime) - 1) % prime
    zeta_minus_d4 = (zeta - domain[-4]) % prime
    zeta_minus_1 = (zeta - 1) % prime
    zeta_minus_last = (zeta - domain[-4]) % prime

    if seed.x is None or seed.y is None or result_seed.x is None or result_seed.y is None:
        raise ValueError("seed and result_seed must be valid points with non-None coordinates")

    if zeta_minus_1 == 0:
        l0 = 1
        inv_den = pow((zeta_minus_last * zeta_n_minus_1) % prime, -1, prime)
        inv_zeta_minus_last = (zeta_n_minus_1 * inv_den) % prime
        inv_zeta_n_minus_1 = (zeta_minus_last * inv_den) % prime
        ln = domain[-4] * domain_size_inv % prime
        ln = ln * zeta_n_minus_1 % prime
        ln = ln * inv_zeta_minus_last % prime
    elif zeta_minus_last == 0:
        ln = 1
        inv_den = pow((zeta_minus_1 * zeta_n_minus_1) % prime, -1, prime)
        inv_zeta_minus_1 = (zeta_n_minus_1 * inv_den) % prime
        inv_zeta_n_minus_1 = (zeta_minus_1 * inv_den) % prime
        l0 = domain_size_inv * zeta_n_minus_1 % prime
        l0 = l0 * inv_zeta_minus_1 % prime
    else:
        den01 = zeta_minus_1 * zeta_minus_last % prime
        inv_den = pow((den01 * zeta_n_minus_1) % prime, -1, prime)
        inv_zeta_n_minus_1 = den01 * inv_den % prime
        tmp = zeta_n_minus_1 * inv_den % prime
        inv_zeta_minus_1 = zeta_minus_last * tmp % prime
        inv_zeta_minus_last = zeta_minus_1 * tmp % prime
        l0 = domain_size_inv * zeta_n_minus_1 % prime
        l0 = l0 * inv_zeta_minus_1 % prime
        ln = domain[-4] * domain_size_inv % prime
        ln = ln * zeta_n_minus_1 % prime
        ln = ln * inv_zeta_minus_last % prime

    one_minus_b = (1 - proof.b_zeta) % prime
    x1_y1 = proof.accx_zeta * proof.accy_zeta % prime
    x2_y2 = proof.px_zeta * proof.py_zeta % prime

    c_values = [
        (-(proof.accip_zeta + proof.b_zeta * proof.s_zeta) * zeta_minus_d4) % prime,
        ((proof.b_zeta * (-(x1_y1 + x2_y2)) + one_minus_b * (-proof.accx_zeta)) * zeta_minus_d4) % prime,
        ((proof.b_zeta * (-(x1_y1 - x2_y2)) + one_minus_b * (-proof.accy_zeta)) * zeta_minus_d4) % prime,
        proof.b_zeta * one_minus_b % prime,
        ((proof.accx_zeta - seed.x) * l0 + (proof.accx_zeta - result_seed.x) * ln) % prime,
        ((proof.accy_zeta - seed.y) * l0 + (proof.accy_zeta - result_seed.y) * ln) % prime,
        (proof.accip_zeta * l0 + (proof.accip_zeta - 1) * ln) % prime,
    ]
    linear_combination = sum((alpha * c_value) % prime for alpha, c_value in zip(alphas, c_values, strict=True)) % prime

    prod_sum = (zeta - domain[-1]) % prime
    prod_sum = prod_sum * ((zeta - domain[-2]) % prime) % prime
    prod_sum = prod_sum * ((zeta - domain[-3]) % prime) % prime
    q_zeta = (linear_combination + proof.l_zeta_omega) % prime
    q_zeta = q_zeta * prod_sum % prime
    q_zeta = q_zeta * inv_zeta_n_minus_1 % prime

    terms = (proof.px_zeta, proof.py_zeta, proof.s_zeta, proof.b_zeta, proof.accip_zeta, proof.accx_zeta, proof.accy_zeta, q_zeta)
    agg_zeta = sum((v * term) % prime for v, term in zip(v_values, terms, strict=True)) % prime

    edwards_a = int(edwards_a_value) % prime
    c_acc_x = proof.b_zeta * ((proof.accy_zeta * proof.py_zeta + edwards_a * proof.accx_zeta * proof.px_zeta) % prime) % prime
    c_acc_x = (c_acc_x + one_minus_b) % prime
    scalar_accx = alphas[1] * (c_acc_x * zeta_minus_d4 % prime) % prime

    c_acc_y = proof.b_zeta * ((proof.accx_zeta * proof.py_zeta - proof.px_zeta * proof.accy_zeta) % prime) % prime
    c_acc_y = (c_acc_y + one_minus_b) % prime
    scalar_accy = alphas[2] * (c_acc_y * zeta_minus_d4 % prime) % prime

    scalar_accip = alphas[0] * zeta_minus_d4 % prime
    zeta_omega = zeta * omega % prime
    return agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, proof.l_zeta_omega


def linear_pcs_verifications(
    proof: RingProofFields,
    fixed_cols_blst: tuple[Any, Any, Any],
    relation_to_prove: CurvePoint,
    result_plus_seed: CurvePoint,
    seed_point: CurvePoint,
    params: RingProofParams,
    transcript_prefix: FiatShamirTranscript,
    witness_commitments: bytes,
    quotient_commitment: bytes,
) -> tuple[LinearPcsVerification, LinearPcsVerification]:
    domain, a, omega, prime = params.domain, params.cv.curve.params.a, params.omega, params.prime

    _, alpha_list, zeta_p, v_list = derive_challenges_after_vk(
        transcript_prefix,
        relation_to_prove,
        witness_commitments,
        quotient_commitment,
        proof.evaluations,
        proof.l_zeta_omega,
    )

    linear_eval_bundle = _compute_quotient_and_linearization_terms(
        alpha_list,
        v_list,
        zeta_p,
        proof,
        seed_point,
        result_plus_seed,
        domain,
        a,
        omega,
        prime,
    )
    agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega_out = linear_eval_bundle

    Cpx_blst, Cpy_blst, Cs_blst = fixed_cols_blst
    Cb_blst = g1_to_blst(proof.c_b)
    Caccip_blst = g1_to_blst(proof.c_accip)
    Caccx_blst = g1_to_blst(proof.c_accx)
    Caccy_blst = g1_to_blst(proof.c_accy)
    Cq_blst = g1_to_blst(proof.c_q)
    Phi_zeta_blst = g1_to_blst(proof.phi_zeta)
    Phi_zeta_omega_blst = g1_to_blst(proof.phi_zeta_omega)

    quotient_terms = (
        (Cpx_blst, v_list[0]),
        (Cpy_blst, v_list[1]),
        (Cs_blst, v_list[2]),
        (Cb_blst, v_list[3]),
        (Caccip_blst, v_list[4]),
        (Caccx_blst, v_list[5]),
        (Caccy_blst, v_list[6]),
        (Cq_blst, v_list[7]),
    )
    linearization_terms = (
        (Caccip_blst, scalar_accip),
        (Caccx_blst, scalar_accx),
        (Caccy_blst, scalar_accy),
    )
    return (
        LinearPcsVerification(quotient_terms, Phi_zeta_blst, zeta_p, agg_zeta),
        LinearPcsVerification(linearization_terms, Phi_zeta_omega_blst, zeta_omega, l_zeta_omega_out),
    )


class Verify:
    def __init__(
        self,
        proof: RingProofFields,
        fixed_cols: list,
        relation_to_prove: CurvePoint,
        result_plus_seed: CurvePoint,
        seed_point: CurvePoint,
        domain: list,
        transcript_prefix: FiatShamirTranscript,
        padding_rows: int = 4,
        edwards_a: int = -5,
        prime: int | None = None,
        omega: int | None = None,
        pcs: type[PCS] = KZG,
        transcript_witness_commitments: tuple[Any, ...] | bytes | None = None,
        transcript_quotient_commitment: Any | None = None,
    ) -> None:
        self.proof = proof

        self.Cpx, self.Cpy, self.Cs = fixed_cols
        self.relation_to_prove = relation_to_prove
        self.Result_plus_Seed = result_plus_seed
        self.sp = seed_point
        self.D = domain
        self.padding_rows = padding_rows
        self.prime = prime if prime is not None else relation_to_prove.curve.params.field_modulus
        self.omega = omega
        self.pcs = pcs
        self.edwards_a = edwards_a
        if self.padding_rows < 1 or self.padding_rows >= len(self.D):
            raise ValueError("padding_rows must be >= 1 and less than domain size")

        self.Cb_blst = g1_to_blst(self.proof.c_b)
        self.Caccip_blst = g1_to_blst(self.proof.c_accip)
        self.Caccx_blst = g1_to_blst(self.proof.c_accx)
        self.Caccy_blst = g1_to_blst(self.proof.c_accy)
        self.Cq_blst = g1_to_blst(self.proof.c_q)
        self.Phi_zeta_blst = g1_to_blst(self.proof.phi_zeta)
        self.Phi_zeta_omega_blst = g1_to_blst(self.proof.phi_zeta_omega)

        self.Cpx_blst = g1_to_blst(self.Cpx)
        self.Cpy_blst = g1_to_blst(self.Cpy)
        self.Cs_blst = g1_to_blst(self.Cs)

        self.t = transcript_prefix

        witness_commitments = (
            transcript_witness_commitments
            if transcript_witness_commitments is not None
            else [self.pcs.serialize_g1_uncompressed(cmt) for cmt in proof.witness_commitments]
        )
        # Add quotient and evaluations once we have their serialized form.
        quotient_commitment = (
            transcript_quotient_commitment if transcript_quotient_commitment is not None else self.pcs.serialize_g1_uncompressed(proof.c_q)
        )
        self.t, self.alpha_list, self.zeta_p, self.V_list = derive_challenges_after_vk(
            self.t,
            self.relation_to_prove,
            witness_commitments,
            quotient_commitment,
            proof.evaluations,
            proof.l_zeta_omega,
        )

    def _domain_omega(self) -> int:
        if self.omega is not None:
            return self.omega
        domain_size = len(self.D)
        if 2048 % domain_size != 0:
            raise ValueError(f"omega must be supplied for domain size {domain_size}")
        return pow(ROOT_OF_UNITY_2048, 2048 // domain_size, self.prime)

    def is_valid(self) -> bool:
        """If both the verifications are true then sign is valid"""
        return bool(self.pcs.batch_verify_linear_preconverted(list(self._linear_pcs_verifications())))

    def _linear_pcs_verifications(
        self,
    ) -> tuple[LinearPcsVerification, LinearPcsVerification]:
        """Prepare deferred linear KZG equations from one native scalar pass."""
        agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega = _compute_quotient_and_linearization_terms(
            self.alpha_list,
            self.V_list,
            self.zeta_p,
            self.proof,
            self.sp,
            self.Result_plus_Seed,
            self.D,
            self.edwards_a,
            self._domain_omega(),
            self.prime,
        )
        quotient_terms = (
            (self.Cpx_blst, self.V_list[0]),
            (self.Cpy_blst, self.V_list[1]),
            (self.Cs_blst, self.V_list[2]),
            (self.Cb_blst, self.V_list[3]),
            (self.Caccip_blst, self.V_list[4]),
            (self.Caccx_blst, self.V_list[5]),
            (self.Caccy_blst, self.V_list[6]),
            (self.Cq_blst, self.V_list[7]),
        )
        linearization_terms = (
            (self.Caccip_blst, scalar_accip),
            (self.Caccx_blst, scalar_accx),
            (self.Caccy_blst, scalar_accy),
        )
        return (
            LinearPcsVerification(quotient_terms, self.Phi_zeta_blst, self.zeta_p, agg_zeta),
            LinearPcsVerification(linearization_terms, self.Phi_zeta_omega_blst, zeta_omega, l_zeta_omega),
        )
