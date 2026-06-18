from typing import Any, NamedTuple

from dot_ring.ring_proof.constants import OMEGA_2048, S_PRIME
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


def _ring_proof_fields(proof: RingProofFields | tuple[Any, ...]) -> RingProofFields:
    if isinstance(proof, RingProofFields):
        return proof
    return RingProofFields(*proof)


def _compute_quotient_and_linearization_terms(
    alpha_list: list[int],
    v_list: list[int],
    zeta_value: int,
    px_value: int,
    py_value: int,
    s_value: int,
    b_value: int,
    accip_value: int,
    accx_value: int,
    accy_value: int,
    l_zeta_omega_value: int,
    seed_x_value: int,
    seed_y_value: int,
    result_seed_x_value: int,
    result_seed_y_value: int,
    domain_last_value: int,
    domain_neg1_value: int,
    domain_neg2_value: int,
    domain_neg3_value: int,
    domain_size: int,
    domain_size_inv_value: int,
    edwards_a_value: int,
    omega_value: int,
) -> tuple[int, int, int, int, int, int]:
    if len(alpha_list) < 7 or len(v_list) < 8:
        raise ValueError("expected at least 7 alpha values and 8 aggregation values")

    prime = S_PRIME
    alphas = [int(value) % prime for value in alpha_list[:7]]
    v_values = [int(value) % prime for value in v_list[:8]]
    zeta = int(zeta_value) % prime
    px = int(px_value) % prime
    py = int(py_value) % prime
    s = int(s_value) % prime
    b = int(b_value) % prime
    accip = int(accip_value) % prime
    accx = int(accx_value) % prime
    accy = int(accy_value) % prime
    l_zeta_omega = int(l_zeta_omega_value) % prime
    seed_x = int(seed_x_value) % prime
    seed_y = int(seed_y_value) % prime
    result_seed_x = int(result_seed_x_value) % prime
    result_seed_y = int(result_seed_y_value) % prime
    domain_last = int(domain_last_value) % prime
    domain_neg1 = int(domain_neg1_value) % prime
    domain_neg2 = int(domain_neg2_value) % prime
    domain_neg3 = int(domain_neg3_value) % prime
    inv_size = int(domain_size_inv_value) % prime

    zeta_n_minus_1 = (pow(zeta, domain_size, prime) - 1) % prime
    zeta_minus_d4 = (zeta - domain_last) % prime
    zeta_minus_1 = (zeta - 1) % prime
    zeta_minus_last = (zeta - domain_last) % prime

    if zeta_minus_1 == 0:
        l0 = 1
        inv_den = pow((zeta_minus_last * zeta_n_minus_1) % prime, -1, prime)
        inv_zeta_minus_last = (zeta_n_minus_1 * inv_den) % prime
        inv_zeta_n_minus_1 = (zeta_minus_last * inv_den) % prime
        ln = domain_last * inv_size % prime
        ln = ln * zeta_n_minus_1 % prime
        ln = ln * inv_zeta_minus_last % prime
    elif zeta_minus_last == 0:
        ln = 1
        inv_den = pow((zeta_minus_1 * zeta_n_minus_1) % prime, -1, prime)
        inv_zeta_minus_1 = (zeta_n_minus_1 * inv_den) % prime
        inv_zeta_n_minus_1 = (zeta_minus_1 * inv_den) % prime
        l0 = inv_size * zeta_n_minus_1 % prime
        l0 = l0 * inv_zeta_minus_1 % prime
    else:
        den01 = zeta_minus_1 * zeta_minus_last % prime
        inv_den = pow((den01 * zeta_n_minus_1) % prime, -1, prime)
        inv_zeta_n_minus_1 = den01 * inv_den % prime
        tmp = zeta_n_minus_1 * inv_den % prime
        inv_zeta_minus_1 = zeta_minus_last * tmp % prime
        inv_zeta_minus_last = zeta_minus_1 * tmp % prime
        l0 = inv_size * zeta_n_minus_1 % prime
        l0 = l0 * inv_zeta_minus_1 % prime
        ln = domain_last * inv_size % prime
        ln = ln * zeta_n_minus_1 % prime
        ln = ln * inv_zeta_minus_last % prime

    one_minus_b = (1 - b) % prime
    x1_y1 = accx * accy % prime
    x2_y2 = px * py % prime

    c_values = [
        (-(accip + b * s) * zeta_minus_d4) % prime,
        ((b * (-(x1_y1 + x2_y2)) + one_minus_b * (-accx)) * zeta_minus_d4) % prime,
        ((b * (-(x1_y1 - x2_y2)) + one_minus_b * (-accy)) * zeta_minus_d4) % prime,
        b * one_minus_b % prime,
        ((accx - seed_x) * l0 + (accx - result_seed_x) * ln) % prime,
        ((accy - seed_y) * l0 + (accy - result_seed_y) * ln) % prime,
        (accip * l0 + (accip - 1) * ln) % prime,
    ]
    linear_combination = sum((alpha * c_value) % prime for alpha, c_value in zip(alphas, c_values, strict=True)) % prime

    prod_sum = (zeta - domain_neg1) % prime
    prod_sum = prod_sum * ((zeta - domain_neg2) % prime) % prime
    prod_sum = prod_sum * ((zeta - domain_neg3) % prime) % prime
    q_zeta = (linear_combination + l_zeta_omega) % prime
    q_zeta = q_zeta * prod_sum % prime
    q_zeta = q_zeta * inv_zeta_n_minus_1 % prime

    terms = (px, py, s, b, accip, accx, accy, q_zeta)
    agg_zeta = sum((v * term) % prime for v, term in zip(v_values, terms, strict=True)) % prime

    edwards_a = int(edwards_a_value) % prime
    omega = int(omega_value) % prime
    c_acc_x = b * ((accy * py + edwards_a * accx * px) % prime) % prime
    c_acc_x = (c_acc_x + one_minus_b) % prime
    scalar_accx = alphas[1] * (c_acc_x * zeta_minus_d4 % prime) % prime

    c_acc_y = b * ((accx * py - px * accy) % prime) % prime
    c_acc_y = (c_acc_y + one_minus_b) % prime
    scalar_accy = alphas[2] * (c_acc_y * zeta_minus_d4 % prime) % prime

    scalar_accip = alphas[0] * zeta_minus_d4 % prime
    zeta_omega = zeta * omega % prime
    return agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega


def prepare_linear_pcs_verifications_fast(
    proof: RingProofFields | tuple[Any, ...],
    fixed_cols_blst: tuple[Any, Any, Any],
    relation_to_prove: tuple[int, int],
    result_plus_seed: tuple[int, int],
    seed_point: tuple[int, int],
    domain: list[int],
    padding_rows: int,
    domain_size_inv: int,
    edwards_a: int,
    omega: int,
    transcript_prefix: FiatShamirTranscript,
    witness_commitments: bytes,
    quotient_commitment: bytes,
) -> tuple[LinearPcsVerification, LinearPcsVerification]:
    proof_fields = _ring_proof_fields(proof)

    _, alpha_list, zeta_p, v_list = derive_challenges_after_vk(
        transcript_prefix,
        relation_to_prove,
        witness_commitments,
        quotient_commitment,
        proof_fields.evaluations,
        proof_fields.l_zeta_omega,
    )

    last_index = len(domain) - padding_rows
    linear_eval_bundle = _compute_quotient_and_linearization_terms(
        alpha_list,
        v_list,
        zeta_p,
        proof_fields.px_zeta,
        proof_fields.py_zeta,
        proof_fields.s_zeta,
        proof_fields.b_zeta,
        proof_fields.accip_zeta,
        proof_fields.accx_zeta,
        proof_fields.accy_zeta,
        proof_fields.l_zeta_omega,
        seed_point[0],
        seed_point[1],
        result_plus_seed[0],
        result_plus_seed[1],
        domain[last_index],
        domain[-1],
        domain[-2],
        domain[-3],
        len(domain),
        domain_size_inv,
        edwards_a,
        omega,
    )
    agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega_out = linear_eval_bundle

    Cpx_blst, Cpy_blst, Cs_blst = fixed_cols_blst
    Cb_blst = g1_to_blst(proof_fields.c_b)
    Caccip_blst = g1_to_blst(proof_fields.c_accip)
    Caccx_blst = g1_to_blst(proof_fields.c_accx)
    Caccy_blst = g1_to_blst(proof_fields.c_accy)
    Cq_blst = g1_to_blst(proof_fields.c_q)
    Phi_zeta_blst = g1_to_blst(proof_fields.phi_zeta)
    Phi_zeta_omega_blst = g1_to_blst(proof_fields.phi_zeta_omega)

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
    prime = S_PRIME
    pcs: type[PCS] = KZG
    omega: int | None = None
    edwards_a = -5

    def __init__(
        self,
        proof: RingProofFields | tuple[Any, ...],
        fixed_cols: list,
        relation_to_prove: tuple | bytes,
        result_plus_seed: tuple,
        seed_point: tuple,
        domain: list,
        transcript_prefix: FiatShamirTranscript,
        padding_rows: int = 4,
        edwards_a: int = -5,
        prime: int = S_PRIME,
        omega: int | None = None,
        pcs: type[PCS] = KZG,
        domain_size_inv: int | None = None,
        transcript_witness_commitments: tuple[Any, ...] | bytes | None = None,
        transcript_quotient_commitment: Any | None = None,
    ) -> None:
        proof_fields = _ring_proof_fields(proof)
        self.Cb = proof_fields.c_b
        self.Caccip = proof_fields.c_accip
        self.Caccx = proof_fields.c_accx
        self.Caccy = proof_fields.c_accy
        self.px_zeta = proof_fields.px_zeta
        self.py_zeta = proof_fields.py_zeta
        self.s_zeta = proof_fields.s_zeta
        self.b_zeta = proof_fields.b_zeta
        self.accip_zeta = proof_fields.accip_zeta
        self.accx_zeta = proof_fields.accx_zeta
        self.accy_zeta = proof_fields.accy_zeta
        self.Cq = proof_fields.c_q
        self.l_zeta_omega = proof_fields.l_zeta_omega
        self.Phi_zeta = proof_fields.phi_zeta
        self.Phi_zeta_omega = proof_fields.phi_zeta_omega

        self.Cpx, self.Cpy, self.Cs = fixed_cols
        self.relation_to_prove = relation_to_prove
        self.Result_plus_Seed, self.sp, self.D = result_plus_seed, seed_point, domain
        self.padding_rows = padding_rows
        self.prime = prime
        self.omega = omega
        self.pcs = pcs
        self.domain_size_inv = domain_size_inv if domain_size_inv is not None else pow(len(self.D), -1, self.prime)
        self.edwards_a = edwards_a
        if self.padding_rows < 1 or self.padding_rows >= len(self.D):
            raise ValueError("padding_rows must be >= 1 and less than domain size")
        self.last_index = len(self.D) - self.padding_rows

        self.Cb_blst = g1_to_blst(self.Cb)
        self.Caccip_blst = g1_to_blst(self.Caccip)
        self.Caccx_blst = g1_to_blst(self.Caccx)
        self.Caccy_blst = g1_to_blst(self.Caccy)
        self.Cq_blst = g1_to_blst(self.Cq)
        self.Phi_zeta_blst = g1_to_blst(self.Phi_zeta)
        self.Phi_zeta_omega_blst = g1_to_blst(self.Phi_zeta_omega)

        self.Cpx_blst = g1_to_blst(self.Cpx)
        self.Cpy_blst = g1_to_blst(self.Cpy)
        self.Cs_blst = g1_to_blst(self.Cs)

        self.t = transcript_prefix

        witness_commitments = (
            transcript_witness_commitments
            if transcript_witness_commitments is not None
            else [self.pcs.serialize_g1_uncompressed(cmt) for cmt in proof_fields.witness_commitments]
        )
        # Add quotient and evaluations once we have their serialized form.
        quotient_commitment = (
            transcript_quotient_commitment if transcript_quotient_commitment is not None else self.pcs.serialize_g1_uncompressed(proof_fields.c_q)
        )
        self.t, self.alpha_list, self.zeta_p, self.V_list = derive_challenges_after_vk(
            self.t,
            self.relation_to_prove,
            witness_commitments,
            quotient_commitment,
            proof_fields.evaluations,
            proof_fields.l_zeta_omega,
        )

    def _domain_omega(self) -> int:
        if self.omega is not None:
            return self.omega
        domain_size = len(self.D)
        if 2048 % domain_size != 0:
            raise ValueError(f"omega must be supplied for domain size {domain_size}")
        return pow(OMEGA_2048, 2048 // domain_size, self.prime)

    def is_valid(self) -> bool:
        """If both the verifications are true then sign is valid"""
        return bool(self.pcs.batch_verify_linear_preconverted(list(self._prepare_linear_pcs_verifications())))

    def _prepare_linear_pcs_verifications(
        self,
    ) -> tuple[LinearPcsVerification, LinearPcsVerification]:
        """Prepare deferred linear KZG equations from one native scalar pass."""
        agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega = self._native_linear_eval_bundle()
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

    def _native_linear_eval_bundle(self) -> tuple[int, int, int, int, int, int]:
        omega = self._domain_omega()
        bundle = _compute_quotient_and_linearization_terms(
            self.alpha_list,
            self.V_list,
            self.zeta_p,
            self.px_zeta,
            self.py_zeta,
            self.s_zeta,
            self.b_zeta,
            self.accip_zeta,
            self.accx_zeta,
            self.accy_zeta,
            self.l_zeta_omega,
            self.sp[0],
            self.sp[1],
            self.Result_plus_Seed[0],
            self.Result_plus_Seed[1],
            self.D[self.last_index],
            self.D[-1],
            self.D[-2],
            self.D[-3],
            len(self.D),
            self.domain_size_inv,
            self.edwards_a,
            omega,
        )
        return bundle
