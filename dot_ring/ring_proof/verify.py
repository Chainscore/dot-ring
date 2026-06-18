from typing import Any, NamedTuple, cast

from dot_ring import blst as _blst
from dot_ring.curve.native_field.scalar import Scalar
from dot_ring.ring_proof.constants import OMEGA_2048, S_PRIME
from dot_ring.ring_proof.pcs.kzg import KZG
from dot_ring.ring_proof.pcs.protocol import PCS
from dot_ring.ring_proof.pcs.utils import (
    LinearPcsVerification,
    PcsVerification,
    g1_to_blst,
    pcs_transcript_g1,
)
from dot_ring.ring_proof.transcript.phases import (
    derive_challenges_after_vk,
    phase1_alphas,
    phase2_eval_point,
    phase3_nu_vector,
)
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript

blst = cast(Any, _blst)

# Pre-compute Scalar constants
ONE_S = Scalar(1)
ZERO_S = Scalar(0)


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


def blst_msm(points: list, scalars: list) -> Any:
    """
    Multi-scalar multiplication using Pippenger's algorithm via blst.
    Much faster than individual scalar_mul + add operations.
    """
    if not points:
        return blst.P1()

    return blst.P1_Affines.mult_pippenger(blst.P1_Affines.as_memory(points), scalars)


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
    domain_size_inv_value: int | None = None,
    edwards_a_value: int | Scalar | None = None,
    omega_value: int | None = None,
    include_linearization: bool = False,
) -> int | tuple[int, int, int, int, int, int]:
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
    inv_size = pow(domain_size, -1, prime) if domain_size_inv_value is None else int(domain_size_inv_value) % prime

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
    if not include_linearization:
        return agg_zeta

    if edwards_a_value is None or omega_value is None:
        raise ValueError("edwards_a_value and omega_value are required when include_linearization=True")

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
        True,
    )
    Agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega_out = cast(
        tuple[int, int, int, int, int, int],
        linear_eval_bundle,
    )

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
        LinearPcsVerification(quotient_terms, Phi_zeta_blst, zeta_p, Agg_zeta),
        LinearPcsVerification(linearization_terms, Phi_zeta_omega_blst, zeta_omega, l_zeta_omega_out),
    )


def lagrange_at_zeta(domain_size: int, index: int, zeta: int, omega: int, prime: int) -> Scalar:
    """
    Compute L_i(zeta) using closed-form formula for roots of unity domain.

    L_i(zeta) = (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)

    This is O(1) instead of O(n) polynomial evaluation!
    """
    # Use Scalar for optimized arithmetic
    zeta_s = Scalar(zeta)

    omega_s = Scalar(omega)
    # omega^i
    if index == 0:
        omega_i = ONE_S
    else:
        omega_i = omega_s**index

    # zeta - omega^i
    zeta_minus_omega_i = zeta_s - omega_i

    # Handle special case when zeta == omega^i
    if zeta_minus_omega_i == ZERO_S:
        return ONE_S  # L_i(omega^i) = 1

    # zeta^n - 1
    zeta_n_minus_1 = (zeta_s**domain_size) - ONE_S

    # omega^i / n
    inv_size = Scalar(domain_size) ** -1
    omega_i_over_n = omega_i * inv_size

    # Final: (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)
    result = omega_i_over_n * zeta_n_minus_1 * (zeta_minus_omega_i**-1)

    return result


class Verify:
    prime = S_PRIME
    pcs: type[PCS] = KZG
    omega: int | None = None
    edwards_a = Scalar(-5)

    def __init__(
        self,
        proof: RingProofFields | tuple[Any, ...],
        vk: dict | bytes,
        fixed_cols: list,
        rl_to_proove: tuple | bytes | None,
        rps: tuple,
        seed_point: tuple,
        Domain: list,
        raw_proof_bytes: dict | None = None,
        transcript_challenge: bytes = b"Bandersnatch-SHA512-ELL2-v1",
        padding_rows: int = 4,
        edwards_a: int = -5,
        prime: int = S_PRIME,
        omega: int | None = None,
        pcs: type[PCS] = KZG,
        transcript_prefix: FiatShamirTranscript | None = None,
        domain_size_inv: int | None = None,
        transcript_witness_commitments: tuple[Any, ...] | None = None,
        transcript_quotient_commitment: Any | None = None,
        relation_to_prove: tuple | bytes | None = None,
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

        self.proof_ptr = proof_fields
        self.verifier_key = vk
        self.Cpx, self.Cpy, self.Cs = fixed_cols
        if relation_to_prove is None:
            if rl_to_proove is None:
                raise TypeError("relation_to_prove is required")
            relation_to_prove = rl_to_proove
        elif rl_to_proove is not None and rl_to_proove != relation_to_prove:
            raise ValueError("relation_to_prove and rl_to_proove differ")
        self.relation_to_prove = relation_to_prove
        self.relation_to_proove = relation_to_prove
        self.Result_plus_Seed, self.sp, self.D = rps, seed_point, Domain
        self.padding_rows = padding_rows
        self.prime = prime
        self.omega = omega
        self.pcs = pcs
        self.domain_size_inv = domain_size_inv if domain_size_inv is not None else pow(len(self.D), -1, self.prime)
        self.edwards_a = Scalar(edwards_a)
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

        self.t = transcript_prefix if transcript_prefix is not None else FiatShamirTranscript(self.prime, transcript_challenge)

        # Absorb into transcript
        witness_commitments = (
            transcript_witness_commitments
            if transcript_witness_commitments is not None
            else [self._transcript_g1(cmt) for cmt in proof_fields.witness_commitments]
        )
        # Add quotient and evaluations once we have their serialized form.
        quotient_commitment = transcript_quotient_commitment if transcript_quotient_commitment is not None else self._transcript_g1(proof_fields.c_q)
        if transcript_prefix is not None:
            self.t, self.alpha_list, self.zeta_p, self.V_list = derive_challenges_after_vk(
                self.t,
                self.relation_to_prove,
                witness_commitments,
                quotient_commitment,
                proof_fields.evaluations,
                proof_fields.l_zeta_omega,
            )
        elif transcript_prefix is None:
            evals_bytes = b"".join(v.to_bytes(32, "little") for v in proof_fields.evaluations)
            lin_eval_bytes = proof_fields.l_zeta_omega.to_bytes(32, "little")
            self.t, self.alpha_list = phase1_alphas(
                self.t,
                self.verifier_key,
                self.relation_to_prove,
                witness_commitments,
            )
            self.t, self.zeta_p = phase2_eval_point(self.t, quotient_commitment)
            self.V_list = phase3_nu_vector(self.t, evals_bytes, lin_eval_bytes)

        # Save transcript
        self.cur_t = self.t

    def _domain_omega(self) -> int:
        if self.omega is not None:
            return self.omega
        domain_size = len(self.D)
        if 2048 % domain_size != 0:
            raise ValueError(f"omega must be supplied for domain size {domain_size}")
        return pow(OMEGA_2048, 2048 // domain_size, self.prime)

    def _transcript_g1(self, point: Any) -> Any:
        return pcs_transcript_g1(self.pcs, point)

    def contributions_to_constraints_eval_at_zeta(self) -> tuple[Any, Any, Any, Any, Any, Any, Any]:
        # Convert to Scalar for optimized arithmetic
        zeta = Scalar(self.zeta_p)
        sx, sy = Scalar(self.sp[0]), Scalar(self.sp[1])

        # Precompute common values
        zeta_minus_d4 = zeta - Scalar(self.D[self.last_index])

        # Inline lagrange_at_zeta for index=0 and index=SIZE-4
        # L_i(zeta) = (omega^i / n) * (zeta^n - 1) / (zeta - omega^i)

        # Shared term: zeta^n - 1
        domain_size = len(self.D)
        zeta_n_minus_1 = (zeta**domain_size) - ONE_S

        # L_0: index=0, omega^0 = 1
        # omega^0 / n = 1/n = INV_SIZE_S
        # zeta - omega^0 = zeta - 1
        inv_size = Scalar(domain_size) ** -1
        zeta_minus_1 = zeta - ONE_S
        if zeta_minus_1 == ZERO_S:
            L_0_zeta = ONE_S
        else:
            L_0_zeta = inv_size * zeta_n_minus_1 * (zeta_minus_1**-1)

        # L_N_4: index=SIZE-4, omega^(SIZE-4) from the domain
        # omega^(SIZE-4) / n
        omega_i_N_4 = Scalar(self.D[self.last_index])
        omega_i_over_n_N_4 = omega_i_N_4 * inv_size
        zeta_minus_omega_i_N_4 = zeta - omega_i_N_4
        if zeta_minus_omega_i_N_4 == ZERO_S:
            L_N_4_zeta = ONE_S
        else:
            L_N_4_zeta = omega_i_over_n_N_4 * zeta_n_minus_1 * (zeta_minus_omega_i_N_4**-1)

        # Pre-fetch instance variables and convert to Scalar
        b = Scalar(self.b_zeta)
        accx = Scalar(self.accx_zeta)
        accy = Scalar(self.accy_zeta)
        accip = Scalar(self.accip_zeta)
        px = Scalar(self.px_zeta)
        py = Scalar(self.py_zeta)
        s = Scalar(self.s_zeta)
        rps0 = Scalar(self.Result_plus_Seed[0])
        rps1 = Scalar(self.Result_plus_Seed[1])

        # Constraint 1 - combined operations
        c1_zeta = -(accip + b * s) * zeta_minus_d4

        # Constraints 2 and 3 - reuse calculations
        x1_y1 = accx * accy
        x2_y2 = px * py
        one_minus_b = ONE_S - b

        c2 = b * -(x1_y1 + x2_y2) + one_minus_b * -accx
        c2_zeta = c2 * zeta_minus_d4

        c3 = b * -(x1_y1 - x2_y2) + one_minus_b * -accy
        c3_zeta = c3 * zeta_minus_d4

        # Constraint 4 - simplified
        c4_zeta = b * (ONE_S - b)

        # Constraints 5-7 - combined operations
        c5_zeta = (accx - sx) * L_0_zeta + (accx - rps0) * L_N_4_zeta
        c6_zeta = (accy - sy) * L_0_zeta + (accy - rps1) * L_N_4_zeta
        c7_zeta = accip * L_0_zeta + (accip - ONE_S) * L_N_4_zeta

        return (
            c1_zeta,
            c2_zeta,
            c3_zeta,
            c4_zeta,
            c5_zeta,
            c6_zeta,
            c7_zeta,
        )

    def divide(self, numr: int, denom: int) -> int:
        # Inlined modular division - use built-in pow (faster than external call)
        return (numr * pow(denom, -1, self.prime)) % self.prime

    def is_valid(self) -> bool:
        """If both the verifications are true then sign is valid"""
        return bool(self.pcs.batch_verify_linear_preconverted(list(self._prepare_linear_pcs_verifications())))

    def _prepare_quotient_poly_verification(self) -> PcsVerification:
        """Prepare KZG verification data for quotient polynomial"""
        alphas_list = [Scalar(a) for a in self.alpha_list]
        zeta = Scalar(self.zeta_p)
        v_list = [Scalar(v) for v in self.V_list]

        # cs are now Scalars
        cs = self.contributions_to_constraints_eval_at_zeta()

        # Precompute vanishing polynomial evaluation - combine pow operations
        prod_sum = ONE_S
        for k in range(1, 4):
            prod_sum = prod_sum * (zeta - Scalar(self.D[-k]))

        # Calculate numerator efficiently
        linear_combination = ZERO_S
        for alpha, c in zip(alphas_list, cs, strict=False):
            linear_combination = linear_combination + alpha * c

        # Re-calculating based on original quotient definition, but with optimized s_sum
        s_sum = linear_combination + Scalar(self.l_zeta_omega)
        domain_size = len(self.D)
        zeta_pow_size_minus_1 = (zeta**domain_size) - ONE_S

        # q_zeta = (s_sum * prod_sum) / zeta_pow_size_minus_1
        q_zeta = (s_sum * prod_sum) * (zeta_pow_size_minus_1**-1)

        C_a_blst = [
            self.Cpx_blst,
            self.Cpy_blst,
            self.Cs_blst,
            self.Cb_blst,
            self.Caccip_blst,
            self.Caccx_blst,
            self.Caccy_blst,
            self.Cq_blst,
        ]

        # Use Pippenger MSM instead of loop (much faster)
        # Use self.V_list (ints) directly for blst_msm
        C_agg = blst_msm(C_a_blst, self.V_list)

        # Use Scalars for terms calculation
        px = Scalar(self.px_zeta)
        py = Scalar(self.py_zeta)
        s = Scalar(self.s_zeta)
        b = Scalar(self.b_zeta)
        accip = Scalar(self.accip_zeta)
        accx = Scalar(self.accx_zeta)
        accy = Scalar(self.accy_zeta)
        q = q_zeta  # Scalar

        terms = [
            v_list[0] * px,
            v_list[1] * py,
            v_list[2] * s,
            v_list[3] * b,
            v_list[4] * accip,
            v_list[5] * accx,
            v_list[6] * accy,
            v_list[7] * q,
        ]

        Agg_zeta = Scalar(0)
        for t in terms:
            Agg_zeta = Agg_zeta + t

        return PcsVerification(C_agg, self.Phi_zeta_blst, int(zeta), int(Agg_zeta))

    def _prepare_quotient_poly_verification_linear(self) -> LinearPcsVerification:
        """Prepare quotient KZG verification with an unmaterialized commitment."""
        Agg_zeta = self._native_linear_eval_bundle()[0]

        commitment_terms = (
            (self.Cpx_blst, self.V_list[0]),
            (self.Cpy_blst, self.V_list[1]),
            (self.Cs_blst, self.V_list[2]),
            (self.Cb_blst, self.V_list[3]),
            (self.Caccip_blst, self.V_list[4]),
            (self.Caccx_blst, self.V_list[5]),
            (self.Caccy_blst, self.V_list[6]),
            (self.Cq_blst, self.V_list[7]),
        )
        return LinearPcsVerification(commitment_terms, self.Phi_zeta_blst, self.zeta_p, Agg_zeta)

    def _prepare_linear_pcs_verifications(
        self,
    ) -> tuple[LinearPcsVerification, LinearPcsVerification]:
        """Prepare deferred linear KZG equations from one native scalar pass."""
        Agg_zeta, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega = self._native_linear_eval_bundle()
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
            LinearPcsVerification(quotient_terms, self.Phi_zeta_blst, self.zeta_p, Agg_zeta),
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
            True,
        )
        return cast(tuple[int, int, int, int, int, int], bundle)

    def _prepare_linearization_poly_verification(self) -> PcsVerification:
        """Prepare KZG verification data for linearization polynomial"""
        alphas_list = [Scalar(a) for a in self.alpha_list]
        zeta = Scalar(self.zeta_p)

        zeta_minus_d4 = zeta - Scalar(self.D[self.last_index])

        # Cl1 scalar
        scalar_cl1 = zeta_minus_d4

        # Cl2 scalars
        x1, y1 = Scalar(self.accx_zeta), Scalar(self.accy_zeta)
        x2, y2 = Scalar(self.px_zeta), Scalar(self.py_zeta)
        b = Scalar(self.b_zeta)
        coeff_a = self.edwards_a

        # S_PRIME is scalar field modulus, which Scalar handles implicitly

        C_acc_x_cl2 = b * (y1 * y2 + (coeff_a * x1 * x2)) + (ONE_S - b)
        C_acc_x_f_cl2 = C_acc_x_cl2 * zeta_minus_d4

        # Cl3 scalars
        C_acc_y_cl3 = (b * (x1 * y2 - x2 * y1)) + (ONE_S - b)
        C_acc_y_f_cl3 = C_acc_y_cl3 * zeta_minus_d4

        # Combined scalars
        scalar_accip = alphas_list[0] * scalar_cl1
        scalar_accx = alphas_list[1] * C_acc_x_f_cl2
        scalar_accy = alphas_list[2] * C_acc_y_f_cl3

        # Use MSM for the final combination
        points = [self.Caccip_blst, self.Caccx_blst, self.Caccy_blst]
        scalars = [int(scalar_accip), int(scalar_accx), int(scalar_accy)]
        Cl = blst_msm(points, scalars)

        zeta_omega = zeta * Scalar(self._domain_omega())

        return PcsVerification(Cl, self.Phi_zeta_omega_blst, int(zeta_omega), int(Scalar(self.l_zeta_omega)))

    def _prepare_linearization_poly_verification_linear(self) -> LinearPcsVerification:
        """Prepare linearization KZG verification with an unmaterialized commitment."""
        _, scalar_accip, scalar_accx, scalar_accy, zeta_omega, l_zeta_omega = self._native_linear_eval_bundle()
        commitment_terms = (
            (self.Caccip_blst, scalar_accip),
            (self.Caccx_blst, scalar_accx),
            (self.Caccy_blst, scalar_accy),
        )
        return LinearPcsVerification(commitment_terms, self.Phi_zeta_omega_blst, zeta_omega, l_zeta_omega)
