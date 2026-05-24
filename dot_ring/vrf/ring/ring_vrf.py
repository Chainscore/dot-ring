from dataclasses import dataclass
from typing import Any, cast

from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.columns.columns import Column, WitnessColumnBuilder
from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints
from dot_ring.ring_proof.constraints.constraints import RingConstraintBuilder
from dot_ring.ring_proof.helpers import Helpers as H
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.opening import Opening
from dot_ring.ring_proof.proof.aggregation_poly import AggPoly
from dot_ring.ring_proof.proof.linearization_poly import LAggPoly
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.transcript.phases import phase1_alphas, phase3_nu_vector
from dot_ring.ring_proof.transcript.transcript import Transcript
from dot_ring.ring_proof.verify import Verify
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

from ..vrf import VRF
from .ring import Ring
from .ring_batch_item import RingBatchItem
from .ring_batch_verifier import RingBatchVerifier
from .ring_context import RingContext, RingSetup
from .ring_keys import parse_concatenated_keys as _parse_concatenated_keys
from .ring_root import RingRoot
from .ring_serialization import (
    compress_g1 as _compress_g1,
)
from .ring_serialization import (
    decompress_g1 as _decompress_g1,
)
from .ring_serialization import (
    ring_proof_len as _ring_proof_len,
)
from .ring_serialization import (
    transcript_g1 as _transcript_g1,
)
from .ring_serialization import (
    transcript_vk as _transcript_vk,
)
from .ring_verifier_key_builder import RingVerifierKeyBuilder


@dataclass
class RingVRF(VRF[Any]):
    """
    Ring VRF implementation.

    This implementation provides Ring VRF operations combining
    Pedersen VRF proofs with ring signatures.

    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.ring.ring_vrf import RingVRF
    >>> proof = RingVRF[Bandersnatch].prove(alpha, ad, secret_key, producer_key, keys)
    >>> verified = RingVRF[Bandersnatch].verify(ad, ring_root, proof)

    Note: Ring VRF currently only supports Bandersnatch curve.
    """

    pedersen_proof: PedersenVRF | None
    c_b: Column
    c_accip: Column
    c_accx: Column
    c_accy: Column
    px_zeta: int
    py_zeta: int
    s_zeta: int
    b_zeta: int
    accip_zeta: int
    accx_zeta: int
    accy_zeta: int
    c_q: Column
    l_zeta_omega: int
    open_agg_zeta: Opening
    open_l_zeta_omega: Opening

    def to_bytes(self) -> bytes:
        """
        Serialize the Ring VRF proof to bytes.

        Returns:
            bytes: Bytes representation of the Ring VRF proof
        """
        assert self.c_b.commitment is not None
        assert self.c_accip.commitment is not None
        assert self.c_accx.commitment is not None
        assert self.c_accy.commitment is not None
        assert self.c_q.commitment is not None
        assert self.open_agg_zeta.proof is not None
        assert self.open_l_zeta_omega.proof is not None

        assert self.pedersen_proof is not None
        params = RingProofParams(cv=self.cv)
        return self.pedersen_proof.to_bytes() + b"".join(
            (
                _compress_g1(params, self.c_b.commitment),
                _compress_g1(params, self.c_accip.commitment),
                _compress_g1(params, self.c_accx.commitment),
                _compress_g1(params, self.c_accy.commitment),
                H.to_l_endian(self.px_zeta),
                H.to_l_endian(self.py_zeta),
                H.to_l_endian(self.s_zeta),
                H.to_l_endian(self.b_zeta),
                H.to_l_endian(self.accip_zeta),
                H.to_l_endian(self.accx_zeta),
                H.to_l_endian(self.accy_zeta),
                _compress_g1(params, self.c_q.commitment),
                H.to_l_endian(self.l_zeta_omega),
                _compress_g1(params, self.open_agg_zeta.proof),
                _compress_g1(params, self.open_l_zeta_omega.proof),
            )
        )

    @classmethod
    def from_bytes(cls, proof: bytes, skip_pedersen: bool = False) -> "RingVRF":
        """
        Deserialize the Ring VRF proof from bytes.

        Args:
            proof: Bytes representation of the Ring VRF proof
        Returns:
            RingVRF: Deserialized Ring VRF proof object
        """
        if not skip_pedersen:
            point_len = cls.cv.curve.POINT_LEN * (2 if cls.cv.curve.UNCOMPRESSED else 1)
            scalar_size = (cls.cv.curve.ORDER.bit_length() + 7) // 8
            pedersen_len = 4 * point_len + 2 * scalar_size
            pedersen_proof = PedersenVRF[cls.cv].from_bytes(proof[:pedersen_len])  # type: ignore[name-defined]
            offset = pedersen_len
        else:
            pedersen_proof = None
            offset = 0

        params = RingProofParams(cv=cls.cv)
        expected = offset + _ring_proof_len(params)
        if len(proof) != expected:
            raise ValueError(f"invalid Ring VRF proof length: expected {expected}, got {len(proof)}")

        commitment_size = params.pcs.commitment_size

        c_b_commitment = _decompress_g1(params, proof[offset : offset + commitment_size])
        offset += commitment_size
        c_accip_commitment = _decompress_g1(params, proof[offset : offset + commitment_size])
        offset += commitment_size
        c_accx_commitment = _decompress_g1(params, proof[offset : offset + commitment_size])
        offset += commitment_size
        c_accy_commitment = _decompress_g1(params, proof[offset : offset + commitment_size])
        offset += commitment_size

        px_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        py_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        s_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        b_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        accip_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        accx_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32
        accy_zeta = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32

        c_q_commitment = _decompress_g1(params, proof[offset : offset + commitment_size])
        offset += commitment_size

        l_zeta_omega = H.to_scalar_int(proof[offset : offset + 32])
        offset += 32

        open_agg_zeta_commitment = _decompress_g1(params, proof[offset : offset + commitment_size])
        offset += commitment_size
        open_l_zeta_omega_commitment = _decompress_g1(params, proof[offset : offset + commitment_size])
        offset += commitment_size
        return cls(
            pedersen_proof=pedersen_proof,
            c_b=Column(name="c_b", evals=[], commitment=c_b_commitment),
            c_accip=Column(name="c_accip", evals=[], commitment=c_accip_commitment),
            c_accx=Column(name="c_accx", evals=[], commitment=c_accx_commitment),
            c_accy=Column(name="c_accy", evals=[], commitment=c_accy_commitment),
            px_zeta=px_zeta,
            py_zeta=py_zeta,
            s_zeta=s_zeta,
            b_zeta=b_zeta,
            accip_zeta=accip_zeta,
            accx_zeta=accx_zeta,
            accy_zeta=accy_zeta,
            c_q=Column(name="c_q", evals=[], commitment=c_q_commitment),
            l_zeta_omega=l_zeta_omega,
            # TODO: Fix Opening initialization; unsafe scalar 0 used temporarily
            open_agg_zeta=Opening(proof=open_agg_zeta_commitment, y=0),  # We only need opening proof to verify
            open_l_zeta_omega=Opening(proof=open_l_zeta_omega_commitment, y=0),  # We only need opening proof to verify
        )

    @classmethod
    def generate_bls_signature(
        cls,
        blinding_factor: int,
        producer_key: bytes | str,
        ring: Ring,
        transcript_challenge: bytes | None = None,
        ring_root: RingRoot | None = None,
    ) -> tuple[
        Column,
        Column,
        Column,
        Column,
        int,
        int,
        int,
        int,
        int,
        int,
        int,
        Column,
        int,
        Any,
        Any,
    ]:
        """
        Returns the Ring Proof as an output.

        Args:
            blinding_factor: Blinding factor from Pedersen VRF
            producer_key: Public key of the prover
            ring: Ring object containing member keys and params
            transcript_challenge: Challenge for Fiat-Shamir
            ring_root: Optional pre-computed ring root for performance
        """
        if transcript_challenge is None:
            transcript_challenge = cls.cv.curve.SUITE_ID or cls.cv.curve.SUITE_STRING
        # Use params from the ring object
        params = ring.params
        producer_key_point = cls.cv.point.string_to_point(producer_key)

        if isinstance(producer_key_point, str) or producer_key_point.is_identity():
            producer_key_pt = params.padding_point
        else:
            producer_key_pt = params.point_to_ring_point(producer_key_point)

        if not ring_root:
            ring_root = RingRoot.from_ring(ring, params)  # ring_root builder

        s_v = ring_root.s.evals
        try:
            producer_index = ring.nm_points.index(producer_key_pt)
        except ValueError as exc:
            raise ValueError("producer key is not in ring") from exc
        witness_obj = WitnessColumnBuilder.from_params(
            ring.nm_points,
            s_v,
            producer_index,
            blinding_factor,
            params,
        )
        witness_res = witness_obj.build()
        witness_relation_res = witness_obj.result(params.blinding_base)
        Result_plus_Seed = witness_obj.result_p_seed(witness_relation_res)
        constraints = RingConstraintBuilder(
            Result_plus_Seed=Result_plus_Seed,  # type: ignore
            px=cast(list[int], ring_root.px.coeffs),
            py=cast(list[int], ring_root.py.coeffs),
            s=cast(list[int], ring_root.s.coeffs),
            b=cast(list[int], witness_res[0].coeffs),
            acc_x=cast(list[int], witness_res[1].coeffs),
            acc_y=cast(list[int], witness_res[2].coeffs),
            acc_ip=cast(list[int], witness_res[3].coeffs),
            params=params,
            seed_point=params.seed_point,
        )

        constraint_dict = constraints.compute()
        fixed_col_commits = [ring_root.px.commitment, ring_root.py.commitment, ring_root.s.commitment]

        ws = witness_res
        witness_commitments = [
            _transcript_g1(params, ws[0].commitment),
            _transcript_g1(params, ws[-1].commitment),
            _transcript_g1(params, ws[1].commitment),
            _transcript_g1(params, ws[2].commitment),
        ]

        vk = _transcript_vk(params, fixed_col_commits)
        t = Transcript(params.prime, transcript_challenge)
        t, alpha = phase1_alphas(t, vk, witness_relation_res, witness_commitments)

        cd = constraint_dict
        c_polys = [cd[val] for val in cd]
        C_agg = aggregate_constraints(c_polys, alpha, params.radix_omega, params.prime, domain=params.domain)
        qp = QuotientPoly(params.domain_size, params.pcs)
        Q_p, C_q = qp.quotient_poly(C_agg)
        C_q_commitment = Column(name="C_q", evals=[], commitment=C_q)
        l_obj = LAggPoly(
            t,
            _transcript_g1(params, C_q),
            list([ring_root.px, ring_root.py, ring_root.s]),
            list(ws),
            alpha,
            domain=params.domain,
            omega=params.omega,
            prime=params.prime,
            padding_rows=params.padding_rows,
            edwards_a=params.ring_edwards_a,
        )
        current_t, zeta, rel_poly_evals, l_agg, zeta_omega, l_zw = l_obj.l_agg_poly()
        _, _, phi_z, phi_zw = AggPoly.proof_contents_phi(
            zeta,
            zeta_omega,
            l_agg,
            list([ring_root.px, ring_root.py, ring_root.s]),
            list(ws),
            Q_p,
            phase3_nu_vector(current_t, list(rel_poly_evals.values()), l_zw),
            prime=params.prime,
            pcs=params.pcs,
        )
        [
            p_x_zeta,
            p_y_zeta,
            s_zeta,
            b_zeta,
            acc_ip_zeta,
            acc_x_zeta,
            acc_y_zeta,
        ] = list(rel_poly_evals.values())
        c_b, c_acc_x, c_acc_y, c_acc_ip = ws[0], ws[1], ws[2], ws[3]
        return (
            c_b,
            c_acc_ip,
            c_acc_x,
            c_acc_y,
            p_x_zeta,
            p_y_zeta,
            s_zeta,
            b_zeta,
            acc_ip_zeta,
            acc_x_zeta,
            acc_y_zeta,
            C_q_commitment,
            l_zw,
            phi_z,
            phi_zw,
        )

    def _ring_proof_verifier(
        self,
        message: bytes | CurvePoint,
        ring: Ring,
        ring_root: RingRoot,
    ) -> Verify:
        fixed_cols_cmts = [
            ring_root.px.commitment,
            ring_root.py.commitment,
            ring_root.s.commitment,
        ]

        if isinstance(message, bytes):
            message_pt = ring.params.cv.point.string_to_point(message)
            if isinstance(message_pt, str):
                raise ValueError("Invalid message point")
            message = message_pt

        rltn = ring.params.point_to_ring_point(message)
        res_plus_seed = ring.params.add_points(ring.params.seed_point, rltn)

        # Ensure commitments are not None
        fixed_cols_cmts_safe = []
        for c in fixed_cols_cmts:
            assert c is not None
            fixed_cols_cmts_safe.append(c)
        verifier_key: dict[str, Any] = _transcript_vk(ring.params, fixed_cols_cmts_safe)

        return Verify(
            (
                self.c_b.commitment,
                self.c_accip.commitment,
                self.c_accx.commitment,
                self.c_accy.commitment,
                self.px_zeta,
                self.py_zeta,
                self.s_zeta,
                self.b_zeta,
                self.accip_zeta,
                self.accx_zeta,
                self.accy_zeta,
                self.c_q.commitment,
                self.l_zeta_omega,
                self.open_agg_zeta.proof,
                self.open_l_zeta_omega.proof,
            ),
            verifier_key,
            fixed_cols_cmts,
            rltn,
            res_plus_seed,
            ring.params.seed_point,
            ring.params.domain,
            transcript_challenge=self.cv.curve.SUITE_ID or self.cv.curve.SUITE_STRING,
            padding_rows=ring.params.padding_rows,
            edwards_a=ring.params.ring_edwards_a,
            prime=ring.params.prime,
            omega=ring.params.omega,
            pcs=ring.params.pcs,
        )

    def verify_ring_proof(
        self,
        message: bytes | CurvePoint,
        ring: Ring,
        ring_root: RingRoot,
    ) -> bool:
        """
        Verifies the Ring Proof
        """
        return self._ring_proof_verifier(message, ring, ring_root).is_valid()

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        ad: bytes,
        secret_key: bytes,
        producer_key: bytes,
        ring: Ring,
        ring_root: RingRoot | None = None,
    ) -> "RingVRF":
        """
        Generate ring VRF proof (pedersen vrf proof + ring_proof).

        Args:
            alpha: VRF input
            ad: Additional data
            secret_key: Prover's secret key
            producer_key: Prover's public key
            ring: Ring object containing member keys. Params are auto-constructed if not provided to Ring.
            ring_root: Pre-computed ring root. If provided, skips expensive ring column construction (~335ms for 1023 members).

        Returns:
            RingVRF proof

        Examples:
            >>> ring = Ring(keys)  # Automatically determines optimal domain size
            >>> proof = RingVRF[Bandersnatch].prove(alpha, ad, sk, pk, ring)
        """
        pedersen_proof = PedersenVRF[cast(Any, cls).cv].prove(alpha, secret_key, ad)  # type: ignore[misc]

        ring_proof = cls.generate_bls_signature(pedersen_proof._blinding_factor, producer_key, ring=ring, ring_root=ring_root)

        return cls(pedersen_proof, *ring_proof)

    @classmethod
    def parse_keys(cls, keys: bytes) -> list[bytes]:
        """Parse a bytes object containing concatenated keys into a list of individual keys.

        Args:
            keys (bytes): A bytes object containing concatenated keys.

        Returns:
            List[bytes]: A list of individual keys extracted from the input bytes object.
        """
        return _parse_concatenated_keys(keys, cls.cv)

    def verify(self, input: bytes, ad_data: bytes, ring: Ring, ring_root: RingRoot) -> bool:
        """
        Verify ring VRF proof (pedersen_proof + ring_proof)
        """
        if self.pedersen_proof is None:
            raise ValueError("Pedersen proof is missing")
        p_proof_valid = self.pedersen_proof.verify(input, ad_data)
        ring_proof_valid = self.verify_ring_proof(self.pedersen_proof.blinded_pk, ring, ring_root)

        return p_proof_valid and ring_proof_valid

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        return PedersenVRF[cls.cv].proof_to_hash(gamma, mul_cofactor)  # type: ignore[misc]


__all__ = [
    "RingBatchItem",
    "RingBatchVerifier",
    "RingContext",
    "RingSetup",
    "RingVRF",
    "RingVerifierKeyBuilder",
]
