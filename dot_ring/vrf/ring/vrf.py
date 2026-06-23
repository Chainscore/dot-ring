"""Ring VRF (section 5).

The encoded proof is the Pedersen library envelope followed by the ring-proof
payload; the spec writes this as `(pi_p, pi_r)`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.protocol import G1Commitment
from dot_ring.ring_proof.pcs.utils import g1_to_blst
from dot_ring.ring_proof.proof_builder import RingProofBuilder
from dot_ring.ring_proof.proof_payload import RingProofPayload
from dot_ring.ring_proof.verify import RingProofFields, Verify, linear_pcs_verifications
from dot_ring.vrf.codec import point_len
from dot_ring.vrf.pedersen import PedersenVRF

from ..vrf import VRF
from .members import Ring
from .root import RingRoot


@dataclass
class RingVRF(VRF[Any]):
    """Pedersen VRF proof plus ring proof that proves `Y_bar` belongs to the ring."""

    pedersen_proof: PedersenVRF
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
    open_agg_zeta: G1Commitment
    open_l_zeta_omega: G1Commitment

    @classmethod
    def proof_len(cls) -> int:
        params = RingProofParams(cv=cls.cv)
        return PedersenVRF[cls.cv].proof_len() + RingProofPayload.encoded_len(params)

    def encode(self) -> bytes:
        """Serialize Pedersen + RingProof"""
        params = RingProofParams(cv=self.cv)
        return self.pedersen_proof.encode() + self._payload().encode(params)

    @classmethod
    def decode(cls, proof: bytes) -> RingVRF:
        """Decode the Pedersen and the fixed-order ring-proof payload."""
        expected_len = cls.proof_len()
        if len(proof) != expected_len:
            raise ValueError(f"invalid Ring VRF proof length: Ring VRF proof must be exactly {expected_len} bytes, got {len(proof)}")

        pedersen_len = PedersenVRF[cls.cv].proof_len()
        pedersen_proof = PedersenVRF[cls.cv].decode(proof[:pedersen_len])
        offset = pedersen_len

        params = RingProofParams(cv=cls.cv)
        expected = offset + RingProofPayload.encoded_len(params)
        if len(proof) != expected:
            raise ValueError(f"invalid Ring VRF proof length: expected {expected}, got {len(proof)}")
        payload = RingProofPayload.decode(proof[offset:], params)
        return cls(
            pedersen_proof=pedersen_proof,
            c_b=payload.c_b,
            c_accip=payload.c_accip,
            c_accx=payload.c_accx,
            c_accy=payload.c_accy,
            px_zeta=payload.px_zeta,
            py_zeta=payload.py_zeta,
            s_zeta=payload.s_zeta,
            b_zeta=payload.b_zeta,
            accip_zeta=payload.accip_zeta,
            accx_zeta=payload.accx_zeta,
            accy_zeta=payload.accy_zeta,
            c_q=payload.c_q,
            l_zeta_omega=payload.l_zeta_omega,
            open_agg_zeta=payload.open_agg_zeta,
            open_l_zeta_omega=payload.open_l_zeta_omega,
        )

    def _payload(self) -> RingProofPayload:
        return RingProofPayload(
            c_b=self.c_b,
            c_accip=self.c_accip,
            c_accx=self.c_accx,
            c_accy=self.c_accy,
            px_zeta=self.px_zeta,
            py_zeta=self.py_zeta,
            s_zeta=self.s_zeta,
            b_zeta=self.b_zeta,
            accip_zeta=self.accip_zeta,
            accx_zeta=self.accx_zeta,
            accy_zeta=self.accy_zeta,
            c_q=self.c_q,
            l_zeta_omega=self.l_zeta_omega,
            open_agg_zeta=self.open_agg_zeta,
            open_l_zeta_omega=self.open_l_zeta_omega,
        )

    def as_ring_proof(self) -> RingProofFields:
        """Return the ring-proof fields in the order expected by the SNARK verifier."""
        return RingProofFields(
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
            self.open_agg_zeta,
            self.open_l_zeta_omega,
        )

    def _ring_proof_verifier(
        self,
        message: bytes | CurvePoint,
        ring: Ring,
        ring_root: RingRoot,
    ) -> Verify:
        fixed_cols_cmts = ring_root.fixed_commitments()
        transcript_prefix = ring_root.verifier_transcript_prefix()

        if isinstance(message, bytes):
            try:
                message = ring.params.cv.point_type.string_to_point(message)
            except ValueError as exc:
                raise ValueError("Invalid message point") from exc

        if not ring.params.cv.curve.params.auxiliary_points.accumulator_base:
            raise ValueError("Curve does not have an accumulator base point for Ring VRF")
        seed_point = ring.params.cv.point(ring.params.cv.curve.params.auxiliary_points.accumulator_base)
        rltn = message
        res_plus_seed = seed_point + rltn
        witness_commitments, quotient_commitment = self._proof_transcript_commitments(ring.params)

        return Verify(
            self.as_ring_proof(),
            fixed_cols_cmts,
            rltn,
            res_plus_seed,
            seed_point,
            ring.params.domain,
            transcript_prefix,
            padding_rows=ring.params.padding_rows,
            edwards_a=ring.params.cv.curve.params.a,
            prime=ring.params.prime,
            omega=ring.params.omega,
            pcs=ring.params.pcs,
            transcript_witness_commitments=witness_commitments,
            transcript_quotient_commitment=quotient_commitment,
        )

    def verify_ring_proof(
        self,
        message: bytes | CurvePoint,
        ring: Ring,
        ring_root: RingRoot,
    ) -> bool:
        """Spec section 5.2 step 2: verify the ring proof against `Y_bar`."""
        if not ring_root.matches_ring(ring):
            return False
        return self._ring_proof_verifier(message, ring, ring_root).is_valid()

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        additional_data: bytes,
        secret_key: bytes,
        producer_key: bytes,
        ring: Ring,
        ring_root: RingRoot | None = None,
        salt: bytes = b"",
    ) -> RingVRF:
        """Spec section 5.1: run Pedersen prove, then prove `Y_bar = producer_key + b*B` is in the ring."""
        if producer_key != cls.cv.public_key_from_secret(secret_key):
            raise ValueError("producer_key does not match secret_key")

        pedersen_proof = PedersenVRF[cls.cv].prove(alpha, secret_key, additional_data, salt)

        ring_proof = RingProofBuilder(
            cls.cv,
            pedersen_proof._blinding_factor,
            producer_key,
            ring,
            ring_root=ring_root,
        ).build()

        return cls(pedersen_proof, *ring_proof.as_tuple())

    @classmethod
    def parse_keys(cls, keys: bytes) -> list[bytes]:
        """Parse a bytes object containing concatenated keys into a list of individual keys.

        Args:
            keys (bytes): A bytes object containing concatenated keys.

        Returns:
            List[bytes]: A list of individual keys extracted from the input bytes object.
        """
        encoded_point_len = point_len(cls.cv)
        if len(keys) % encoded_point_len != 0:
            raise ValueError(f"invalid concatenated key length: expected multiple of {encoded_point_len}, got {len(keys)}")
        return [keys[encoded_point_len * i : encoded_point_len * (i + 1)] for i in range(len(keys) // encoded_point_len)]

    def verify(self, input: bytes, ad_data: bytes, ring: Ring, ring_root: RingRoot) -> bool:
        """Spec section 5.2: Pedersen verify first, then ring-verify the blinded key."""
        pedersen_proof = self.pedersen_proof
        p_proof_valid = pedersen_proof.verify(input, ad_data)
        ring_proof_valid = self.verify_ring_proof(pedersen_proof.blinded_pk, ring, ring_root)

        return p_proof_valid and ring_proof_valid

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        return PedersenVRF[cls.cv].proof_to_hash(gamma, mul_cofactor)

    @classmethod
    def batch_verify(
        cls,
        proofs: Sequence[RingVRF],
        inputs: Sequence[bytes],
        additional_data: Sequence[bytes],
        ring: Ring,
        ring_root: RingRoot,
    ) -> bool:
        if not ring_root.matches_ring(ring):
            return False

        # Verify all Pedersen proofs first; if any fail, return immediately.
        if not PedersenVRF[cls.cv].batch_verify([p.pedersen_proof for p in proofs], inputs, additional_data):
            return False

        fixed_cols_blst = tuple(g1_to_blst(commitment) for commitment in ring_root.fixed_commitments())
        transcript_prefix = ring_root.verifier_transcript_prefix()

        if not ring.params.cv.curve.params.auxiliary_points.accumulator_base:
            raise ValueError("Curve does not have an accumulator base point for Ring VRF")
        seed_point = ring.params.cv.point_type(*ring.params.cv.curve.params.auxiliary_points.accumulator_base)

        pcs_verifications: list[Any] = []
        try:
            for proof in proofs:
                relation = proof.pedersen_proof.blinded_pk
                result_plus_seed = seed_point + relation
                witness_commitments, quotient_commitment = proof._proof_transcript_commitments(ring.params)
                pcs_verifications.extend(
                    linear_pcs_verifications(
                        proof.as_ring_proof(),
                        fixed_cols_blst,
                        relation,
                        result_plus_seed,
                        seed_point,
                        ring.params,
                        transcript_prefix,
                        witness_commitments,
                        quotient_commitment,
                    )
                )
        except (AssertionError, AttributeError, TypeError, ValueError):
            return False

        return bool(ring.params.pcs.batch_verify_linear_preconverted(pcs_verifications))

    def _proof_transcript_commitments(self, params: RingProofParams) -> tuple[bytes, Any]:
        commitments = (
            self.c_b.commitment,
            self.c_accip.commitment,
            self.c_accx.commitment,
            self.c_accy.commitment,
            self.c_q.commitment,
        )
        transcript_commitments = tuple(params.pcs.serialize_g1_uncompressed(commitment) for commitment in commitments)
        return b"".join(transcript_commitments[:4]), transcript_commitments[4]
