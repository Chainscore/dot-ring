from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.columns.columns import Column
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.ring_proof.pcs.opening import Opening
from dot_ring.ring_proof.verify import RingProofFields, Verify
from dot_ring.vrf.pedersen import PedersenVRF
from dot_ring.vrf.vrf import PreparedSecretKey

from ..vrf import VRF
from .members import Ring, parse_concatenated_keys as _parse_concatenated_keys
from .batch_verifier import RingBatchItem, RingBatchVerifier, _proof_relation_points, _proof_transcript_commitments
from .context import RingContext, RingSetup, RingVerifierKeyBuilder
from .proof_builder import RingProofBuilder
from .proof_payload import RingProofPayload, ring_proof_len
from .root import RingRoot


@dataclass
class RingVRF(VRF[Any]):
    """
    Ring VRF implementation.

    This implementation provides Ring VRF operations combining
    Pedersen VRF proofs with ring signatures.

    Usage:
    >>> from dot_ring.curve.specs.bandersnatch import Bandersnatch
    >>> from dot_ring.vrf.ring import RingVRF
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

    @classmethod
    def proof_len(cls, skip_pedersen: bool = False) -> int:
        params = RingProofParams(cv=cls.cv)
        proof_len = ring_proof_len(params)
        if skip_pedersen:
            return proof_len
        return PedersenVRF[cast(Any, cls).cv].proof_len() + proof_len  # type: ignore[misc]

    def to_bytes(self) -> bytes:
        """
        Serialize the Ring VRF proof to bytes.

        Returns:
            bytes: Bytes representation of the Ring VRF proof
        """
        params = RingProofParams(cv=self.cv)
        return cast(bytes, self.require_pedersen_proof().to_bytes()) + self._payload().to_bytes(params)

    @classmethod
    def from_bytes(cls, proof: bytes, skip_pedersen: bool = False) -> RingVRF:
        """
        Deserialize the Ring VRF proof from bytes.

        Args:
            proof: Bytes representation of the Ring VRF proof
        Returns:
            RingVRF: Deserialized Ring VRF proof object
        """
        expected_len = cls.proof_len(skip_pedersen)
        if len(proof) != expected_len:
            raise ValueError(f"invalid Ring VRF proof length: Ring VRF proof must be exactly {expected_len} bytes, got {len(proof)}")

        if not skip_pedersen:
            pedersen_len = PedersenVRF[cast(Any, cls).cv].proof_len()  # type: ignore[misc]
            pedersen_proof = PedersenVRF[cast(Any, cls).cv].from_bytes(proof[:pedersen_len])  # type: ignore[misc]
            offset = pedersen_len
        else:
            pedersen_proof = None
            offset = 0

        params = RingProofParams(cv=cls.cv)
        expected = offset + ring_proof_len(params)
        if len(proof) != expected:
            raise ValueError(f"invalid Ring VRF proof length: expected {expected}, got {len(proof)}")
        payload = RingProofPayload.from_bytes(proof[offset:], params)
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

    def ring_proof_tuple(self) -> RingProofFields:
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
            self.open_agg_zeta.proof,
            self.open_l_zeta_omega.proof,
        )

    def require_pedersen_proof(self) -> PedersenVRF:
        if self.pedersen_proof is None:
            raise ValueError("Pedersen proof is missing")
        return self.pedersen_proof

    def _ring_proof_verifier(
        self,
        message: bytes | CurvePoint,
        ring: Ring,
        ring_root: RingRoot,
    ) -> Verify:
        fixed_cols_cmts, verifier_key = ring_root.verifier_key(ring.params)
        transcript_prefix = ring_root.verifier_transcript_prefix(ring.params)

        if isinstance(message, bytes):
            try:
                message = ring.params.cv.string_to_point(message)
            except ValueError as exc:
                raise ValueError("Invalid message point") from exc

        rltn, res_plus_seed = _proof_relation_points(self, message, ring.params)
        witness_commitments, quotient_commitment = _proof_transcript_commitments(self, ring.params)

        return Verify(
            self.ring_proof_tuple(),
            verifier_key,
            fixed_cols_cmts,
            rltn,
            res_plus_seed,
            ring.params.seed_point,
            ring.params.domain,
            transcript_challenge=self.cv.curve.params.suite_id,
            padding_rows=ring.params.padding_rows,
            edwards_a=ring.params.ring_edwards_a,
            prime=ring.params.prime,
            omega=ring.params.omega,
            pcs=ring.params.pcs,
            transcript_prefix=transcript_prefix,
            domain_size_inv=pow(ring.params.domain_size, -1, ring.params.prime),
            transcript_witness_commitments=witness_commitments,
            transcript_quotient_commitment=quotient_commitment,
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
        if not ring_root.matches_ring(ring):
            return False
        return cast(bool, self._ring_proof_verifier(message, ring, ring_root).is_valid())

    @classmethod
    def prove(
        cls,
        alpha: bytes,
        ad: bytes,
        secret_key: bytes,
        producer_key: bytes,
        ring: Ring,
        ring_root: RingRoot | None = None,
    ) -> RingVRF:
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
        return cls.prove_prepared(alpha, ad, cls.prepare_secret_key(secret_key), producer_key, ring, ring_root)

    @classmethod
    def prove_prepared(
        cls,
        alpha: bytes,
        ad: bytes,
        secret_key: PreparedSecretKey[Any],
        producer_key: bytes,
        ring: Ring,
        ring_root: RingRoot | None = None,
    ) -> RingVRF:
        if secret_key.curve is not cls.cv:
            raise ValueError("prepared secret key uses a different curve")
        if producer_key != secret_key.public_key_bytes:
            raise ValueError("producer_key does not match secret_key")

        pedersen_proof = PedersenVRF[cast(Any, cls).cv].prove_prepared(alpha, secret_key, ad)  # type: ignore[misc]

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
        return cast(list[bytes], _parse_concatenated_keys(keys, cls.cv))

    def verify(self, input: bytes, ad_data: bytes, ring: Ring, ring_root: RingRoot) -> bool:
        """
        Verify ring VRF proof (pedersen_proof + ring_proof)
        """
        pedersen_proof = self.require_pedersen_proof()
        p_proof_valid = pedersen_proof.verify(input, ad_data)
        ring_proof_valid = self.verify_ring_proof(pedersen_proof.blinded_pk, ring, ring_root)

        return p_proof_valid and ring_proof_valid

    @classmethod
    def proof_to_hash(cls, gamma: CurvePoint, mul_cofactor: bool = False) -> bytes:
        return PedersenVRF[cls.cv].proof_to_hash(gamma, mul_cofactor)

__all__ = [
    "RingBatchItem",
    "RingBatchVerifier",
    "RingContext",
    "RingSetup",
    "RingVRF",
    "RingVerifierKeyBuilder",
]
