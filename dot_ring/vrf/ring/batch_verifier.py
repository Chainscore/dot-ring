from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from dot_ring.ring_proof.pcs.utils import (
    LinearPcsVerification,
    g1_to_blst,
    pcs_transcript_g1,
)
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript
from dot_ring.ring_proof.verify import Verify, prepare_linear_pcs_verifications_fast
from dot_ring.vrf.pedersen.batch_verifier import PedersenBatchItem, PedersenBatchVerifier
from dot_ring.vrf.transcript import VrfIo

from .members import Ring
from .root import RingRoot

if TYPE_CHECKING:
    from .vrf import RingVRF


@dataclass
class RingBatchItem:
    curve: Any
    pedersen: PedersenBatchItem
    pcs: Any
    verifications: tuple[Any, Any]


@dataclass(frozen=True)
class RingBatchContext:
    ring: Ring
    ring_root: RingRoot
    fixed_cols_cmts: list[Any]
    fixed_cols_blst: tuple[Any, Any, Any]
    verifier_key: dict[str, Any]
    transcript_prefix: FiatShamirTranscript
    seed_point: tuple[int, int]
    domain: list[int]
    padding_rows: int
    omega: int
    ring_edwards_a: int
    domain_size_inv: int

    @classmethod
    def from_ring(cls, ring: Ring, ring_root: RingRoot, *, validate_ring_root: bool = True) -> RingBatchContext:
        if validate_ring_root and not ring_root.matches_ring(ring):
            raise ValueError("ring root does not match ring")
        fixed_cols_cmts, verifier_key = ring_root.verifier_key(ring.params)
        transcript_prefix = ring_root.verifier_transcript_prefix(ring.params)
        domain = ring.params.domain
        return cls(
            ring=ring,
            ring_root=ring_root,
            fixed_cols_cmts=fixed_cols_cmts,
            fixed_cols_blst=tuple(g1_to_blst(commitment) for commitment in fixed_cols_cmts),
            verifier_key=verifier_key,
            transcript_prefix=transcript_prefix,
            seed_point=ring.params.seed_point,
            domain=domain,
            padding_rows=ring.params.padding_rows,
            omega=ring.params.omega,
            ring_edwards_a=ring.params.ring_edwards_a,
            domain_size_inv=pow(ring.params.domain_size, -1, ring.params.prime),
        )

    @property
    def key(self) -> tuple[int, int]:
        return (id(self.ring), id(self.ring_root))

    def _decode_message_point(self, message: Any) -> Any:
        if not isinstance(message, bytes):
            return message
        try:
            return self.ring.params.cv.string_to_point(message)
        except ValueError as exc:
            raise ValueError("Invalid message point") from exc

    def ring_proof_verifier(self, proof: RingVRF, message: Any) -> Verify:
        ring = self.ring
        message = self._decode_message_point(message)

        rltn, res_plus_seed = _proof_relation_points(proof, message, ring.params)
        witness_commitments, quotient_commitment = _proof_transcript_commitments(proof, ring.params)

        return Verify(
            proof.ring_proof_tuple(),
            self.verifier_key,
            self.fixed_cols_cmts,
            rltn,
            res_plus_seed,
            self.seed_point,
            self.domain,
            transcript_challenge=proof.cv.curve.params.suite_id,
            padding_rows=self.padding_rows,
            edwards_a=self.ring_edwards_a,
            prime=ring.params.prime,
            omega=self.omega,
            pcs=ring.params.pcs,
            transcript_prefix=self.transcript_prefix,
            domain_size_inv=self.domain_size_inv,
            transcript_witness_commitments=witness_commitments,
            transcript_quotient_commitment=quotient_commitment,
        )

    def ring_pcs_verifications(self, proof: RingVRF, message: Any) -> tuple[LinearPcsVerification, LinearPcsVerification]:
        ring = self.ring
        message = self._decode_message_point(message)

        rltn, res_plus_seed = _proof_relation_points(proof, message, ring.params)
        witness_commitments, quotient_commitment = _proof_transcript_commitments(proof, ring.params)
        return prepare_linear_pcs_verifications_fast(
            proof.ring_proof_tuple(),
            self.fixed_cols_blst,
            rltn,
            res_plus_seed,
            self.seed_point,
            self.domain,
            self.padding_rows,
            self.domain_size_inv,
            self.ring_edwards_a,
            self.omega,
            self.transcript_prefix,
            witness_commitments,
            quotient_commitment,
        )

    def prepare_ios(self, proof: RingVRF, ios: list[VrfIo], ad: bytes) -> RingBatchItem:
        return _prepare_ios_with_context(proof, ios, ad, self)

    def prepare(self, proof: RingVRF, input: bytes, ad: bytes) -> RingBatchItem:
        pedersen_proof = proof.require_pedersen_proof()
        input_point = proof.cv.encode_to_curve(input)
        return self.prepare_ios(proof, [VrfIo(input_point, pedersen_proof.output_point)], ad)

    def _prepare_pedersen_item(self, proof: RingVRF, ios: list[VrfIo], ad: bytes) -> Any:
        pedersen_proof = proof.require_pedersen_proof()
        if self.ring.params.cv.name != proof.cv.name:
            raise ValueError("proof curve does not match ring curve")
        return PedersenBatchVerifier(proof.cv).prepare(ios, ad, pedersen_proof)

    def _prepare_pcs_item(self, proof: RingVRF, message: Any) -> tuple[Any, tuple[LinearPcsVerification, LinearPcsVerification]]:
        pcs = self.ring.params.pcs
        # Deferred linear KZG verification avoids materializing small commitments before batching.
        return pcs, self.ring_pcs_verifications(proof, message)


def _prepare_ios_with_context(proof: RingVRF, ios: list[VrfIo], ad: bytes, context: RingBatchContext) -> RingBatchItem:
    pedersen_item = context._prepare_pedersen_item(proof, ios, ad)
    pcs, verifications = context._prepare_pcs_item(proof, proof.require_pedersen_proof().blinded_pk)
    return RingBatchItem(proof.cv, pedersen_item, pcs, verifications)


def _proof_transcript_commitments(proof: RingVRF, params: Any) -> tuple[bytes, Any]:
    commitments = (
        proof.c_b.commitment,
        proof.c_accip.commitment,
        proof.c_accx.commitment,
        proof.c_accy.commitment,
        proof.c_q.commitment,
    )
    transcript_commitments = tuple(pcs_transcript_g1(params.pcs, commitment) for commitment in commitments)
    witness_commitments = b"".join(transcript_commitments[:4])
    quotient_commitment = transcript_commitments[4]
    return witness_commitments, quotient_commitment


def _proof_relation_points(proof: RingVRF, message: Any, params: Any) -> tuple[tuple[int, int], tuple[int, int]]:
    relation = params.point_to_ring_point(message)
    result_plus_seed = params.add_points(params.seed_point, relation)
    return relation, result_plus_seed


def _verify_pcs_batch(pcs: Any, verifications: list[Any]) -> bool:
    return bool(pcs.batch_verify_linear_preconverted(cast(list[LinearPcsVerification], verifications)))


class RingBatchVerifier:
    def __init__(self, context: RingBatchContext | None = None) -> None:
        self.items: list[RingBatchItem] = []
        self.pedersen_batches: dict[str, PedersenBatchVerifier] = {}
        self.pcs_batches: dict[int, tuple[Any, list[Any]]] = {}
        self._contexts: dict[tuple[int, int], RingBatchContext] = {}
        if context is not None:
            self._contexts[context.key] = context
        self._invalid = False

    @staticmethod
    def prepare_context(ring: Ring, ring_root: RingRoot, *, validate_ring_root: bool = True) -> RingBatchContext:
        return RingBatchContext.from_ring(ring, ring_root, validate_ring_root=validate_ring_root)

    @staticmethod
    def prepare_ios(
        proof: RingVRF,
        ios: list[VrfIo],
        ad: bytes,
        ring: Ring,
        ring_root: RingRoot,
        *,
        validate_ring_root: bool = True,
    ) -> RingBatchItem:
        context = RingBatchContext.from_ring(ring, ring_root, validate_ring_root=validate_ring_root)
        return context.prepare_ios(proof, ios, ad)

    @staticmethod
    def prepare(proof: RingVRF, input: bytes, ad: bytes, ring: Ring, ring_root: RingRoot, *, validate_ring_root: bool = True) -> RingBatchItem:
        pedersen_proof = proof.require_pedersen_proof()
        curve = proof.cv
        input_point = curve.encode_to_curve(input)
        return RingBatchVerifier.prepare_ios(
            proof,
            [VrfIo(input_point, pedersen_proof.output_point)],
            ad,
            ring,
            ring_root,
            validate_ring_root=validate_ring_root,
        )

    def push_prepared(self, item: RingBatchItem) -> None:
        self.items.append(item)
        pedersen_batch = self.pedersen_batches.setdefault(item.curve.name, PedersenBatchVerifier(item.curve))
        pedersen_batch.push_prepared(item.pedersen)
        _, verifications = self.pcs_batches.setdefault(id(item.pcs), (item.pcs, []))
        verifications.extend(item.verifications)

    def push_ios(
        self,
        proof: RingVRF,
        ios: list[VrfIo],
        ad: bytes,
        ring: Ring,
        ring_root: RingRoot,
        *,
        validate_ring_root: bool = True,
    ) -> None:
        try:
            root_key = (id(ring), id(ring_root))
            context = self._contexts.get(root_key)
            if context is None:
                context = RingBatchContext.from_ring(ring, ring_root, validate_ring_root=validate_ring_root)
                self._contexts[root_key] = context
            self.push_prepared(context.prepare_ios(proof, ios, ad))
        except (AssertionError, TypeError, ValueError):
            self._invalid = True

    def push(
        self,
        proof: RingVRF,
        input: bytes,
        ad: bytes,
        ring: Ring,
        ring_root: RingRoot,
        *,
        validate_ring_root: bool = True,
    ) -> None:
        try:
            root_key = (id(ring), id(ring_root))
            context = self._contexts.get(root_key)
            if context is None:
                context = RingBatchContext.from_ring(ring, ring_root, validate_ring_root=validate_ring_root)
                self._contexts[root_key] = context
            self.push_prepared(context.prepare(proof, input, ad))
        except (AssertionError, TypeError, ValueError):
            self._invalid = True

    def verify(self) -> bool:
        if self._invalid:
            return False
        if not self.items:
            return True

        if not all(batch.verify() for batch in self.pedersen_batches.values()):
            return False

        try:
            return all(_verify_pcs_batch(pcs, verifications) for pcs, verifications in self.pcs_batches.values())
        except (AssertionError, TypeError, ValueError):
            return False
