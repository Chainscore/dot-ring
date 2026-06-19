from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from dot_ring.curve.point import CurvePoint
from dot_ring.ring_proof.pcs.utils import (
    LinearPcsVerification,
    g1_to_blst,
)
from dot_ring.ring_proof.transcript.transcript import FiatShamirTranscript
from dot_ring.ring_proof.verify import Verify, linear_pcs_verifications
from dot_ring.vrf.pedersen.batch_verifier import PedersenBatchVerifier, _PedersenBatchItem
from dot_ring.vrf.transcript import VrfIo

from .members import Ring
from .root import RingRoot

if TYPE_CHECKING:
    from .vrf import RingVRF


@dataclass
class _RingBatchItem:
    curve: Any
    pedersen: _PedersenBatchItem
    pcs: Any
    verifications: tuple[Any, Any]


@dataclass(frozen=True)
class _RingBatchContext:
    ring: Ring
    ring_root: RingRoot
    fixed_cols_cmts: list[Any]
    fixed_cols_blst: tuple[Any, Any, Any]
    transcript_prefix: FiatShamirTranscript
    seed_point: CurvePoint
    domain: list[int]
    padding_rows: int
    omega: int
    edwards_a: int
    domain_size_inv: int

    @classmethod
    def from_ring(cls, ring: Ring, ring_root: RingRoot, *, validate_ring_root: bool = True) -> _RingBatchContext:
        if validate_ring_root and not ring_root.matches_ring(ring):
            raise ValueError("ring root does not match ring")
        fixed_cols_cmts = ring_root.fixed_commitments(ring.params)
        transcript_prefix = ring_root.verifier_transcript_prefix(ring.params)
        domain = ring.params.domain
        return cls(
            ring=ring,
            ring_root=ring_root,
            fixed_cols_cmts=fixed_cols_cmts,
            fixed_cols_blst=tuple(g1_to_blst(commitment) for commitment in fixed_cols_cmts),
            transcript_prefix=transcript_prefix,
            seed_point=ring.params.cv.point(ring.params.cv.curve.params.auxiliary_points.accumulator_base),
            domain=domain,
            padding_rows=ring.params.padding_rows,
            omega=ring.params.omega,
            edwards_a=ring.params.cv.curve.params.a,
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
            self.fixed_cols_cmts,
            rltn,
            res_plus_seed,
            self.seed_point,
            self.domain,
            self.transcript_prefix,
            padding_rows=self.padding_rows,
            edwards_a=self.edwards_a,
            prime=ring.params.prime,
            omega=self.omega,
            pcs=ring.params.pcs,
            domain_size_inv=self.domain_size_inv,
            transcript_witness_commitments=witness_commitments,
            transcript_quotient_commitment=quotient_commitment,
        )

    def ring_pcs_verifications(self, proof: RingVRF, message: Any) -> tuple[LinearPcsVerification, LinearPcsVerification]:
        ring = self.ring
        message = self._decode_message_point(message)

        rltn, res_plus_seed = _proof_relation_points(proof, message, ring.params)
        witness_commitments, quotient_commitment = _proof_transcript_commitments(proof, ring.params)
        return linear_pcs_verifications(
            proof.as_ring_proof(),
            self.fixed_cols_blst,
            rltn,
            res_plus_seed,
            self.seed_point,
            self.domain,
            self.padding_rows,
            self.domain_size_inv,
            self.edwards_a,
            self.omega,
            ring.params.prime,
            self.transcript_prefix,
            witness_commitments,
            quotient_commitment,
        )

    def _item_from_ios(self, proof: RingVRF, ios: list[VrfIo], ad: bytes) -> _RingBatchItem:
        return _ring_batch_item(proof, ios, ad, self)

    def _item(self, proof: RingVRF, input: bytes, ad: bytes) -> _RingBatchItem:
        pedersen_proof = proof.pedersen_proof
        input_point = proof.cv.encode_to_curve(input)
        return _ring_batch_item_from_trusted_ios(proof, [VrfIo(input_point, pedersen_proof.output_point)], ad, self)

    def _pedersen_item(self, proof: RingVRF, ios: list[VrfIo], ad: bytes) -> Any:
        pedersen_proof = proof.pedersen_proof
        if self.ring.params.cv.name != proof.cv.name:
            raise ValueError("proof curve does not match ring curve")
        verifier = PedersenBatchVerifier(proof.cv)
        item = verifier._item(ios, ad, pedersen_proof)
        if verifier._invalid:
            raise ValueError("invalid Pedersen VRF point")
        return item

    def _pedersen_item_from_trusted_ios(self, proof: RingVRF, ios: list[VrfIo], ad: bytes) -> Any:
        pedersen_proof = proof.pedersen_proof
        if self.ring.params.cv.name != proof.cv.name:
            raise ValueError("proof curve does not match ring curve")
        verifier = PedersenBatchVerifier(proof.cv)
        item = verifier._item_from_trusted_ios(ios, ad, pedersen_proof)
        if verifier._invalid:
            raise ValueError("invalid Pedersen VRF point")
        return item

    def _pcs_item(self, proof: RingVRF, message: Any) -> tuple[Any, tuple[LinearPcsVerification, LinearPcsVerification]]:
        pcs = self.ring.params.pcs
        # Deferred linear KZG verification avoids materializing small commitments before batching.
        return pcs, self.ring_pcs_verifications(proof, message)


def _ring_batch_item(proof: RingVRF, ios: list[VrfIo], ad: bytes, context: _RingBatchContext) -> _RingBatchItem:
    pedersen_item = context._pedersen_item(proof, ios, ad)
    pcs, verifications = context._pcs_item(proof, proof.pedersen_proof.blinded_pk)
    return _RingBatchItem(proof.cv, pedersen_item, pcs, verifications)


def _ring_batch_item_from_trusted_ios(proof: RingVRF, ios: list[VrfIo], ad: bytes, context: _RingBatchContext) -> _RingBatchItem:
    pedersen_item = context._pedersen_item_from_trusted_ios(proof, ios, ad)
    pcs, verifications = context._pcs_item(proof, proof.pedersen_proof.blinded_pk)
    return _RingBatchItem(proof.cv, pedersen_item, pcs, verifications)


def _proof_transcript_commitments(proof: RingVRF, params: Any) -> tuple[bytes, Any]:
    commitments = (
        proof.c_b.commitment,
        proof.c_accip.commitment,
        proof.c_accx.commitment,
        proof.c_accy.commitment,
        proof.c_q.commitment,
    )
    transcript_commitments = tuple(params.pcs.serialize_g1_uncompressed(commitment) for commitment in commitments)
    witness_commitments = b"".join(transcript_commitments[:4])
    quotient_commitment = transcript_commitments[4]
    return witness_commitments, quotient_commitment


def _proof_relation_points(proof: RingVRF, message: Any, params: Any) -> tuple[CurvePoint, CurvePoint]:
    relation = params.cv.point(message)
    seed = params.cv.point(params.cv.curve.params.auxiliary_points.accumulator_base)
    return relation, seed + relation


class RingBatchVerifier:
    def __init__(self) -> None:
        self.items: list[_RingBatchItem] = []
        self.pedersen_batches: dict[str, PedersenBatchVerifier] = {}
        self.pcs_batches: dict[int, tuple[Any, list[Any]]] = {}
        self._contexts: dict[tuple[int, int], _RingBatchContext] = {}
        self._invalid = False

    def _push_item(self, item: _RingBatchItem) -> None:
        self.items.append(item)
        pedersen_batch = self.pedersen_batches.setdefault(item.curve.name, PedersenBatchVerifier(item.curve))
        pedersen_batch._push_item(item.pedersen)
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
                context = _RingBatchContext.from_ring(ring, ring_root, validate_ring_root=validate_ring_root)
                self._contexts[root_key] = context
            self._push_item(context._item_from_ios(proof, ios, ad))
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
                context = _RingBatchContext.from_ring(ring, ring_root, validate_ring_root=validate_ring_root)
                self._contexts[root_key] = context
            self._push_item(context._item(proof, input, ad))
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
            return all(
                pcs.batch_verify_linear_preconverted(verifications)
                for pcs, verifications in self.pcs_batches.values()
            )
        except (AssertionError, TypeError, ValueError):
            return False
