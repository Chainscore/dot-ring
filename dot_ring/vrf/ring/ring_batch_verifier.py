from __future__ import annotations

from typing import Any, cast

from dot_ring.vrf.pedersen.pedersen_batch_verifier import PedersenBatchVerifier
from dot_ring.vrf.transcript import VrfIo

from .ring_batch_item import RingBatchItem
from .ring import Ring
from .ring_root import RingRoot


class RingBatchVerifier:
    def __init__(self) -> None:
        self.items: list[RingBatchItem] = []

    def push(self, proof: RingVRF, input: bytes, ad: bytes, ring: Ring, ring_root: RingRoot) -> None:
        self.items.append(RingBatchItem(proof, input, ad, ring, ring_root))

    def verify(self) -> bool:
        if not self.items:
            return True

        pedersen_batches: dict[str, PedersenBatchVerifier] = {}
        pcs_batches: dict[int, tuple[Any, list[tuple[Any, Any, int, int]]]] = {}

        try:
            for item in self.items:
                if item.proof.pedersen_proof is None:
                    return False
                if item.ring.params.cv.name != item.proof.cv.name:
                    return False

                curve = item.proof.cv
                input_point = cast(Any, curve.point).encode_to_curve(item.input)
                pedersen_batch = pedersen_batches.setdefault(curve.name, PedersenBatchVerifier(curve))
                pedersen_batch.push([VrfIo(input_point, item.proof.pedersen_proof.output_point)], item.ad, item.proof.pedersen_proof)

                ring_verifier = item.proof._ring_proof_verifier(item.proof.pedersen_proof.blinded_pk, item.ring, item.ring_root)
                pcs = item.ring.params.pcs
                _, verifications = pcs_batches.setdefault(id(pcs), (pcs, []))
                verifications.append(ring_verifier._prepare_quotient_poly_verification())
                verifications.append(ring_verifier._prepare_linearization_poly_verification())
        except (AssertionError, TypeError, ValueError):
            return False

        if not all(batch.verify() for batch in pedersen_batches.values()):
            return False

        try:
            return all(pcs.batch_verify(verifications) for pcs, verifications in pcs_batches.values())
        except (AssertionError, TypeError, ValueError):
            return False
