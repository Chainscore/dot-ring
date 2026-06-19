"""Pedersen VRF batch verification from Bandersnatch VRF spec section 4.4."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.point import CurvePoint
from dot_ring.vrf.transcript import CHALLENGE_LEN, DomSep, VrfIo, challenge, squeeze_transcript_bytes, suite_id, vrf_transcript_scalars

from .vrf import PedersenVRF, _blinding_base


@dataclass
class _PedersenBatchItem:
    c: int
    ios: list[VrfIo]
    zs: list[int]
    pk_com: CurvePoint
    r: CurvePoint
    ok: CurvePoint
    s: int
    sb: int


def _signed_mod(value: int, order: int) -> int:
    value %= order
    if value > order >> 1:
        value -= order
    return value


def _fold_duplicate_points_by_identity(points: list[CurvePoint], scalars: list[int], order: int) -> tuple[list[CurvePoint], list[int]]:
    seen: set[int] = set()
    has_duplicate = False
    for point in points:
        point_id = id(point)
        if point_id in seen:
            has_duplicate = True
            break
        seen.add(point_id)
    if not has_duplicate:
        return points, scalars

    points_by_id: dict[int, CurvePoint] = {}
    scalars_by_id: dict[int, int] = {}
    for point, scalar in zip(points, scalars, strict=True):
        scalar %= order
        if scalar == 0:
            continue
        point_id = id(point)
        if point_id in scalars_by_id:
            scalars_by_id[point_id] = (scalars_by_id[point_id] + scalar) % order
        else:
            points_by_id[point_id] = point
            scalars_by_id[point_id] = scalar

    folded_points = []
    folded_scalars = []
    for point_id, point in points_by_id.items():
        scalar = _signed_mod(scalars_by_id[point_id], order)
        if scalar:
            folded_points.append(point)
            folded_scalars.append(scalar)
    return folded_points, folded_scalars


def _batch_coefficient_pairs_from_bytes(item_count: int, item_bytes: bytes | bytearray, curve: CurveVariant) -> list[tuple[int, int]]:
    """Spec section 4.4.2: transcript weights from scalar triples only, in item order."""
    if item_count == 0:
        return []

    absorbed = bytearray(suite_id(curve))
    absorbed.append(DomSep.BATCH_VERIFY)
    absorbed.extend(item_bytes)

    order = curve.curve.params.subgroup_order
    raw = squeeze_transcript_bytes(curve.curve.params.hash_fn, bytes(absorbed), 2 * CHALLENGE_LEN * item_count)
    pairs = []
    for index in range(item_count):
        offset = 2 * CHALLENGE_LEN * index
        io_weight = int.from_bytes(raw[offset : offset + CHALLENGE_LEN], "little") % order
        commitment_weight = int.from_bytes(raw[offset + CHALLENGE_LEN : offset + 2 * CHALLENGE_LEN], "little") % order
        pairs.append((io_weight, commitment_weight))
    return pairs


def _batch_coefficient_item_bytes(item: _PedersenBatchItem, scalar_size: int, order: int) -> bytes:
    return (
        int(item.c % order).to_bytes(scalar_size, "little")
        + int(item.s % order).to_bytes(scalar_size, "little")
        + int(item.sb % order).to_bytes(scalar_size, "little")
    )


def _batch_coefficient_pairs(items: list[_PedersenBatchItem], curve: CurveVariant) -> list[tuple[int, int]]:
    order = curve.curve.params.subgroup_order
    scalar_size = (order.bit_length() + 7) // 8
    item_bytes = bytearray()
    for item in items:
        item_bytes.extend(_batch_coefficient_item_bytes(item, scalar_size, order))
    return _batch_coefficient_pairs_from_bytes(len(items), item_bytes, curve)


class PedersenBatchVerifier:
    """Accumulates spec section 4.4 items and verifies the two weighted equations together."""

    def __init__(self, curve: CurveVariant):
        self.cv = curve
        self.items: list[_PedersenBatchItem] = []
        self._order = curve.curve.params.subgroup_order
        self._scalar_size = (self._order.bit_length() + 7) // 8
        self._coefficient_item_bytes = bytearray()
        self._single_io_items = True
        self._invalid = False

    @classmethod
    def __class_getitem__(cls, curve_variant: CurveVariant | Any) -> type[PedersenBatchVerifier] | Any:
        if not isinstance(curve_variant, CurveVariant):
            return cls

        class _SpecializedPedersenBatchVerifier(cls):
            def __init__(self) -> None:
                super().__init__(curve_variant)

        _SpecializedPedersenBatchVerifier.__name__ = f"{cls.__name__}[{curve_variant.name}]"
        return _SpecializedPedersenBatchVerifier

    def _item(
        self,
        ios: list[VrfIo],
        additional_data: bytes,
        proof: PedersenVRF,
    ) -> _PedersenBatchItem:
        if not PedersenVRF._valid_ios(ios):
            return self._invalid_item(proof)
        return self._item_from_trusted_ios(ios, additional_data, proof)

    def _item_from_trusted_ios(
        self,
        ios: list[VrfIo],
        additional_data: bytes,
        proof: PedersenVRF,
    ) -> _PedersenBatchItem:
        if not proof._valid_proof_points():
            return self._invalid_item(proof)
        if len(ios) == 1:
            return self._single_io_item(ios[0], additional_data, proof)

        transcript, zs = vrf_transcript_scalars(self.cv, DomSep.PEDERSEN_VRF, ios, additional_data)
        transcript.absorb(proof.blinded_pk.point_to_string())
        c = challenge(self.cv, [proof.result_point, proof.ok], transcript)
        return _PedersenBatchItem(
            c=c,
            ios=list(ios),
            zs=zs,
            pk_com=proof.blinded_pk,
            r=proof.result_point,
            ok=proof.ok,
            s=proof.s,
            sb=proof.sb,
        )

    def _invalid_item(self, proof: PedersenVRF) -> _PedersenBatchItem:
        self._invalid = True
        return _PedersenBatchItem(0, [], [], proof.blinded_pk, proof.result_point, proof.ok, proof.s, proof.sb)

    def _single_io_item(self, io: VrfIo, additional_data: bytes, proof: PedersenVRF) -> _PedersenBatchItem:
        absorbed = bytearray(suite_id(self.cv))
        absorbed.append(DomSep.PEDERSEN_VRF)
        absorbed.extend((1).to_bytes(8, "little"))
        absorbed.extend(io.input.point_to_string())
        absorbed.extend(io.output.point_to_string())
        absorbed.extend(len(additional_data).to_bytes(8, "little"))
        absorbed.extend(additional_data)
        absorbed.extend(proof.blinded_pk.point_to_string())
        absorbed.append(DomSep.CHALLENGE)
        absorbed.extend(proof.result_point.point_to_string())
        absorbed.extend(proof.ok.point_to_string())
        c = _challenge_scalar_from_absorbed(self.cv, bytes(absorbed))
        return _PedersenBatchItem(
            c=c,
            ios=[io],
            zs=[1],
            pk_com=proof.blinded_pk,
            r=proof.result_point,
            ok=proof.ok,
            s=proof.s,
            sb=proof.sb,
        )

    def _push_item(self, item: _PedersenBatchItem) -> None:
        if self._invalid:
            return
        self.items.append(item)
        self._single_io_items = self._single_io_items and len(item.ios) == 1 and len(item.zs) == 1 and item.zs[0] == 1
        self._coefficient_item_bytes.extend(_batch_coefficient_item_bytes(item, self._scalar_size, self._order))

    def push(self, ios: list[VrfIo], additional_data: bytes, proof: PedersenVRF) -> None:
        self._push_item(self._item(ios, additional_data, proof))

    def verify(self) -> bool:
        if self._invalid:
            return False
        if not self.items:
            return True

        blinding_base = _blinding_base(self.cv)
        generator = self.cv.generator_point()
        order = self._order
        expected_bytes = len(self.items) * 3 * self._scalar_size
        if len(self._coefficient_item_bytes) == expected_bytes:
            coefficients = _batch_coefficient_pairs_from_bytes(len(self.items), self._coefficient_item_bytes, self.cv)
        else:
            coefficients = _batch_coefficient_pairs(self.items, self.cv)

        if self._single_io_items:
            points, scalars = self._verification_terms_single_io(coefficients, generator, blinding_base)
            points, scalars = _fold_duplicate_points_by_identity(points, scalars, order)
            return self.cv.msm(points, scalars).is_identity()

        points: list[CurvePoint] = []
        scalars: list[int] = []
        generator_scalar = 0
        blinding_scalar = 0

        for item, (io_weight, commitment_weight) in zip(self.items, coefficients, strict=True):
            for io, z in zip(item.ios, item.zs, strict=True):
                points.extend([io.input, io.output])
                scalars.extend(
                    [
                        _signed_mod(io_weight * item.s * z, order),
                        _signed_mod(-(io_weight * item.c * z), order),
                    ]
                )
            points.append(item.ok)
            scalars.append(-io_weight)

            generator_scalar = (generator_scalar + commitment_weight * item.s) % order
            blinding_scalar = (blinding_scalar + commitment_weight * item.sb) % order

            points.extend([item.pk_com, item.r])
            scalars.extend(
                [
                    _signed_mod(-(commitment_weight * item.c), order),
                    -commitment_weight,
                ]
            )

        if generator_scalar:
            points.append(generator)
            scalars.append(_signed_mod(generator_scalar, order))
        if blinding_scalar:
            points.append(blinding_base)
            scalars.append(_signed_mod(blinding_scalar, order))

        points, scalars = _fold_duplicate_points_by_identity(points, scalars, order)
        return self.cv.msm(points, scalars).is_identity()

    def _verification_terms_single_io(
        self,
        coefficients: list[tuple[int, int]],
        generator: CurvePoint,
        blinding_base: CurvePoint,
    ) -> tuple[list[CurvePoint], list[int]]:
        items = self.items
        order = self._order
        half_order = order >> 1
        point_count = len(items) * 5 + 2
        points: list[CurvePoint | None] = [None] * point_count
        scalars = [0] * point_count
        generator_scalar = 0
        blinding_scalar = 0
        pos = 0

        for item, (io_weight, commitment_weight) in zip(items, coefficients, strict=True):
            io = item.ios[0]

            value = (io_weight * item.s) % order
            if value > half_order:
                value -= order
            points[pos] = io.input
            scalars[pos] = value
            pos += 1

            value = -(io_weight * item.c) % order
            if value > half_order:
                value -= order
            points[pos] = io.output
            scalars[pos] = value
            pos += 1

            points[pos] = item.ok
            scalars[pos] = -io_weight
            pos += 1

            generator_scalar = (generator_scalar + commitment_weight * item.s) % order
            blinding_scalar = (blinding_scalar + commitment_weight * item.sb) % order

            value = -(commitment_weight * item.c) % order
            if value > half_order:
                value -= order
            points[pos] = item.pk_com
            scalars[pos] = value
            pos += 1

            points[pos] = item.r
            scalars[pos] = -commitment_weight
            pos += 1

        if generator_scalar:
            value = generator_scalar
            if value > half_order:
                value -= order
            points[pos] = generator
            scalars[pos] = value
            pos += 1
        if blinding_scalar:
            value = blinding_scalar
            if value > half_order:
                value -= order
            points[pos] = blinding_base
            scalars[pos] = value
            pos += 1

        return points[:pos], scalars[:pos]  # type: ignore[return-value]


def _challenge_scalar_from_absorbed(curve: CurveVariant, absorbed: bytes) -> int:
    rnd = squeeze_transcript_bytes(curve.curve.params.hash_fn, absorbed, CHALLENGE_LEN)
    return int.from_bytes(rnd, "little") % curve.curve.params.subgroup_order
