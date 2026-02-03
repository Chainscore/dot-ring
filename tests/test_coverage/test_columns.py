import pytest

from dot_ring.ring_proof.columns.columns import Column, PublicColumnBuilder, WitnessColumnBuilder
from dot_ring.ring_proof.constants import DEFAULT_SIZE, OMEGAS, S_PRIME, PaddingPoint
from dot_ring.ring_proof.params import RingProofParams


def test_column_interpolate_rejects_oversize_evals():
    col = Column("x", [1, 2, 3], size=2)
    with pytest.raises(ValueError, match="exceeds column size"):
        col.interpolate(domain_omega=OMEGAS[DEFAULT_SIZE], prime=S_PRIME)


def test_column_commit_requires_coeffs():
    col = Column("x", [1], size=1)
    with pytest.raises(ValueError, match="call interpolate"):
        col.commit()


def test_public_builder_from_params_and_padding():
    params = RingProofParams(domain_size=8, max_ring_size=3, padding_rows=1)
    builder = PublicColumnBuilder.from_params(params)
    assert builder.size == 8
    assert builder.max_ring_size == 3

    ring = [(1, 1)]
    padded = builder._pad_ring_with_padding_point(ring)
    assert len(padded) == builder.max_ring_size
    assert padded[-1] == PaddingPoint


def test_public_builder_rejects_oversize_ring():
    builder = PublicColumnBuilder(size=8, max_ring_size=2, padding_rows=1)
    ring_pk = [(0, 0)] * 8
    with pytest.raises(ValueError, match="exceeds max supported size"):
        builder.build(ring_pk)


def test_witness_builder_from_params_and_bits_vector_error():
    params = RingProofParams(domain_size=8, max_ring_size=6, padding_rows=1)
    builder = WitnessColumnBuilder.from_params(
        ring_pk=[(0, 0)] * params.max_ring_size,
        selector_vector=[0] * params.max_ring_size,
        producer_index=0,
        secret_t=3,
        params=params,
    )
    with pytest.raises(ValueError, match="b vector length exceeds"):
        builder._bits_vector()
