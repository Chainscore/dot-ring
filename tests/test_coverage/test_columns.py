import pytest

from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.ring_proof.columns.columns import Column, WitnessColumnBuilder
from dot_ring.ring_proof.constants import DEFAULT_SIZE, OMEGAS, S_PRIME
from dot_ring.ring_proof.params import RingProofParams
from dot_ring.vrf.ring.ring_root import Ring, RingRoot


def test_column_interpolate_rejects_oversize_evals():
    col = Column("x", [1, 2, 3], size=2)
    with pytest.raises(ValueError, match="exceeds column size"):
        col.interpolate(domain_omega=OMEGAS[DEFAULT_SIZE], prime=S_PRIME)


def test_column_commit_requires_coeffs():
    col = Column("x", [1], size=1)
    with pytest.raises(ValueError, match="call interpolate"):
        col.commit()


def test_ring_from_params():
    """Test Ring construction with explicit params"""
    params = RingProofParams(domain_size=8, max_ring_size=3, padding_rows=1)
    # Create dummy keys (just using some bytes)
    keys = [b"key1" * 8, b"key2" * 8]
    ring = Ring(keys, params)

    assert ring.params == params
    assert len(ring.nm_points) == params.domain_size


def test_ring_rejects_oversize_ring():
    """Test Ring rejects rings that are too large"""
    params = RingProofParams(domain_size=8, max_ring_size=2, padding_rows=1)
    # Create 8 keys which exceeds max_ring_size=2 and domain_size-padding_rows=7
    keys = [b"key" + bytes([i]) * 8 for i in range(8)]

    with pytest.raises(ValueError, match="exceeds max supported size"):
        Ring(keys, params)


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
