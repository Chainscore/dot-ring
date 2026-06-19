import pytest

from dot_ring.curve.specs.baby_jubjub import BabyJubJub
from dot_ring.ring_proof.params import RingProofParams


def test_ring_proof_params_defaults():
    params = RingProofParams()

    assert params.domain_size == 512
    assert params.max_ring_size == 255
    assert params.radix_domain_size == 2048
    assert pow(params.omega, params.domain_size, params.prime) == 1
    assert pow(params.omega, params.domain_size // 2, params.prime) != 1
    assert len(params.domain) == params.domain_size
    assert len(params.radix_domain) == params.radix_domain_size
    assert params.radix_shift == 4
    assert params.last_index == params.domain_size - params.padding_rows
    assert params.max_effective_ring_size == params.domain_size - params.scalar_bits - params.padding_rows


def test_baby_jubjub_ring_proof_params_are_unsupported():
    with pytest.raises(ValueError, match="BabyJubJub ring proofs require a primitive"):
        RingProofParams(cv=BabyJubJub)


def test_ring_proof_params_extends_root_size():
    params = RingProofParams(
        domain_size=512,
        radix_domain_size=4096,
        base_root_size=2048,
        padding_rows=4,
        max_ring_size=1,
    )
    assert params.base_root_size == 4096
    assert params.radix_domain_size == 4096


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"domain_size": 3}, "domain_size must be a power of two"),
        ({"domain_size": 4, "radix_domain_size": 6}, "radix_domain_size must be a power of two"),
        ({"domain_size": 8, "radix_domain_size": 4}, "must divide radix_domain_size"),
        (
            {
                "domain_size": 4,
                "radix_domain_size": 8,
                "base_root_size": 12,
                "padding_rows": 1,
                "max_ring_size": 1,
            },
            "must divide base_root_size",
        ),
        ({"domain_size": 512, "padding_rows": 0, "max_ring_size": 1}, "padding_rows must be >= 1"),
        ({"domain_size": 512, "padding_rows": 512, "max_ring_size": 1}, "padding_rows must be less than domain_size"),
        ({"domain_size": 512, "padding_rows": 4, "max_ring_size": 256}, "exceeds supported size"),
        ({"domain_size": 256, "padding_rows": 4, "max_ring_size": 1}, "domain_size is too small"),
    ],
)
def test_ring_proof_params_validation_errors(kwargs, match):
    with pytest.raises(ValueError, match=match):
        RingProofParams(**kwargs)


@pytest.mark.parametrize(
    ("ring_size", "domain_size", "max_ring_size"),
    [
        (1, 512, 255),
        (254, 512, 255),
        (255, 512, 255),
        (256, 1024, 767),
        (767, 1024, 767),
        (768, 2048, 1791),
        (1791, 2048, 1791),
        (1792, 4096, 3839),
        (2047, 4096, 3839),
    ],
)
def test_from_ring_size_matches_spec_capacity(ring_size, domain_size, max_ring_size):
    params = RingProofParams.from_ring_size(ring_size)

    assert params.domain_size == domain_size
    assert params.max_ring_size == max_ring_size
    assert params.max_effective_ring_size == max_ring_size
    assert pow(params.omega, params.domain_size, params.prime) == 1
    assert pow(params.omega, params.domain_size // 2, params.prime) != 1
    assert params.required_srs_degree == max(params.domain_size - 1, params.radix_domain_size - params.domain_size)
