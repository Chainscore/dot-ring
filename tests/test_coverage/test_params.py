import pytest

from dot_ring.ring_proof.constants import D_2048, DEFAULT_SIZE, MAX_RING_SIZE, OMEGA_2048, S_PRIME
from dot_ring.ring_proof.params import (
    RingProofParams,
    _domain_for_size,
    _extend_root_to_size,
    _is_power_of_two,
    _omega_for_domain,
    _sqrt_mod_prime,
)


def test_is_power_of_two():
    assert _is_power_of_two(1)
    assert _is_power_of_two(8)
    assert not _is_power_of_two(0)
    assert not _is_power_of_two(6)


def test_omega_for_domain_valid():
    omega = _omega_for_domain(DEFAULT_SIZE, S_PRIME, OMEGA_2048, 2048)
    assert omega == pow(OMEGA_2048, 2048 // DEFAULT_SIZE, S_PRIME)


def test_omega_for_domain_invalid():
    with pytest.raises(ValueError, match="must divide"):
        _omega_for_domain(3, S_PRIME, OMEGA_2048, 2048)


def test_domain_for_size_matches_omega():
    domain = _domain_for_size(8, S_PRIME, OMEGA_2048, 2048)
    omega = _omega_for_domain(8, S_PRIME, OMEGA_2048, 2048)
    assert len(domain) == 8
    assert domain[0] == 1
    assert domain[1] == omega


def test_sqrt_mod_prime_zero():
    assert _sqrt_mod_prime(0, 7) == 0


def test_sqrt_mod_prime_mod4_3():
    root = _sqrt_mod_prime(2, 7)
    assert (root * root) % 7 == 2


def test_sqrt_mod_prime_tonelli_shanks():
    root = _sqrt_mod_prime(10, 13)
    assert (root * root) % 13 == 10


def test_sqrt_mod_prime_non_residue():
    with pytest.raises(ValueError, match="No square root"):
        _sqrt_mod_prime(2, 13)


def test_extend_root_to_size_grows():
    root, size = _extend_root_to_size(1, 4, 8, 7)
    assert size == 8
    assert root == 1


def test_ring_proof_params_defaults():
    params = RingProofParams()

    assert params.domain_size == DEFAULT_SIZE
    assert params.max_ring_size == MAX_RING_SIZE
    assert params.radix_domain_size == DEFAULT_SIZE * 4
    assert params.omega == pow(OMEGA_2048, 2048 // DEFAULT_SIZE, S_PRIME)
    assert params.radix_domain == list(D_2048)
    assert params.radix_shift == 4
    assert params.last_index == params.domain_size - params.padding_rows
    assert params.max_effective_ring_size == params.domain_size - params.padding_rows


def test_ring_proof_params_extends_root_size():
    params = RingProofParams(
        domain_size=2,
        radix_domain_size=8,
        prime=7,
        base_root=1,
        base_root_size=4,
        padding_rows=1,
        max_ring_size=1,
    )
    assert params.base_root_size == 8
    assert params.radix_domain_size == 8


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
        ({"domain_size": 8, "padding_rows": 0, "max_ring_size": 1}, "padding_rows must be >= 1"),
        ({"domain_size": 8, "padding_rows": 8, "max_ring_size": 1}, "padding_rows must be less than domain_size"),
        ({"domain_size": 8, "padding_rows": 2, "max_ring_size": 7}, "exceeds supported size"),
    ],
)
def test_ring_proof_params_validation_errors(kwargs, match):
    with pytest.raises(ValueError, match=match):
        RingProofParams(**kwargs)
