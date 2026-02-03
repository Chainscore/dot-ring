from dot_ring.ring_proof.constraints.aggregation import aggregate_constraints


def test_aggregate_constraints_uses_default_domain_and_trims_zeros():
    polys = [[0, 0, 0, 0]]
    alphas = [1]
    omega_root = 5

    result = aggregate_constraints(polys, alphas, omega_root)

    assert result == []
