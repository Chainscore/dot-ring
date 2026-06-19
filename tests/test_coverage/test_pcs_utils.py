"""Additional tests for utils module to improve coverage."""

from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.ring_proof.pcs.utils import synthetic_div_with_eval

RING_PRIME = Bandersnatch.curve.params.field_modulus


class TestPCSUtils:
    """Test PCS utility functions."""

    def test_synthetic_div_with_eval_matches_checked_division(self):
        poly = [3, 5, 7, 11, 13]
        x = 17
        y = sum(c * pow(x, i, RING_PRIME) for i, c in enumerate(poly)) % RING_PRIME

        quotient, value = synthetic_div_with_eval(poly, x)

        assert value == y
        assert len(quotient) == len(poly) - 1
