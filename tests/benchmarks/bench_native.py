import pytest
import random
from dot_ring.curve.native_field.scalar import Scalar
from dot_ring.curve.specs.bandersnatch import BandersnatchParams

MODULUS = BandersnatchParams.PRIME_FIELD

@pytest.fixture
def scalar_a():
    return Scalar(random.randint(0, MODULUS - 1))

@pytest.fixture
def scalar_b():
    return Scalar(random.randint(0, MODULUS - 1))

def test_native_field_add(benchmark, scalar_a, scalar_b):
    benchmark(lambda: scalar_a + scalar_b)

def test_native_field_sub(benchmark, scalar_a, scalar_b):
    benchmark(lambda: scalar_a - scalar_b)

def test_native_field_mul(benchmark, scalar_a, scalar_b):
    benchmark(lambda: scalar_a * scalar_b)
