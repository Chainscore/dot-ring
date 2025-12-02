import pytest
import random
from dot_ring.curve.specs.bandersnatch import BandersnatchPoint, BandersnatchParams

# Setup fixtures
@pytest.fixture
def point_a():
    return BandersnatchPoint(BandersnatchParams.GENERATOR_X, BandersnatchParams.GENERATOR_Y)

@pytest.fixture
def point_b():
    return BandersnatchPoint(BandersnatchParams.GENERATOR_X, BandersnatchParams.GENERATOR_Y) * 12345

@pytest.fixture
def scalar():
    return 0x1234567890123456789012345678901234567890

def test_field_add(benchmark):
    p = BandersnatchParams.PRIME_FIELD
    a = random.randint(0, p-1)
    b = random.randint(0, p-1)
    def op():
        return (a + b) % p
    benchmark(op)

def test_field_mul(benchmark):
    p = BandersnatchParams.PRIME_FIELD
    a = random.randint(0, p-1)
    b = random.randint(0, p-1)
    def op():
        return (a * b) % p
    benchmark(op)

def test_curve_add(benchmark, point_a, point_b):
    benchmark(lambda: point_a + point_b)

def test_curve_double(benchmark, point_a):
    benchmark(lambda: point_a.double())

def test_scalar_mult(benchmark, point_a, scalar):
    benchmark(lambda: point_a * scalar)

def test_msm_4(benchmark, point_a):
    points = [point_a * i for i in range(4)]
    scalars = [random.randint(0, BandersnatchParams.ORDER) for _ in range(4)]
    benchmark(lambda: BandersnatchPoint.msm(points, scalars))

def test_ntt(benchmark):
    from dot_ring.ring_proof.polynomial.fft import _fft_in_place
    from dot_ring.curve.specs.bandersnatch import BandersnatchParams
    
    n = 1024
    # Use a dummy omega (not critical for perf, just needs to be an int)
    # But for correctness of flow, let's use a small number.
    # In real usage, it would be a root of unity.
    omega = 12345 
    prime = BandersnatchParams.PRIME_FIELD
    
    # Setup coeffs
    coeffs = [random.randint(0, prime-1) for _ in range(n)]
    
    def op():
        # Copy to avoid in-place modification affecting next rounds (though benchmark runner handles setup usually, 
        # but here we are inside the function. pytest-benchmark runs the function multiple times.
        # If we modify in place, it's fine for perf, numbers just change.)
        # But to be safe and measure "NTT on fresh data", we might want to copy.
        # However, copying might dominate the benchmark for small N.
        # Let's just run it in-place on the same buffer.
        _fft_in_place(coeffs, omega, prime)
        
    benchmark(op)
