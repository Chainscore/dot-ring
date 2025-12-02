
import pytest
import random
from dot_ring.curve.native_field.scalar import Scalar
from dot_ring.curve.native_field.vector_ops import vect_add, vect_sub, vect_mul
from dot_ring.curve.specs.bandersnatch import BandersnatchParams

MODULUS = BandersnatchParams.PRIME_FIELD

def test_vect_add():
    a = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    b = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    
    res = vect_add(a, b, MODULUS)
    
    for i in range(10):
        expected = a[i] + b[i]
        assert res[i] == expected, f"Mismatch at index {i}: {res[i]} != {expected}"

def test_vect_sub():
    a = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    b = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    
    res = vect_sub(a, b, MODULUS)
    
    for i in range(10):
        expected = a[i] - b[i]
        assert res[i] == expected, f"Mismatch at index {i}: {res[i]} != {expected}"

def test_vect_mul():
    a = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    b = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    
    res = vect_mul(a, b, MODULUS)
    
    for i in range(10):
        expected = a[i] * b[i]
        assert res[i] == expected, f"Mismatch at index {i}: {res[i]} != {expected}"

def test_vect_add_scalar():
    a = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    b = Scalar(random.randint(0, MODULUS - 1))
    
    res = vect_add(a, b, MODULUS)
    
    for i in range(10):
        expected = a[i] + b
        assert res[i] == expected, f"Mismatch at index {i}: {res[i]} != {expected}"

def test_vect_mul_scalar():
    a = [Scalar(random.randint(0, MODULUS - 1)) for _ in range(10)]
    b = Scalar(random.randint(0, MODULUS - 1))
    
    res = vect_mul(a, b, MODULUS)
    
    for i in range(10):
        expected = a[i] * b
        assert res[i] == expected, f"Mismatch at index {i}: {res[i]} != {expected}"

def test_perf_vect_add(benchmark):
    a = [Scalar(i) for i in range(1000)]
    b = [Scalar(i) for i in range(1000)]
    
    def run():
        vect_add(a, b, MODULUS)
        
    benchmark(run)
