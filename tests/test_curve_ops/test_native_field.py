import random

from dot_ring.curve.native_field.scalar import Scalar

from dot_ring.curve.specs.bandersnatch import BandersnatchParams

MODULUS = BandersnatchParams.PRIME_FIELD


def test_scalar_init():
    s = Scalar(123)
    assert s.to_int() == 123

    s = Scalar(MODULUS - 1)
    assert s.to_int() == MODULUS - 1

    s = Scalar(0)
    assert s.to_int() == 0


def test_scalar_add():
    for _ in range(100):
        a = random.randint(0, MODULUS - 1)
        b = random.randint(0, MODULUS - 1)

        expected = (a + b) % MODULUS
        res = Scalar(a) + Scalar(b)

        assert res.to_int() == expected, f"Failed add: {a} + {b}"


def test_scalar_sub():
    for _ in range(100):
        a = random.randint(0, MODULUS - 1)
        b = random.randint(0, MODULUS - 1)

        expected = (a - b) % MODULUS
        res = Scalar(a) - Scalar(b)

        assert res.to_int() == expected, f"Failed sub: {a} - {b}"


def test_scalar_mul():
    for _ in range(100):
        a = random.randint(0, MODULUS - 1)
        b = random.randint(0, MODULUS - 1)

        expected = (a * b) % MODULUS
        res = Scalar(a) * Scalar(b)

        assert res.to_int() == expected, f"Failed mul: {a} * {b}"


def test_scalar_mul_edge_cases():
    # Test 0 * x
    assert (Scalar(0) * Scalar(123)).to_int() == 0
    # Test 1 * x
    assert (Scalar(1) * Scalar(123)).to_int() == 123
    # Test max * max
    max_val = MODULUS - 1
    expected = (max_val * max_val) % MODULUS
    assert (Scalar(max_val) * Scalar(max_val)).to_int() == expected


def test_scalar_pow():
    a = Scalar(2)
    res = pow(a, 3)
    assert res.to_int() == 8

    # Test modular inverse
    a = Scalar(12345)
    inv = pow(a, -1)
    res = a * inv
    assert res.to_int() == 1


def test_scalar_neg():
    a = Scalar(1)
    res = -a
    assert res.to_int() == MODULUS - 1


def test_scalar_eq():
    a = Scalar(123)
    b = Scalar(123)
    c = Scalar(456)
    assert a == b
    assert a != c
    assert a == 123
    assert a != 456


def test_scalar_mod():
    a = Scalar(123)
    assert a % MODULUS == 123
    assert a % 10 == 3
