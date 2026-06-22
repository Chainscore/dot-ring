import random

import pytest

from dot_ring.curve.specs.baby_jubjub import BabyJubJub
from dot_ring.curve.specs.bandersnatch import Bandersnatch
from dot_ring.curve.specs.bls12_381_G1 import BLS12_381_G1_RO
from dot_ring.curve.specs.bls12_381_G2 import BLS12_381_G2_RO
from dot_ring.curve.specs.curve448 import Curve448_RO
from dot_ring.curve.specs.curve25519 import Curve25519_RO
from dot_ring.curve.specs.ed448 import Ed448_RO
from dot_ring.curve.specs.ed25519 import Ed25519_RO
from dot_ring.curve.specs.jubjub import JubJub
from dot_ring.curve.specs.p256 import P256_RO
from dot_ring.curve.specs.p384 import P384_RO
from dot_ring.curve.specs.p521 import P521_RO


# PROPERTY-BASED TESTS; General mathematical group properties
@pytest.mark.parametrize(
    "curve_variant",
    [
        Bandersnatch,
        JubJub,
        BabyJubJub,
        Ed448_RO,
        Ed25519_RO,
        Curve448_RO,
        Curve25519_RO,
        P256_RO,
        P384_RO,
        P521_RO,
        BLS12_381_G1_RO,
        BLS12_381_G2_RO,
    ],
)
def test_curve_property_based(curve_variant):
    """
    Property-based tests for fundamental group operations:
    - Commutativity: P + Q == Q + P
    - Associativity: (P + Q) + R == P + (Q + R)
    - Distributivity: (a + b)P == aP + bP
    - Scalar wrap-around: (order * P) == identity
    - Negation: P + (-P) == identity
    """
    Generator = curve_variant.point_type.generator_point()
    order = curve_variant.curve.params.subgroup_order

    # Random scalars within valid range
    a = random.randint(1, order - 1)
    b = random.randint(1, order - 1)
    c = random.randint(1, order - 1)

    P = Generator * a
    Q = Generator * b
    R = Generator * c

    # Commutativity
    assert (P + Q) == (Q + P)

    # Associativity
    assert ((P + Q) + R) == (P + (Q + R))

    # Distributivity
    lhs = Generator * ((a + b) % order)
    rhs = (Generator * a) + (Generator * b)
    assert lhs == rhs

    # Scalar wrap-around
    assert (Generator * order).is_identity()

    # Negation
    assert (P + (-P)).is_identity()


# SANITY TESTS; Simple deterministic checks per curve
def test_curve_sanity_operations():
    """
    Sanity checks for basic curve operations:
    - Point + Identity = Point
    - Point + (-Point) = Identity
    - Generator * Order = Identity
    """

    curve_data = [
        Bandersnatch,
        JubJub,
        BabyJubJub,
        Ed448_RO,
        Ed25519_RO,
        Curve448_RO,
        Curve25519_RO,
        P256_RO,
        P384_RO,
        P521_RO,
        BLS12_381_G1_RO,
        BLS12_381_G2_RO,
    ]

    for curve_variant in curve_data:
        Generator = curve_variant.point_type.generator_point()
        Identity = curve_variant.point_type.identity()
        Order = curve_variant.curve.params.subgroup_order

        # Addition with identity
        assert Generator + Identity == Generator
        assert Identity + Generator == Generator

        # Negation property
        assert Generator + (-Generator) == Identity

        # Scalar multiplication order property
        assert (Generator * Order).is_identity()
