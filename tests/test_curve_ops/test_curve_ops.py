import pytest
import random
from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve, BandersnatchPoint
from dot_ring.curve.specs.jubjub import JubJub_TE_Curve, JubJubPoint
from dot_ring.curve.specs.baby_jubjub import BabyJubJub_TE_Curve, BabyJubJubPoint
from dot_ring.curve.specs.ed448 import Ed448_TE_Curve, Ed448Point
from dot_ring.curve.specs.ed25519 import Ed25519_TE_Curve, Ed25519Point
from dot_ring.curve.specs.p256 import P256_SW_Curve, P256Point
from dot_ring.curve.specs.p384 import P384_SW_Curve, P384Point
from dot_ring.curve.specs.p521 import P521_SW_Curve, P521Point
from dot_ring.curve.specs.curve448 import Curve448_MG_Curve, Curve448Point
from dot_ring.curve.specs.curve25519 import Curve25519_MG_Curve, Curve25519Point
from dot_ring.curve.specs.bls12_381_G1 import BLS12_381_G1_SW_Curve, BLS12_381_G1Point
from dot_ring.curve.specs.bls12_381_G2 import BLS12_381_G2_SW_Curve, BLS12_381_G2Point

#PROPERTY-BASED TESTS; General mathematical group properties
@pytest.mark.parametrize("PointClass, CurveClass", [
    (BandersnatchPoint, Bandersnatch_TE_Curve),
    (JubJubPoint, JubJub_TE_Curve),
    (BabyJubJubPoint, BabyJubJub_TE_Curve),
    (Ed448Point, Ed448_TE_Curve),
    (Ed25519Point, Ed25519_TE_Curve),
    (Curve448Point, Curve448_MG_Curve),
    (Curve25519Point, Curve25519_MG_Curve),
    (P256Point, P256_SW_Curve),
    (P384Point, P384_SW_Curve),
    (P521Point, P521_SW_Curve),
    (BLS12_381_G1Point, BLS12_381_G1_SW_Curve),
    (BLS12_381_G2Point, BLS12_381_G2_SW_Curve),
])
def test_curve_property_based(PointClass, CurveClass):
    """
    Property-based tests for fundamental group operations:
    - Commutativity: P + Q == Q + P
    - Associativity: (P + Q) + R == P + (Q + R)
    - Distributivity: (a + b)P == aP + bP
    - Scalar wrap-around: (order * P) == identity
    - Negation: P + (-P) == identity
    """
    Generator = PointClass.generator_point()
    order = CurveClass.ORDER

    # Random scalars within valid range
    a = random.randint(1, order - 1)
    b = random.randint(1, order - 1)
    c = random.randint(1, order - 1)

    P = Generator * a
    Q = Generator * b
    R = Generator * c

    #Commutativity
    assert (P + Q) == (Q + P)

    #Associativity
    assert ((P + Q) + R) == (P + (Q + R))

    #Distributivity
    lhs = Generator * ((a + b) % order)
    rhs = (Generator * a) + (Generator * b)
    assert lhs == rhs

    #Scalar wrap-around
    assert (Generator * order).is_identity()

    #Negation
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
        (BandersnatchPoint, Bandersnatch_TE_Curve),
        (JubJubPoint, JubJub_TE_Curve),
        (BabyJubJubPoint, BabyJubJub_TE_Curve),
        (Ed448Point, Ed448_TE_Curve),
        (Ed25519Point, Ed25519_TE_Curve),
        (Curve448Point, Curve448_MG_Curve),
        (Curve25519Point, Curve25519_MG_Curve),
        (P256Point, P256_SW_Curve),
        (P384Point, P384_SW_Curve),
        (P521Point, P521_SW_Curve),
        (BLS12_381_G1Point, BLS12_381_G1_SW_Curve),
        (BLS12_381_G2Point, BLS12_381_G2_SW_Curve),
    ]

    for PointClass, CurveClass in curve_data:
        Generator = PointClass.generator_point()
        Identity = PointClass.identity()
        Order = CurveClass.ORDER

        # Addition with identity
        assert Generator + Identity == Generator
        assert Identity + Generator == Generator

        # Negation property
        assert Generator + (-Generator) == Identity

        # Scalar multiplication order property
        assert (Generator * Order).is_identity()
