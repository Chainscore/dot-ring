from  dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve, BandersnatchPoint
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

#Test Curve Operations w.r.t Fundamental Properties
#Addition Property (Point+Identity=Point)
#Scalar Multiplication Property (Generator*Order=Identity)
#Negation Property (Point+(-Point)=Identity)

def test_curve_arth_ops():

    #Check For Edwards Curves
    Generator=BandersnatchPoint.generator_point()
    #addition property
    assert Generator+BandersnatchPoint.identity()==Generator
    assert Generator+(-Generator)==BandersnatchPoint.identity()
    assert (BandersnatchPoint.scalar_mul(Generator,Bandersnatch_TE_Curve.ORDER)).is_identity()


    Generator=JubJubPoint.generator_point()
    assert Generator + JubJubPoint.identity() == Generator
    assert Generator+(-Generator)==JubJubPoint.identity()
    assert (Generator*JubJub_TE_Curve.ORDER).is_identity()

    Generator=BabyJubJubPoint.generator_point()
    assert Generator + BabyJubJubPoint.identity() == Generator
    assert Generator+(-Generator)==BabyJubJubPoint.identity()
    assert (Generator*BabyJubJub_TE_Curve.ORDER).is_identity()

    Generator = Ed448Point.generator_point()
    assert Generator+Ed448Point.identity()==Generator
    assert Generator+(-Generator)==Ed448Point.identity()
    assert (Generator * Ed448_TE_Curve.ORDER).is_identity()

    Generator = Ed25519Point.generator_point()
    assert Generator+Ed25519Point.identity()==Generator
    assert Generator+(-Generator)==Ed25519Point.identity()
    assert (Generator * Ed25519_TE_Curve.ORDER).is_identity()

    #Check For Montgomery Curves
    Generator = Curve448Point.generator_point()
    assert Generator+Curve448Point.identity()==Generator
    assert Generator+(-Generator)==Curve448Point.identity()
    assert (Generator * Curve448_MG_Curve.ORDER).is_identity()

    Generator = Curve25519Point.generator_point()
    assert Generator+Curve25519Point.identity()==Generator
    assert Generator+(-Generator)==Curve25519Point.identity()
    assert (Generator * Curve25519_MG_Curve.ORDER).is_identity()

    #Check For Weierstrass Curves
    Generator = P256Point.generator_point()
    assert Generator + P256Point.identity()== Generator
    assert Generator+(-Generator)==P256Point.identity()
    assert (Generator * P256_SW_Curve.ORDER).is_identity()

    Generator = P384Point.generator_point()
    assert Generator + P384Point.identity()== Generator
    assert Generator+(-Generator)==P384Point.identity()
    assert (Generator * P384_SW_Curve.ORDER).is_identity()

    Generator = P521Point.generator_point()
    assert Generator + P521Point.identity()== Generator
    assert Generator+(-Generator)==P521Point.identity()
    assert (Generator * P521_SW_Curve.ORDER).is_identity()

    Generator = BLS12_381_G1Point.generator_point()
    assert Generator + BLS12_381_G1Point.identity()== Generator
    assert Generator+(-Generator)==BLS12_381_G1Point.identity()
    assert (Generator * BLS12_381_G1_SW_Curve.ORDER).is_identity()

    Generator=BLS12_381_G2Point.generator_point()
    assert Generator + BLS12_381_G2Point.identity()== Generator
    assert Generator+(-Generator)==BLS12_381_G2Point.identity()
    assert (Generator*BLS12_381_G2_SW_Curve.ORDER).is_identity()