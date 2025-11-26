import pytest
from dot_ring.curve.montgomery.mg_curve import MGCurve
from dot_ring.curve.specs.curve25519 import Curve25519_RO
from dot_ring.curve.e2c import E2C_Variant

def test_mg_curve_methods():
    curve = Curve25519_RO.curve
    
    # Test __str__ and __repr__
    assert str(curve).startswith("MGCurve(p=")
    assert repr(curve).startswith("MGCurve(PRIME_FIELD=")
    
    # Test __eq__ and __hash__
    curve2 = Curve25519_RO.curve
    assert curve == curve2
    assert hash(curve) == hash(curve2)
    
    # Test is_on_curve with generator
    generator = (curve.GENERATOR_X, curve.GENERATOR_Y)
    assert curve.is_on_curve(generator)
    
    # Test is_on_curve with invalid point
    # u=1, v=0 => 0 != 1 + A + 1
    invalid_point = (1, 0)
    assert not curve.is_on_curve(invalid_point)
    
    # Test point_at_infinity
    inf = curve.point_at_infinity()
    assert inf.is_identity()
    
    # Test validate_point
    assert curve.validate_point(inf)
    
    # Test validate_point with valid point
    gen_point = Curve25519_RO.point.generator_point()
    assert curve.validate_point(gen_point)
    
    # Test validate_point with invalid point object (mock)
    class MockPoint:
        x = 1
        y = 0
        def is_identity(self): return False
        
    assert not curve.validate_point(MockPoint())

def test_mg_curve_random_point():
    curve = Curve25519_RO.curve
    point = curve.random_point()
    assert curve.is_on_curve((point.x, point.y))
    assert curve.validate_point(point)

def test_mg_curve_validation():
    # Test invalid B
    with pytest.raises(ValueError, match="B coefficient cannot be zero"):
        MGCurve(
            PRIME_FIELD=17,
            ORDER=3,
            GENERATOR_X=0,
            GENERATOR_Y=0,
            COFACTOR=1,
            Z=1,
            A=1,
            B=0, # Invalid
            SUITE_STRING=b"",
            DST=b"",
            E2C=E2C_Variant.ELL2,
            BBx=0,
            BBy=0,
            L=0,
            M=0,
            K=0,
            H_A=None,
            S_in_bytes=0,
            Requires_Isogeny=False,
            Isogeny_Coeffs=None,
            UNCOMPRESSED=False,
            ENDIAN="little",
            POINT_LEN=0,
            CHALLENGE_LENGTH=0
        )

    # Test singular curve (A^2 - 4 = 0 mod p) => A=2, p=17 => 4-4=0
    with pytest.raises(ValueError, match="Curve is singular"):
        MGCurve(
            PRIME_FIELD=17,
            ORDER=3,
            GENERATOR_X=0,
            GENERATOR_Y=0,
            COFACTOR=1,
            Z=1,
            A=2, # 2^2 - 4 = 0
            B=1,
            SUITE_STRING=b"",
            DST=b"",
            E2C=E2C_Variant.ELL2,
            BBx=0,
            BBy=0,
            L=0,
            M=0,
            K=0,
            H_A=None,
            S_in_bytes=0,
            Requires_Isogeny=False,
            Isogeny_Coeffs=None,
            UNCOMPRESSED=False,
            ENDIAN="little",
            POINT_LEN=0,
            CHALLENGE_LENGTH=0
        )
