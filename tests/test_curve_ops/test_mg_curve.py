import hashlib

import pytest

from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.montgomery.mg_curve import MGCurve
from dot_ring.curve.specs.curve25519 import Curve25519_RO
from dot_ring.curve.specs.parameters import EncodingParams, HashToCurveParams, MontgomeryCurveParams


def _mock_mg_params(*, a: int, b: int) -> MontgomeryCurveParams:
    return MontgomeryCurveParams(
        field_modulus=17,
        subgroup_order=19,
        cofactor=1,
        suite_id=b"mock-mg",
        hash_fn=hashlib.sha256,
        generator=(0, 0),
        hash_to_curve=HashToCurveParams(
            dst=b"",
            z=1,
            field_extension_degree=1,
            security_level=1,
            field_length=2,
            expand_len=32,
        ),
        encoding=EncodingParams(endian="little", point_len=0, challenge_len=0),
        a=a,
        b=b,
    )


def test_mg_curve_methods():
    curve = Curve25519_RO.curve

    # Test __str__ and __repr__
    assert str(curve).startswith("MGCurve(p=")
    assert repr(curve).startswith("MGCurve(field_modulus=")

    # Test __eq__ and __hash__
    curve2 = Curve25519_RO.curve
    assert curve == curve2
    assert hash(curve) == hash(curve2)

    # Test is_on_curve with generator
    generator = curve.params.generator
    assert curve.is_on_curve(generator)

    # Test is_on_curve with invalid point
    # u=1, v=0 => 0 != 1 + A + 1
    invalid_point = (1, 0)
    assert not curve.is_on_curve(invalid_point)

    # Point construction is suite-bound; MGCurve itself does not own a point class.
    inf = Curve25519_RO.point_type.identity()
    assert inf.is_identity()

    # Test validate_point
    assert curve.validate_point(inf)

    # Test validate_point with valid point
    gen_point = Curve25519_RO.point_type.generator_point()
    assert curve.validate_point(gen_point)

    # Test validate_point with invalid point object (mock)
    class MockPoint:
        x = 1
        y = 0

        def is_identity(self):
            return False

    assert not curve.validate_point(MockPoint())


def test_mg_curve_random_point():
    curve = Curve25519_RO.curve
    point = Curve25519_RO.point_type.encode_to_curve(b"random point")
    assert curve.is_on_curve((point.x, point.y))
    assert curve.validate_point(point)


def test_mg_curve_validation():
    # Test invalid B
    with pytest.raises(ValueError, match="B coefficient cannot be zero"):
        MGCurve(
            params=_mock_mg_params(a=1, b=0),
            e2c_variant=E2C_Variant.ELL2,
        )

    # Test singular curve (A^2 - 4 = 0 mod p) => A=2, p=17 => 4-4=0
    with pytest.raises(ValueError, match="Curve is singular"):
        MGCurve(
            params=_mock_mg_params(a=2, b=1),
            e2c_variant=E2C_Variant.ELL2,
        )
