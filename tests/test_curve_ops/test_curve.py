import hashlib

import pytest

from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.fp2 import Fp2
from dot_ring.curve.specs.ed25519 import Ed25519_RO
from dot_ring.curve.specs.parameters import (
    EncodingParams,
    HashToCurveParams,
    MontgomeryCurveParams,
    TwistedEdwardsCurveParams,
)
from dot_ring.curve.twisted_edwards.te_affine_point import TEAffinePoint
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.transcript.serialize import serialize


def _mock_hash_params(e2c: E2C_Variant = E2C_Variant.ELL2) -> HashToCurveParams[int]:
    return HashToCurveParams(
        dst=b"",
        z=1,
        field_extension_degree=1,
        security_level=1,
        field_length=2,
        expand_len=32,
    )


def _mock_mg_params(*, uncompressed: bool = True) -> MontgomeryCurveParams:
    return MontgomeryCurveParams(
        field_modulus=17,
        subgroup_order=19,
        cofactor=1,
        suite_id=b"mock-mg",
        hash_fn=hashlib.sha256,
        generator=(0, 0),
        hash_to_curve=_mock_hash_params(),
        encoding=EncodingParams(endian="little", point_len=2, challenge_len=0, uncompressed=uncompressed),
        a=0,
        b=1,
    )


def _mock_te_params(*, e2c: E2C_Variant = E2C_Variant.SSWU) -> TwistedEdwardsCurveParams:
    return TwistedEdwardsCurveParams(
        field_modulus=17,
        subgroup_order=19,
        cofactor=1,
        suite_id=b"mock-te",
        hash_fn=hashlib.sha256,
        generator=(0, 1),
        hash_to_curve=_mock_hash_params(e2c),
        encoding=EncodingParams(endian="little", point_len=2, challenge_len=0, uncompressed=True),
        a=1,
        d=2,
    )


class TestCoverageCurve:
    def test_te_affine_double_identity(self):
        """Test TEAffinePoint.double with identity point."""
        identity = Ed25519_RO.identity()
        doubled = identity.double()
        assert doubled.is_identity()

    def test_te_affine_double_result_identity(self):
        """Test TEAffinePoint.double resulting in identity (order 2 point)."""
        # It's hard to construct such a point easily without knowing one.
        # But we can mock or use a point that we know doubles to identity if any.
        # Alternatively, we can test the denominator check by mocking.
        pass

    def test_quotient_poly_vector_xn_minus_1(self):
        """Test QuotientPoly.poly_vector_xn_minus_1."""
        n = 4
        vec = QuotientPoly.poly_vector_xn_minus_1(n)
        assert len(vec) == n + 1
        assert vec[0] == -1
        assert vec[n] == 1
        assert vec[1] == 0

    def test_serialize_large_int(self):
        """Test serialize with integer too large."""
        large_int = 1 << (48 * 8 + 1)
        with pytest.raises(ValueError, match="Integer too large"):
            serialize(large_int)

    def test_serialize_bytes_bytearray(self):
        """Test serialize with bytes and bytearray."""
        b = b"test"
        assert serialize(b) == b

        ba = bytearray(b"test")
        assert serialize(ba) == b

    def test_serialize_invalid_type(self):
        """Test serialize with invalid type."""
        with pytest.raises(TypeError, match="Unsupported object type"):
            serialize(1.5)  # type: ignore

    def test_te_affine_double_coverage(self):
        """Test TEAffinePoint.double with a valid point."""
        g = Ed25519_RO.generator_point()
        doubled = g.double()
        assert doubled == g + g

    # --- MGAffinePoint Tests (Curve448) ---
    def test_mg_affine_ops(self):
        """Test MGAffinePoint operations."""
        from dot_ring.curve.specs.curve448 import Curve448_RO

        g = Curve448_RO.generator_point()

        # Identity
        identity = Curve448_RO.identity()
        assert (g + identity) == g
        assert (identity + g) == g

        # Negation
        neg_g = -g
        assert (g + neg_g) == identity

        # Subtraction
        assert (g - g) == identity
        assert (g - neg_g) == (g + g)

    def test_mg_affine_encode_map(self):
        """Test MGAffinePoint encode and map to curve."""
        from dot_ring.curve.specs.curve448 import Curve448_RO

        # Encode to curve
        msg = b"test message"
        p = Curve448_RO.encode_to_curve(msg, b"DST")
        assert p.is_on_curve()

        # Map to curve (if applicable directly, usually via encode)
        # map_to_curve is often internal or specific

    # --- SWAffinePoint Tests (P256) ---
    def test_sw_affine_ops(self):
        """Test SWAffinePoint operations."""
        from dot_ring.curve.specs.p256 import P256_RO

        g = P256_RO.generator_point()

        # Identity
        identity = P256_RO.identity()
        assert identity.is_identity()

        # Add with identity
        assert (g + identity) == g
        assert (identity + g) == g

        # Negation
        neg_g = -g
        assert (g + neg_g).is_identity()

        # Multiplication
        p2 = g * 2
        assert p2 == (g + g)

    def test_sw_affine_from_bytes(self):
        """Test SWAffinePoint from_bytes (compressed/uncompressed)."""
        from dot_ring.curve.specs.p256 import P256_RO

        g = P256_RO.generator_point()

        # Uncompressed
        b_uncomp = g.point_to_string(compressed=False)
        p_uncomp = P256_RO.string_to_point(b_uncomp)
        assert p_uncomp == g

        # Compressed
        b_comp = g.point_to_string(compressed=True)
        p_comp = P256_RO.string_to_point(b_comp)
        assert p_comp == g

    def test_sw_affine_encode(self):
        """Test SWAffinePoint encode_to_curve."""
        from dot_ring.curve.specs.p256 import P256_RO

        msg = b"test message"
        p = P256_RO.encode_to_curve(msg, b"DST")
        assert p.is_on_curve()

    def test_sw_affine_string_to_point_errors(self):
        """Test SWAffinePoint string_to_point error cases."""
        from dot_ring.curve.specs.p256 import P256_RO

        # Empty string
        with pytest.raises(ValueError, match="Empty octet string"):
            P256_RO.string_to_point(b"")

        # Invalid prefix
        with pytest.raises(ValueError, match="Invalid point encoding prefix"):
            P256_RO.string_to_point(b"\x05" + b"\x00" * 32)

        # Invalid length for compressed
        with pytest.raises(ValueError, match="Invalid compressed point length"):
            P256_RO.string_to_point(b"\x02" + b"\x00")

        # Invalid length for uncompressed
        with pytest.raises(ValueError, match="Invalid uncompressed point length"):
            P256_RO.string_to_point(b"\x04" + b"\x00")

    def test_mg_affine_string_to_point_errors(self):
        """Test MGAffinePoint string_to_point error cases."""
        from dot_ring.curve.specs.curve448 import Curve448_RO

        # Invalid point (not on curve)
        # u=0, v=1 => 0 != 1 (invalid)
        # 56 bytes for u (0), 56 bytes for v (1)
        u_bytes = b"\x00" * 56
        v_bytes = b"\x01" + b"\x00" * 55  # Little endian 1
        with pytest.raises(ValueError, match="Point is not on the curve"):
            Curve448_RO.string_to_point(u_bytes + v_bytes)

    def test_tonelli_shanks_coverage(self):
        """Test Tonelli-Shanks algorithm with a mock curve (p % 8 == 1)."""
        from dot_ring.curve.montgomery.mg_affine_point import MGAffinePoint
        from dot_ring.curve.montgomery.mg_curve import MGCurve

        class MockMGCurve(MGCurve):
            def __init__(self):
                super().__init__(params=_mock_mg_params(), e2c_variant=E2C_Variant.ELL2)

            def __post_init__(self):
                pass

        curve = MockMGCurve()

        # Test _sqrt_mod_p with p=17
        # Squares mod 17: 0, 1, 4, 9, 16, 8, 2, 15, 13
        # 2 is a square (6^2 = 36 = 2 mod 17)
        # 3 is NOT a square

        p = MGAffinePoint(None, None, curve)

        # Test square
        root = p._sqrt_mod_p(2)
        assert root is not None
        assert (root * root) % 17 == 2

        # Test non-square
        root_non = p._sqrt_mod_p(3)
        assert root_non is None

    def test_mg_affine_unimplemented_errors(self):
        """Test MGAffinePoint unimplemented methods."""
        from dot_ring.curve.montgomery.mg_affine_point import MGAffinePoint
        from dot_ring.curve.montgomery.mg_curve import MGCurve

        class MockMGCurve(MGCurve):
            def __init__(self):
                super().__init__(params=_mock_mg_params(uncompressed=False), e2c_variant=E2C_Variant.ELL2)

            def __post_init__(self):
                pass

        curve = MockMGCurve()
        p = MGAffinePoint(0, 0, curve)

        # Test point_to_string compressed error
        with pytest.raises(NotImplementedError, match="Compressed encoding not implemented"):
            p.point_to_string()

        # Test _x_recover NotImplementedError
        with pytest.raises(NotImplementedError):
            MGAffinePoint._x_recover(1, curve)

    def test_sw_tonelli_shanks_coverage(self):
        """Test SWAffinePoint.tonelli_shanks with p % 8 == 1."""
        from dot_ring.curve.short_weierstrass.sw_affine_point import SWAffinePoint

        # p = 17 (1 mod 8)
        # Squares: 0, 1, 4, 9, 16, 8, 2, 15, 13

        # Test square
        root = SWAffinePoint.tonelli_shanks(2, 17)
        assert root is not None
        assert (root * root) % 17 == 2

        # Test non-square
        root_non = SWAffinePoint.tonelli_shanks(3, 17)
        assert root_non is None

        # Test p % 4 == 3 case (e.g., p=7)
        # Squares mod 7: 0, 1, 4, 2
        root_fast = SWAffinePoint.tonelli_shanks(2, 7)
        assert root_fast is not None
        assert (root_fast * root_fast) % 7 == 2

    def test_sw_hybrid_format(self):
        """Test SWAffinePoint hybrid format (0x06/0x07)."""
        from dot_ring.curve.specs.p256 import P256_RO

        g = P256_RO.generator_point()

        # Construct hybrid bytes manually
        # Prefix 0x06 if y is even, 0x07 if y is odd
        y_int = int(g.y)  # type: ignore
        prefix = b"\x06" if y_int % 2 == 0 else b"\x07"

        x_bytes = int(g.x).to_bytes(32, "big")  # type: ignore
        y_bytes = int(g.y).to_bytes(32, "big")  # type: ignore

        hybrid_bytes = prefix + x_bytes + y_bytes

        p = P256_RO.string_to_point(hybrid_bytes)
        assert p == g

        # Test invalid hybrid length
        with pytest.raises(ValueError, match="Invalid hybrid point length"):
            P256_RO.string_to_point(b"\x06" + b"\x00")

        # Test invalid hybrid parity
        wrong_prefix = b"\x07" if y_int % 2 == 0 else b"\x06"
        wrong_hybrid = wrong_prefix + x_bytes + y_bytes
        with pytest.raises(ValueError, match="Hybrid format: y parity doesn't match prefix"):
            P256_RO.string_to_point(wrong_hybrid)

    def test_curve_point_base_coverage(self):
        """Test base CurvePoint methods."""
        from dot_ring.curve.montgomery.mg_curve import MGCurve
        from dot_ring.curve.point import CurvePoint

        class MockCurve(MGCurve):
            def __init__(self):
                super().__init__(params=_mock_mg_params(), e2c_variant=E2C_Variant.ELL2)

            def __post_init__(self):
                pass

        class MockPoint(CurvePoint):
            def is_on_curve(self):
                return True

            def is_identity(self):
                return self.x is None and self.y is None

            def _validate_coordinates(self):
                return True

            @classmethod
            def identity(cls, curve):
                return cls(None, None, curve)

        c = MockCurve()
        p = MockPoint(0, 0, curve=c)

        # Test NotImplementedError
        with pytest.raises(NotImplementedError):
            p + p
        with pytest.raises(NotImplementedError):
            p - p
        with pytest.raises(NotImplementedError):
            p * 2

        # Test msm errors
        with pytest.raises(ValueError, match="Points and scalars must have same length"):
            MockPoint.msm([p], [1, 2], c)

        # Test msm empty
        # Should return identity
        res = MockPoint.msm([], [], c)
        assert res.x is None and res.y is None

        p_hash = MockPoint(1, 2, curve=c)
        h = hash(p_hash)
        assert isinstance(h, int)

    def test_te_affine_errors(self):
        """Test TEAffinePoint error cases."""
        from dot_ring.curve.specs.ed25519 import Ed25519_RO

        g = Ed25519_RO.generator_point()

        # __add__ invalid type
        with pytest.raises(TypeError, match="Can only add TEAffinePoints"):
            g + 1  # type: ignore

        # __mul__ 0
        p0 = g * 0
        assert p0.is_identity()

        # __mul__ negative
        p_neg = g * -1
        assert p_neg == -g

        # encode_to_curve invalid variant
        from dot_ring.curve.twisted_edwards.te_curve import TECurve

        class MockTECurve(TECurve):
            def __init__(self):
                super().__init__(params=_mock_te_params(), e2c_variant=E2C_Variant.SSWU)

        curve = MockTECurve()

        # Unsupported TE hash-to-curve variants fail at dispatch.
        with pytest.raises(ValueError, match="Unexpected E2C Variant"):
            TEAffinePoint.encode_to_curve(b"test", curve=curve)

        # Test point_to_string uncompressed
        # MockTECurve uses uncompressed encoding.
        p = TEAffinePoint(0, 1, curve)  # Identity
        # Identity serialization should succeed for TE (0, 1)
        s = p.point_to_string()
        assert len(s) == 2  # 1 byte x, 1 byte y (p=17 -> 5 bits -> 1 byte)

        # Valid point serialization (uncompressed)
        p_valid = TEAffinePoint(0, 16, curve)  # 16 = -1 mod 17
        s = p_valid.point_to_string()
        assert len(s) == 2  # 1 byte x, 1 byte y

    def test_curve_point_hash_fp2(self):
        """Test CurvePoint.__hash__ with explicit Fp2 coordinates."""
        from dot_ring.curve.specs.bls12_381_G2 import BLS12_381_G2_RO

        point = BLS12_381_G2_RO.generator_point()
        assert isinstance(point.x, Fp2)
        assert isinstance(point.y, Fp2)
        expected = (point.x.re + point.x.im + point.y.re + point.y.im) % point.curve.params.subgroup_order
        assert point.__hash__() == expected
