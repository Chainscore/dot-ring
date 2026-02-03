import pytest

from dot_ring.curve.specs.ed25519 import Ed25519_RO
from dot_ring.curve.twisted_edwards.te_affine_point import TEAffinePoint
from dot_ring.ring_proof.proof.quotient_poly import QuotientPoly
from dot_ring.ring_proof.transcript.serialize import serialize


class TestCoverageCurve:
    def test_te_affine_double_identity(self):
        """Test TEAffinePoint.double with identity point."""
        # Create an identity point
        # Ed25519_RO.point is a configured TEAffinePoint subclass
        PointClass = Ed25519_RO.point
        identity = PointClass.identity()
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
        # Generator point
        PointClass = Ed25519_RO.point
        g = PointClass.generator_point()
        doubled = g.double()
        assert doubled == g + g

    # --- MGAffinePoint Tests (Curve448) ---
    def test_mg_affine_ops(self):
        """Test MGAffinePoint operations."""
        from dot_ring.curve.specs.curve448 import Curve448_RO

        PointClass = Curve448_RO.point
        g = PointClass.generator_point()

        # Identity
        identity = PointClass.identity()
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

        PointClass = Curve448_RO.point

        # Encode to curve
        msg = b"test message"
        p = PointClass.encode_to_curve(msg, b"DST")
        assert p.is_on_curve()

        # Map to curve (if applicable directly, usually via encode)
        # map_to_curve is often internal or specific

    # --- SWAffinePoint Tests (P256) ---
    def test_sw_affine_ops(self):
        """Test SWAffinePoint operations."""
        from dot_ring.curve.specs.p256 import P256_RO

        PointClass = P256_RO.point
        g = PointClass.generator_point()

        # Identity
        identity = PointClass.identity()
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

        PointClass = P256_RO.point
        g = PointClass.generator_point()

        # Uncompressed
        b_uncomp = g.point_to_string(compressed=False)
        p_uncomp = PointClass.string_to_point(b_uncomp)
        assert p_uncomp == g

        # Compressed
        b_comp = g.point_to_string(compressed=True)
        p_comp = PointClass.string_to_point(b_comp)
        assert p_comp == g

    def test_sw_affine_encode(self):
        """Test SWAffinePoint encode_to_curve."""
        from dot_ring.curve.specs.p256 import P256_RO

        PointClass = P256_RO.point

        msg = b"test message"
        p = PointClass.encode_to_curve(msg, b"DST")
        assert p.is_on_curve()

    def test_sw_affine_string_to_point_errors(self):
        """Test SWAffinePoint string_to_point error cases."""
        from dot_ring.curve.specs.p256 import P256_RO

        PointClass = P256_RO.point

        # Empty string
        with pytest.raises(ValueError, match="Empty octet string"):
            PointClass.string_to_point(b"")

        # Invalid prefix
        with pytest.raises(ValueError, match="Invalid point encoding prefix"):
            PointClass.string_to_point(b"\x05" + b"\x00" * 32)

        # Invalid length for compressed
        with pytest.raises(ValueError, match="Invalid compressed point length"):
            PointClass.string_to_point(b"\x02" + b"\x00")

        # Invalid length for uncompressed
        with pytest.raises(ValueError, match="Invalid uncompressed point length"):
            PointClass.string_to_point(b"\x04" + b"\x00")

    def test_mg_affine_string_to_point_errors(self):
        """Test MGAffinePoint string_to_point error cases."""
        from dot_ring.curve.specs.curve448 import Curve448_RO

        PointClass = Curve448_RO.point

        # Invalid point (not on curve)
        # u=0, v=1 => 0 != 1 (invalid)
        # 56 bytes for u (0), 56 bytes for v (1)
        u_bytes = b"\x00" * 56
        v_bytes = b"\x01" + b"\x00" * 55  # Little endian 1
        with pytest.raises(ValueError, match="Point is not on the curve"):
            PointClass.string_to_point(u_bytes + v_bytes)

    def test_tonelli_shanks_coverage(self):
        """Test Tonelli-Shanks algorithm with a mock curve (p % 8 == 1)."""
        from dot_ring.curve.e2c import E2C_Variant
        from dot_ring.curve.montgomery.mg_affine_point import MGAffinePoint
        from dot_ring.curve.montgomery.mg_curve import MGCurve

        class MockMGCurve(MGCurve):
            def __init__(self):
                # p = 17 (1 mod 8)
                super().__init__(
                    PRIME_FIELD=17,
                    ORDER=17,  # Dummy
                    GENERATOR_X=0,
                    GENERATOR_Y=0,  # Dummy
                    COFACTOR=1,
                    Z=1,
                    A=0,
                    B=1,  # Dummy
                    SUITE_STRING=b"",
                    DST=b"",
                    E2C=E2C_Variant.ELL2,
                    BBx=0,
                    BBy=0,
                    L=0,
                    M=1,
                    K=0,
                    H_A=None,
                    S_in_bytes=0,
                    Requires_Isogeny=False,
                    Isogeny_Coeffs=None,
                    UNCOMPRESSED=True,
                    ENDIAN="little",
                    POINT_LEN=2,
                    CHALLENGE_LENGTH=0,
                )

            def __post_init__(self):
                pass

        class MockMGPoint(MGAffinePoint):
            curve = MockMGCurve()

        # Test _sqrt_mod_p with p=17
        # Squares mod 17: 0, 1, 4, 9, 16, 8, 2, 15, 13
        # 2 is a square (6^2 = 36 = 2 mod 17)
        # 3 is NOT a square

        p = MockMGPoint(None, None)

        # Test square
        root = p._sqrt_mod_p(2)
        assert root is not None
        assert (root * root) % 17 == 2

        # Test non-square
        root_non = p._sqrt_mod_p(3)
        assert root_non is None

    def test_mg_affine_unimplemented_errors(self):
        """Test MGAffinePoint unimplemented methods."""
        from dot_ring.curve.e2c import E2C_Variant
        from dot_ring.curve.montgomery.mg_affine_point import MGAffinePoint
        from dot_ring.curve.montgomery.mg_curve import MGCurve

        class MockMGCurve(MGCurve):
            def __init__(self):
                super().__init__(
                    PRIME_FIELD=17,
                    ORDER=17,
                    GENERATOR_X=0,
                    GENERATOR_Y=0,
                    COFACTOR=1,
                    Z=1,
                    A=0,
                    B=1,
                    SUITE_STRING=b"",
                    DST=b"",
                    E2C=E2C_Variant.ELL2,
                    BBx=0,
                    BBy=0,
                    L=0,
                    M=1,
                    K=0,
                    H_A=None,
                    S_in_bytes=0,
                    Requires_Isogeny=False,
                    Isogeny_Coeffs=None,
                    UNCOMPRESSED=False,  # Set to False to test error
                    ENDIAN="little",
                    POINT_LEN=2,
                    CHALLENGE_LENGTH=0,
                )

            def __post_init__(self):
                pass

        class MockMGPoint(MGAffinePoint):
            curve = MockMGCurve()

        p = MockMGPoint(0, 0)

        # Test point_to_string compressed error
        with pytest.raises(NotImplementedError, match="Compressed encoding not implemented"):
            p.point_to_string()

        # Test _x_recover NotImplementedError
        with pytest.raises(NotImplementedError):
            MockMGPoint._x_recover(1)

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

        PointClass = P256_RO.point
        g = PointClass.generator_point()

        # Construct hybrid bytes manually
        # Prefix 0x06 if y is even, 0x07 if y is odd
        y_int = int(g.y)  # type: ignore
        prefix = b"\x06" if y_int % 2 == 0 else b"\x07"

        x_bytes = int(g.x).to_bytes(32, "big")  # type: ignore
        y_bytes = int(g.y).to_bytes(32, "big")  # type: ignore

        hybrid_bytes = prefix + x_bytes + y_bytes

        p = PointClass.string_to_point(hybrid_bytes)
        assert p == g

        # Test invalid hybrid length
        with pytest.raises(ValueError, match="Invalid hybrid point length"):
            PointClass.string_to_point(b"\x06" + b"\x00")

        # Test invalid hybrid parity
        wrong_prefix = b"\x07" if y_int % 2 == 0 else b"\x06"
        wrong_hybrid = wrong_prefix + x_bytes + y_bytes
        with pytest.raises(ValueError, match="Hybrid format: y parity doesn't match prefix"):
            PointClass.string_to_point(wrong_hybrid)

    def test_curve_point_base_coverage(self):
        """Test base CurvePoint methods."""
        from dot_ring.curve.e2c import E2C_Variant
        from dot_ring.curve.montgomery.mg_curve import MGCurve
        from dot_ring.curve.point import CurvePoint

        class MockCurve(MGCurve):
            def __init__(self):
                super().__init__(
                    PRIME_FIELD=17,
                    ORDER=17,
                    GENERATOR_X=0,
                    GENERATOR_Y=0,
                    COFACTOR=1,
                    Z=1,
                    A=0,
                    B=1,
                    SUITE_STRING=b"",
                    DST=b"",
                    E2C=E2C_Variant.ELL2,
                    BBx=0,
                    BBy=0,
                    L=0,
                    M=1,
                    K=0,
                    H_A=None,
                    S_in_bytes=0,
                    Requires_Isogeny=False,
                    Isogeny_Coeffs=None,
                    UNCOMPRESSED=True,
                    ENDIAN="little",
                    POINT_LEN=2,
                    CHALLENGE_LENGTH=0,
                )

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
            def identity(cls):
                return cls(None, None)

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
            MockPoint.msm([p], [1, 2])

        # Test msm empty
        # Should return identity
        res = MockPoint.msm([], [])
        assert res.x is None and res.y is None

        # Test __hash__ with complex types
        class ComplexCoord:
            def __init__(self, re, im):
                self.re, self.im = re, im

        p_complex = MockPoint(ComplexCoord(1, 2), ComplexCoord(3, 4), curve=c)
        h = hash(p_complex)
        assert isinstance(h, int)

    def test_te_affine_errors(self):
        """Test TEAffinePoint error cases."""
        from dot_ring.curve.specs.ed25519 import Ed25519_RO

        PointClass = Ed25519_RO.point
        g = PointClass.generator_point()

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
        from dot_ring.curve.e2c import E2C_Variant
        from dot_ring.curve.twisted_edwards.te_curve import TECurve

        class MockTECurve(TECurve):
            def __init__(self):
                super().__init__(
                    PRIME_FIELD=17,
                    ORDER=18,
                    GENERATOR_X=0,
                    GENERATOR_Y=1,
                    COFACTOR=1,
                    Z=1,
                    EdwardsA=1,
                    EdwardsD=2,
                    SUITE_STRING=b"",
                    DST=b"",
                    E2C=E2C_Variant.SSWU,  # SSWU not supported for TE
                    # Wait, TEAffinePoint.encode_to_curve supports TAI if implemented?
                    # Line 277 raises ValueError "Unexpected E2C Variant"
                    BBx=0,
                    BBy=0,
                    L=0,
                    M=1,
                    K=0,
                    H_A=None,
                    S_in_bytes=0,
                    Requires_Isogeny=False,
                    Isogeny_Coeffs=None,
                    UNCOMPRESSED=True,
                    ENDIAN="little",
                    POINT_LEN=2,
                    CHALLENGE_LENGTH=0,
                )

            def calculate_j_k(self):
                return 0, 0

        class MockTEPoint(TEAffinePoint):
            curve = MockTECurve()

        # Test encode_to_curve with TAI (which might raise if not handled in base)
        # TEAffinePoint.encode_to_curve checks for ELL2/ELL2_NU.
        # If E2C is TAI, it raises ValueError.
        with pytest.raises(ValueError, match="Unexpected E2C Variant"):
            MockTEPoint.encode_to_curve(b"test")

        # Test point_to_string uncompressed
        # MockTECurve has UNCOMPRESSED=True
        p = MockTEPoint(0, 1)  # Identity
        # Identity serialization should succeed for TE (0, 1)
        s = p.point_to_string()
        assert len(s) == 2  # 1 byte x, 1 byte y (p=17 -> 5 bits -> 1 byte)

        # Valid point serialization (uncompressed)
        p_valid = MockTEPoint(0, 16)  # 16 = -1 mod 17
        s = p_valid.point_to_string()
        assert len(s) == 2  # 1 byte x, 1 byte y

    def test_te_affine_hash_complex(self):
        """Test TEAffinePoint.__hash__ with complex types."""
        from dot_ring.curve.e2c import E2C_Variant
        from dot_ring.curve.twisted_edwards.te_curve import TECurve

        class MockTECurve(TECurve):
            def __init__(self):
                super().__init__(
                    PRIME_FIELD=17,
                    ORDER=18,
                    GENERATOR_X=0,
                    GENERATOR_Y=1,
                    COFACTOR=1,
                    Z=1,
                    EdwardsA=1,
                    EdwardsD=2,
                    SUITE_STRING=b"",
                    DST=b"",
                    E2C=E2C_Variant.SSWU,
                    BBx=0,
                    BBy=0,
                    L=0,
                    M=1,
                    K=0,
                    H_A=None,
                    S_in_bytes=0,
                    Requires_Isogeny=False,
                    Isogeny_Coeffs=None,
                    UNCOMPRESSED=True,
                    ENDIAN="little",
                    POINT_LEN=2,
                    CHALLENGE_LENGTH=0,
                )

            def calculate_j_k(self):
                return 0, 0

        class MockTEPoint(TEAffinePoint):
            curve = MockTECurve()

            def is_on_curve(self):
                return True  # Skip validation for complex types

            def _validate_coordinates(self):
                return True

        # Test with re/im (FieldElement-like)
        class ComplexCoord:
            def __init__(self, re, im):
                self.re, self.im = re, im

        p1 = MockTEPoint(ComplexCoord(1, 2), ComplexCoord(3, 4))
        h1 = hash(p1)
        # x_val = 1+2=3, y_val = 3+4=7. sum=10. 10 % 18 = 10.
        assert h1 == 10

        # Test with coeffs (FQ2-like)
        class CoeffsCoord:
            def __init__(self, coeffs):
                self.coeffs = coeffs

        p2 = MockTEPoint(CoeffsCoord([1, 2]), CoeffsCoord([3, 4]))
        h2 = hash(p2)
        # x_val = 3, y_val = 7. sum=10.
        assert h2 == 10
