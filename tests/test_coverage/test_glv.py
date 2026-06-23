"""Additional tests for GLV module to improve coverage."""

from dot_ring.curve.glv import GLV


class TestGLVScalarDecomposition:
    """Test GLV scalar decomposition."""

    def test_decompose_scalar_small(self):
        """Test scalar decomposition with small scalar."""
        from dot_ring.curve.specs.bandersnatch import BANDERSNATCH_PARAMS

        glv = GLV(
            lambda_param=BANDERSNATCH_PARAMS.glv_lambda,
            constant_b=BANDERSNATCH_PARAMS.glv_b,
            constant_c=BANDERSNATCH_PARAMS.glv_c,
        )

        scalar = 12345
        n = BANDERSNATCH_PARAMS.subgroup_order

        k1, k2 = glv.decompose_scalar(scalar, n)

        # k1 + k2 * lambda should equal scalar mod n
        lambda_param = BANDERSNATCH_PARAMS.glv_lambda
        reconstructed = (k1 + k2 * lambda_param) % n
        assert reconstructed == scalar % n

    def test_decompose_scalar_large(self):
        """Test scalar decomposition with large scalar."""
        from dot_ring.curve.specs.bandersnatch import BANDERSNATCH_PARAMS

        glv = GLV(
            lambda_param=BANDERSNATCH_PARAMS.glv_lambda,
            constant_b=BANDERSNATCH_PARAMS.glv_b,
            constant_c=BANDERSNATCH_PARAMS.glv_c,
        )

        # Use a large scalar
        scalar = 2**200 + 12345
        n = BANDERSNATCH_PARAMS.subgroup_order

        k1, k2 = glv.decompose_scalar(scalar % n, n)

        # k1 + k2 * lambda should equal scalar mod n
        lambda_param = BANDERSNATCH_PARAMS.glv_lambda
        reconstructed = (k1 + k2 * lambda_param) % n
        assert reconstructed == scalar % n

    def test_decompose_scalar_zero(self):
        """Test scalar decomposition with zero scalar."""
        from dot_ring.curve.specs.bandersnatch import BANDERSNATCH_PARAMS

        glv = GLV(
            lambda_param=BANDERSNATCH_PARAMS.glv_lambda,
            constant_b=BANDERSNATCH_PARAMS.glv_b,
            constant_c=BANDERSNATCH_PARAMS.glv_c,
        )

        scalar = 0
        n = BANDERSNATCH_PARAMS.subgroup_order

        k1, k2 = glv.decompose_scalar(scalar, n)

        # 0 = k1 + k2 * lambda mod n
        lambda_param = BANDERSNATCH_PARAMS.glv_lambda
        reconstructed = (k1 + k2 * lambda_param) % n
        assert reconstructed == 0


class TestGLVEndomorphism:
    """Test GLV endomorphism computation."""

    def test_compute_endomorphism(self):
        """Test computing endomorphism."""
        from dot_ring.curve.specs.bandersnatch import Bandersnatch, BandersnatchGLV

        G = Bandersnatch.point_type.generator_point()

        phi_G = BandersnatchGLV.compute_endomorphism(G)

        assert phi_G is not None
        assert not phi_G.is_identity()

    def test_endomorphism_lambda_times_generator(self):
        """Test that phi(P) = lambda * P for the endomorphism."""
        from dot_ring.curve.specs.bandersnatch import BANDERSNATCH_PARAMS, Bandersnatch, BandersnatchGLV

        G = Bandersnatch.point_type.generator_point()

        phi_G = BandersnatchGLV.compute_endomorphism(G)
        lambda_G = G * BANDERSNATCH_PARAMS.glv_lambda

        # phi(G) should equal lambda * G
        assert phi_G == lambda_G


class TestGLVWindowedMult:
    """Test GLV windowed multiplication."""

    def test_windowed_simultaneous_mult_basic(self):
        """Test windowed simultaneous multiplication."""
        from dot_ring.curve.specs.bandersnatch import Bandersnatch, BandersnatchGLV

        G = Bandersnatch.point_type.generator_point()
        phi_G = BandersnatchGLV.compute_endomorphism(G)

        k1 = 100
        k2 = 200

        result = BandersnatchGLV.windowed_simultaneous_mult(k1, k2, G, phi_G, w=2)

        expected = G * k1 + phi_G * k2
        assert result == expected

    def test_windowed_mult_with_negative_k1(self):
        """Test windowed mult with negative k1."""
        from dot_ring.curve.specs.bandersnatch import Bandersnatch, BandersnatchGLV

        G = Bandersnatch.point_type.generator_point()
        phi_G = BandersnatchGLV.compute_endomorphism(G)

        k1 = -50
        k2 = 100

        result = BandersnatchGLV.windowed_simultaneous_mult(k1, k2, G, phi_G, w=2)

        expected = G * k1 + phi_G * k2
        assert result == expected

    def test_windowed_mult_with_negative_k2(self):
        """Test windowed mult with negative k2."""
        from dot_ring.curve.specs.bandersnatch import Bandersnatch, BandersnatchGLV

        G = Bandersnatch.point_type.generator_point()
        phi_G = BandersnatchGLV.compute_endomorphism(G)

        k1 = 100
        k2 = -75

        result = BandersnatchGLV.windowed_simultaneous_mult(k1, k2, G, phi_G, w=2)

        expected = G * k1 + phi_G * k2
        assert result == expected

    def test_windowed_mult_both_negative(self):
        """Test windowed mult with both k1 and k2 negative."""
        from dot_ring.curve.specs.bandersnatch import Bandersnatch, BandersnatchGLV

        G = Bandersnatch.point_type.generator_point()
        phi_G = BandersnatchGLV.compute_endomorphism(G)

        k1 = -30
        k2 = -40

        result = BandersnatchGLV.windowed_simultaneous_mult(k1, k2, G, phi_G, w=2)

        expected = G * k1 + phi_G * k2
        assert result == expected
