
import pytest
from dot_ring.curve.specs.ed25519 import Ed25519_RO
from dot_ring.curve.glv import GLV

class TestCoverageGLV:
    def test_glv_identity_handling(self):
        """Test GLV methods with identity points."""
        PointClass = Ed25519_RO.point
        # We need access to the GLV instance.
        # It's usually attached to the curve or used by the point.
        # But here we can instantiate GLV directly and pass points.
        
        # Create a dummy GLV instance
        glv = GLV(lambda_param=1, constant_b=1, constant_c=1)
        
        g = PointClass.generator_point()
        identity = PointClass.identity_point()
        
        # Test windowed_simultaneous_mult with identity
        # P1 identity
        res1 = glv.windowed_simultaneous_mult(1, 1, identity, g)
        assert res1 == g
        
        # P2 identity
        res2 = glv.windowed_simultaneous_mult(1, 1, g, identity)
        assert res2 == g
        
        # Both identity
        res3 = glv.windowed_simultaneous_mult(1, 1, identity, identity)
        assert res3.is_identity()
        
        # Test multi_scalar_mult_4 with identity
        # One identity
        res4 = glv.multi_scalar_mult_4(1, 1, 1, 1, identity, g, g, g)
        assert res4 == g + g + g
        
        # All identity
        res5 = glv.multi_scalar_mult_4(1, 1, 1, 1, identity, identity, identity, identity)
        assert res5.is_identity()

    def test_glv_errors(self):
        """Test GLV error conditions."""
        glv = GLV(lambda_param=1, constant_b=1, constant_c=1)
        
        # Invalid parameters
        with pytest.raises(ValueError, match="Invalid GLV parameters"):
            GLV(lambda_param=0, constant_b=1, constant_c=1).__post_init__()
            
        # Extended Euclidean Algorithm invalid inputs
        with pytest.raises(ValueError, match="Inputs must be positive"):
            glv.extended_euclidean_algorithm(0, 1)
        with pytest.raises(ValueError, match="Inputs must be positive"):
            glv.extended_euclidean_algorithm(1, 0)
