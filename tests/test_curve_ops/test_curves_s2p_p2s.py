from dot_ring.curve.specs.p256 import P256Point
from dot_ring.curve.specs.curve25519 import Curve25519Point
from dot_ring.curve.specs.bandersnatch import BandersnatchPoint

def test_s2p_p2s_correctness():
    #test for Bandersnatch curve
    point=BandersnatchPoint.generator_point()
    S_repr=point.point_to_string()
    assert point==BandersnatchPoint.string_to_point(S_repr), "Invalid Conversion"

    #Test for P256 curve
    point=P256Point.generator_point()
    S_repr=point.point_to_string()
    assert point==P256Point.string_to_point(S_repr), "Invalid Conversion"

    #Test for Curve25519 curve
    point=Curve25519Point.generator_point()
    S_repr=point.point_to_string()
    assert point==Curve25519Point.string_to_point(S_repr), "Invalid Conversion"
