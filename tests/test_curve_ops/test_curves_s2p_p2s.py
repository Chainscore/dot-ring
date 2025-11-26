from dot_ring.curve.specs.p256 import P256_RO
from dot_ring.curve.specs.curve25519 import Curve25519_RO
from dot_ring.curve.specs.bandersnatch import Bandersnatch

def test_s2p_p2s_correctness():
    #test for Bandersnatch curve
    point=Bandersnatch.point.generator_point()
    S_repr=point.point_to_string()
    assert point==Bandersnatch.point.string_to_point(S_repr), "Invalid Conversion"

    #Test for P256 curve
    point=P256_RO.point.generator_point()
    S_repr=point.point_to_string()
    assert point==P256_RO.point.string_to_point(S_repr), "Invalid Conversion"

    #Test for P256 Uncompressed
    point=P256_RO.point.generator_point()
    S_repr=point.point_to_string(compressed=True)
    assert point==P256_RO.point.string_to_point(S_repr), "Invalid Conversion"

    #Test for Curve25519 curve
    point=Curve25519_RO.point.generator_point()
    S_repr=point.point_to_string()
    assert point==Curve25519_RO.point.string_to_point(S_repr), "Invalid Conversion"
