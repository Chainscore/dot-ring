
#ByteArray32_be
#ByteArray32_le
#to_int
#Fq to int
#tuple[FQ] to tuple[int,int]
#BqandersnatchPublic
#BandersnatchVRFSgn
#BandersnatchRingVRFSigm
#point_to_string
#string_to_point
#bls12_381 g1 compress
#g1 decompress
#g2 compress
#g2 decompress

from dot_ring.curve.specs.bandersnatch import (Bandersnatch_TE_Curve, BandersnatchPoint)
from typing import NamedTuple


class BigInt(NamedTuple):
    inner: list[int]


def process_field_elements(big_ints: list[BigInt]) -> list[int]:
    results = []
    limb_size = 64  # each limb represents 64 bits
    for b in big_ints:
        number = 0
        for index, limb in enumerate(b.inner):
            number += limb << (limb_size * index)
        results.append(number)
    return results


def test_h2f():
    # Test vector from specification
    expected_field_elements = process_field_elements([
        BigInt([13667986260176768296, 7615788394780045608, 16744902074056285084, 5843483180372586193]),
        BigInt([10069264885616157454, 379900787323118714, 5986637957723933190, 6530082265195051099]),
    ])

    data = bytes("foo", "utf-8")
    u = Bandersnatch_TE_Curve.hash_to_field(data, 2)
    assert u == expected_field_elements


def test_m2c():
    data = bytes("foo", "utf-8")

    u = Bandersnatch_TE_Curve.hash_to_field(data, 2)
    p0 = BandersnatchPoint.map_to_curve(u[0])
    p1 = BandersnatchPoint.map_to_curve(u[1])

    # Test vector from specification
    assert p0.x == 45311200032263316917859627542467284358670199398458214934254495151428460867180
    assert p0.y == 12776320642587906524824617948027275973876805685686439823724827627303230293583
    assert p1.x == 4062918070531615925962241074596089620660059154890696073867928698119996156623
    assert p1.y == 28091649524129975855673249115644895380082395569265826631567705939331162643040


def test_e2c():
    data = bytes("foo", "utf-8")

    u = BandersnatchPoint.encode_to_curve(data)

    # Test vector from specification
    assert u.x == 26037012954893424526367048031037997009889535281273781660989300420960588198291
    assert u.y == 2904166584983200306316763312322681981821413355244066354672834649878949825050