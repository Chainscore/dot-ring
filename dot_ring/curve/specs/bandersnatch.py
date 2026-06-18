from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Self, cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.native_field.bandersnatch_te import sqrt_mod_bls_scalar_cy as _native_sqrt

from ..glv import GLV
from ..twisted_edwards.te_affine_point import TEAffinePoint
from ..twisted_edwards.te_curve import TECurve
from .parameters import (
    AuxiliaryPointParams,
    Elligator2MontgomeryMap,
    EncodingParams,
    HashToCurveParams,
    TwistedEdwardsCurveParams,
)


def _pippenger_window_bits(point_count: int) -> int:
    if point_count < 8:
        return 2
    if point_count < 96:
        return 3
    if point_count < 192:
        return 4
    if point_count < 384:
        return 5
    if point_count < 768:
        return 6
    if point_count < 1024:
        return 7
    return 8


def elligator2_map_from_edwards(a: int, d: int, p: int) -> Elligator2MontgomeryMap:
    """Derive the Elligator 2 Montgomery map associated with a twisted Edwards curve."""
    denom_inv = pow((a - d) % p, -1, p)
    return Elligator2MontgomeryMap(
        a=(2 * (a + d) * denom_inv) % p,
        b=(4 * denom_inv) % p,
    )


@dataclass(frozen=True, kw_only=True)
class BandersnatchParams(TwistedEdwardsCurveParams):
    """Bandersnatch curve parameters."""

    glv_lambda: int
    glv_b: int
    glv_c: int


BANDERSNATCH_FIELD_MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
BANDERSNATCH_SUBGROUP_ORDER = 0x1CFB69D4CA675F520CCE760202687600FF8F87007419047174FD06B52876E7E1
BANDERSNATCH_GENERATOR = (
    18886178867200960497001835917649091219057080094937609519140440539760939937304,
    19188667384257783945677642223292697773471335439753913231509108946878080696678,
)
BANDERSNATCH_A = -5
BANDERSNATCH_D = 0x6389C12633C267CBC66E3BF86BE3B6D8CB66677177E54F92B369F2F5188D58E7
BANDERSNATCH_GLV_LAMBDA = 0x13B4F3DC4A39A493EDF849562B38C72BCFC49DB970A5056ED13D21408783DF05
BANDERSNATCH_GLV_B = 0x52C9F28B828426A561F00D3A63511A882EA712770D9AF4D6EE0F014D172510B4
BANDERSNATCH_GLV_C = 0x6CC624CF865457C3A97C6EFD6C17D1078456ABCFFF36F4E9515C806CDF650B3D


BANDERSNATCH_PARAMS = BandersnatchParams(
    field_modulus=BANDERSNATCH_FIELD_MODULUS,
    subgroup_order=BANDERSNATCH_SUBGROUP_ORDER,
    cofactor=4,
    suite_id=b"Bandersnatch-SHA512-ELL2-v1",
    hash_fn=hashlib.sha512,
    generator=BANDERSNATCH_GENERATOR,
    a=BANDERSNATCH_A,
    d=BANDERSNATCH_D,
    hash_to_curve=HashToCurveParams(
        dst=b"Bandersnatch-SHA512-ELL2-v1\x60",
        z=5,
        field_extension_degree=1,
        security_level=128,
        field_length=48,
        expand_len=48,
        elligator2_map=elligator2_map_from_edwards(BANDERSNATCH_A, BANDERSNATCH_D, BANDERSNATCH_FIELD_MODULUS),
    ),
    encoding=EncodingParams(endian="little", point_len=32, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            23335687741101763108036518445642207119627658113885888016488710494487028845889,
            5552214580375038693022409684979828600325210968745774080859660443337357929963,
        ),
        accumulator_base=(
            14056632001415368875257708737821299882600475929746323097150942355715730684350,
            10322661992765989500407719465917595459409463902187386706652408883505670839210,
        ),
        padding_point=(
            26913883415342152801331916189968962157924271221160514298872262294143390094043,
            30874728313203001508631936119690348239461579770372782660098261717479009115354,
        ),
    ),
    glv_lambda=BANDERSNATCH_GLV_LAMBDA,
    glv_b=BANDERSNATCH_GLV_B,
    glv_c=BANDERSNATCH_GLV_C,
)

BANDERSNATCH_SHAKE128_PARAMS = BandersnatchParams(
    field_modulus=BANDERSNATCH_FIELD_MODULUS,
    subgroup_order=BANDERSNATCH_SUBGROUP_ORDER,
    cofactor=4,
    suite_id=b"Bandersnatch-SHAKE128-ELL2-v1",
    hash_fn=hashlib.shake_128,
    generator=BANDERSNATCH_GENERATOR,
    a=BANDERSNATCH_A,
    d=BANDERSNATCH_D,
    hash_to_curve=HashToCurveParams(
        dst=b"Bandersnatch-SHAKE128-ELL2-v1\x60",
        z=5,
        field_extension_degree=1,
        security_level=128,
        field_length=48,
        expand_len=None,
        elligator2_map=elligator2_map_from_edwards(BANDERSNATCH_A, BANDERSNATCH_D, BANDERSNATCH_FIELD_MODULUS),
    ),
    encoding=EncodingParams(endian="little", point_len=32, challenge_len=16),
    auxiliary_points=AuxiliaryPointParams(
        blinding_base=(
            6153734995852631824944342602386415873379775188383988340041079006556670120775,
            27204351599954061630605768787803524395123895650061061132592995395630473050754,
        ),
        accumulator_base=(
            27631238720955528589004064829276283990465032040945349648037876197995278250917,
            37605358688136619817560700742505556266961225274493904038881144193539047100140,
        ),
        padding_point=(
            1834402953989431481748983728202937234471322740714585873803966488035889514523,
            52100941849053769665273763352270294131006971127418863694682093199651869272752,
        ),
    ),
    glv_lambda=BANDERSNATCH_GLV_LAMBDA,
    glv_b=BANDERSNATCH_GLV_B,
    glv_c=BANDERSNATCH_GLV_C,
)


BandersnatchGLV = GLV(
    lambda_param=BANDERSNATCH_PARAMS.glv_lambda,
    constant_b=BANDERSNATCH_PARAMS.glv_b,
    constant_c=BANDERSNATCH_PARAMS.glv_c,
)


class BandersnatchCurve(TECurve):
    """Bandersnatch curve with native base-field square roots."""

    def mod_sqrt(self, val: int) -> int:
        try:
            return int(_native_sqrt(val))
        except ValueError as exc:
            raise ValueError("No square root exists") from exc


Bandersnatch_TE_Curve = BandersnatchCurve(params=BANDERSNATCH_PARAMS, e2c_variant=E2C_Variant.ELL2)


class BandersnatchPoint(TEAffinePoint[TECurve]):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """

    def __mul__(self, scalar: int) -> Self:
        """
        GLV scalar multiplication using endomorphism.

        Args:
            scalar: Integer to multiply by

        Returns:
            TEAffinePoint: Scalar multiplication result
        """
        n = self.curve.params.subgroup_order
        k1, k2 = BandersnatchGLV.decompose_scalar(scalar % n, n)
        phi = BandersnatchGLV.compute_endomorphism(self)

        return cast(Self, BandersnatchGLV.windowed_simultaneous_mult(k1, k2, self, phi, w=2))

    @classmethod
    def msm(cls, points: list[Self], scalars: list[int], curve: TECurve) -> Self:
        """
        Optimized multi-scalar multiplication using GLV.
        """
        if len(points) != len(scalars):
            raise ValueError("Points and scalars must have same length")
        if not points:
            return cls.identity(curve)

        # Normalize scalars to [0, ORDER) for GLV
        n = curve.params.subgroup_order
        raw_scalars = scalars
        scalars = [s % n for s in scalars]

        if len(points) == 2:
            # Size-2 MSM using GLV to split into size-4 MSM
            # k1*P1 + k2*P2 = (k1_1 + k1_2*lambda)*P1 + (k2_1 + k2_2*lambda)*P2
            #               = k1_1*P1 + k1_2*phi(P1) + k2_1*P2 + k2_2*phi(P2)

            k1_1, k1_2 = BandersnatchGLV.decompose_scalar(scalars[0], n)
            k2_1, k2_2 = BandersnatchGLV.decompose_scalar(scalars[1], n)

            phi_P1 = BandersnatchGLV.compute_endomorphism(points[0])
            phi_P2 = BandersnatchGLV.compute_endomorphism(points[1])

            return cast(
                Self,
                BandersnatchGLV.multi_scalar_mult_4(k1_1, k1_2, k2_1, k2_2, points[0], phi_P1, points[1], phi_P2),
            )

        if len(points) == 4:
            if any(point.is_identity() for point in points):
                return super().msm(points, scalars, curve)

            return cast(
                Self,
                BandersnatchGLV.multi_scalar_mult_4(
                    scalars[0],
                    scalars[1],
                    scalars[2],
                    scalars[3],
                    points[0],
                    points[1],
                    points[2],
                    points[3],
                ),
            )

        if len(points) == 3:
            if any(point.is_identity() for point in points):
                return super().msm(points, scalars, curve)

            decomposed = [BandersnatchGLV.decompose_scalar(scalar, n) for scalar in scalars]
            phi_points = [BandersnatchGLV.compute_endomorphism(point) for point in points]
            return cast(
                Self,
                BandersnatchGLV.multi_scalar_mult_6(
                    [
                        decomposed[0][0],
                        decomposed[0][1],
                        decomposed[1][0],
                        decomposed[1][1],
                        decomposed[2][0],
                        decomposed[2][1],
                    ],
                    [
                        points[0],
                        phi_points[0],
                        points[1],
                        phi_points[1],
                        points[2],
                        phi_points[2],
                    ],
                ),
            )

        if len(points) >= 5:
            work_points = []
            work_scalars = []
            for point, scalar in zip(points, raw_scalars, strict=True):
                scalar %= n
                if scalar > n >> 1:
                    scalar -= n
                if scalar != 0 and not point.is_identity():
                    work_points.append(point)
                    work_scalars.append(scalar)
            if not work_points:
                return cls.identity(curve)
            if len(work_points) >= 5:
                window_bits = _pippenger_window_bits(len(work_points))
                return cast(Self, BandersnatchGLV.multi_scalar_mult_pippenger(work_scalars, work_points, window_bits=window_bits))

        return super().msm(points, scalars, curve)


Bandersnatch = CurveVariant(
    name="Bandersnatch",
    curve=Bandersnatch_TE_Curve,
    point_type=BandersnatchPoint,
)

Bandersnatch_SHAKE128_TE_Curve = BandersnatchCurve(params=BANDERSNATCH_SHAKE128_PARAMS, e2c_variant=E2C_Variant.ELL2)

Bandersnatch_SHAKE128 = CurveVariant(
    name="Bandersnatch_SHAKE128",
    curve=Bandersnatch_SHAKE128_TE_Curve,
    point_type=BandersnatchPoint,
)
