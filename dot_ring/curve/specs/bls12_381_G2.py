from __future__ import annotations

import hashlib
from typing import Self, cast

from py_ecc.bls12_381 import FQ2, add, multiply

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.fp2 import Fp2
from dot_ring.curve.point import CurvePoint

from ..short_weierstrass.sw_curve import SWCurve
from .parameters import (
    EncodingParams,
    HashToCurveParams,
    RationalIsogeny,
    ShortWeierstrassCurveParams,
    ShortWeierstrassModel,
)

BLS12_381_G2_FIELD_MODULUS = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB


def _fp2(re: int, im: int) -> Fp2:
    return Fp2(re, im, BLS12_381_G2_FIELD_MODULUS)


def _fp2_values(values: tuple[tuple[int, int], ...]) -> tuple[Fp2, ...]:
    return tuple(_fp2(re, im) for re, im in values)


BLS12_381_G2_ISOGENY = RationalIsogeny[Fp2](
    map_curve=ShortWeierstrassModel(a=_fp2(0, 240), b=_fp2(1012, 1012)),
    x_numerator=_fp2_values(
        (
            (
                0x171D6541FA38CCFAED6DEA691F5FB614CB14B4E7F4E810AA22D6108F142B85757098E38D0F671C7188E2AAAAAAAA5ED1,
                0,
            ),
            (
                0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71E,
                0x8AB05F8BDD54CDE190937E76BC3E447CC27C3D6FBD7063FCD104635A790520C0A395554E5C6AAAA9354FFFFFFFFE38D,
            ),
            (
                0,
                0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71A,
            ),
            (
                0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97D6,
                0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97D6,
            ),
        )
    ),
    x_denominator=_fp2_values(
        (
            (1, 0),
            (
                0xC,
                0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA9F,
            ),
            (
                0,
                0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA63,
            ),
        )
    ),
    y_numerator=_fp2_values(
        (
            (
                0x124C9AD43B6CF79BFBF7043DE3811AD0761B0F37A1E26286B0E977C69AA274524E79097A56DC4BD9E1B371C71C718B10,
                0,
            ),
            (
                0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71C,
                0x8AB05F8BDD54CDE190937E76BC3E447CC27C3D6FBD7063FCD104635A790520C0A395554E5C6AAAA9354FFFFFFFFE38F,
            ),
            (
                0,
                0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97BE,
            ),
            (
                0x1530477C7AB4113B59A4C18B076D11930F7DA5D4A07F649BF54439D87D27E500FC8C25EBF8C92F6812CFC71C71C6D706,
                0x1530477C7AB4113B59A4C18B076D11930F7DA5D4A07F649BF54439D87D27E500FC8C25EBF8C92F6812CFC71C71C6D706,
            ),
        )
    ),
    y_denominator=_fp2_values(
        (
            (1, 0),
            (
                0x12,
                0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA99,
            ),
            (
                0,
                0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA9D3,
            ),
            (
                0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA8FB,
                0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA8FB,
            ),
        )
    ),
)


BLS12_381_G2_PARAMS = ShortWeierstrassCurveParams[Fp2](
    field_modulus=BLS12_381_G2_FIELD_MODULUS,
    subgroup_order=0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    cofactor=0xBC69F08F2EE75B3584C6A0EA91B352888E2A8E9145AD7689986FF031508FFE1329C2F178731DB956D82BF015D1212B02EC0EC69D7477C1AE954CBC06689F6A359894C0ADEBBF6B4E8020005AAA95551,
    suite_id=b"BLS12381G2_XMD:SHA-256_SSWU_RO_",
    hash_fn=hashlib.sha256,
    generator=(
        _fp2(
            0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8,
            0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,
        ),
        _fp2(
            0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801,
            0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,
        ),
    ),
    a=_fp2(0, 0),
    b=_fp2(4, 4),
    hash_to_curve=HashToCurveParams(
        dst=b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_",
        z=_fp2(-2, -1),
        field_extension_degree=2,
        security_level=128,
        field_length=64,
        expand_len=64,
        isogeny=BLS12_381_G2_ISOGENY,
    ),
    encoding=EncodingParams(endian="little", point_len=32, challenge_len=32),
)


class BLS12_381_G2Point(CurvePoint[SWCurve[Fp2], Fp2]):
    """
    Point on the BLS12-381 G2 curve.

    Implements point operations specific to the BLS12-381 G2 curve.
    """

    def __init__(self, x: Fp2 | tuple[int, int] | None, y: Fp2 | tuple[int, int] | None, curve: SWCurve[Fp2]) -> None:
        super().__init__(self._coord(x, curve), self._coord(y, curve), curve)

    @staticmethod
    def _coord(value: Fp2 | tuple[int, int] | None, curve: SWCurve[Fp2]) -> Fp2 | None:
        if value is None:
            return None
        if isinstance(value, Fp2):
            if value.p != curve.params.field_modulus:
                raise ValueError("Fp2 coordinate uses the wrong field")
            return value
        if isinstance(value, tuple) and len(value) == 2:
            return Fp2(value[0], value[1], curve.params.field_modulus)
        raise TypeError("BLS12-381 G2 coordinates must be Fp2 values")

    def _py_ecc_point(self) -> tuple[FQ2, FQ2]:
        if self.is_identity() or self.x is None or self.y is None:
            raise ValueError("Cannot convert identity point to py_ecc affine point")
        return self.x.to_fq2(), self.y.to_fq2()

    @classmethod
    def _from_py_ecc_point(cls, point: tuple[FQ2, FQ2] | None, curve: SWCurve[Fp2]) -> BLS12_381_G2Point:
        if point is None:
            return cls.identity(curve)
        return cls(Fp2.from_fq2(point[0], curve.params.field_modulus), Fp2.from_fq2(point[1], curve.params.field_modulus), curve)

    def _validate_coordinates(self) -> bool:
        if self.x is None and self.y is None:
            return True
        if self.x is None or self.y is None:
            return False
        return self.x.p == self.curve.params.field_modulus and self.y.p == self.curve.params.field_modulus

    def is_on_curve(self) -> bool:
        if self.is_identity():
            return True
        if self.x is None or self.y is None:
            return False
        return self.curve.is_on_curve((self.x, self.y))

    def is_identity(self) -> bool:
        return self.x is None and self.y is None

    @classmethod
    def identity(cls, curve: SWCurve[Fp2]) -> BLS12_381_G2Point:
        return cls(None, None, curve)

    def clear_cofactor(self) -> BLS12_381_G2Point:
        return self * self.curve.params.cofactor

    def point_to_string(self) -> bytes:
        raise NotImplementedError("BLS12-381 G2 point serialization is not implemented")

    @classmethod
    def string_to_point(cls, data: str | bytes, curve: SWCurve[Fp2]) -> BLS12_381_G2Point:
        raise NotImplementedError("BLS12-381 G2 point deserialization is not implemented")

    def __add__(self, other: BLS12_381_G2Point) -> BLS12_381_G2Point:  # type: ignore[override]
        """
        Add two points on the BLS12-381 G2 curve using the group law.

        Args:
            other: Another point on the curve

        Returns:
            BLS12_381_G2Point: The sum of the two points
        """
        if not isinstance(other, BLS12_381_G2Point):
            raise TypeError("Can only add BLS12_381_G2Point instances")

        # Handle identity element
        if self.is_identity():
            return other
        if other.is_identity():
            return self

        return self._from_py_ecc_point(add(self._py_ecc_point(), other._py_ecc_point()), self.curve)

    def __neg__(self) -> BLS12_381_G2Point:
        """
        Negate a point on the BLS12-381 G2 curve.
        For a point (x, y), the negation is (x, -y).

        Returns:
            BLS12_381_G2Point: The negated point
        """
        if self.is_identity():
            return self

        if self.x is None or self.y is None:
            raise ValueError("Invalid G2 point coordinate")
        return self.__class__(self.x, -self.y, self.curve)

    def __sub__(self, other: BLS12_381_G2Point) -> BLS12_381_G2Point:  # type: ignore[override]
        """
        Subtract one point from another on the BLS12-381 G2 curve.
        This is equivalent to adding the negation of the other point.

        Args:
            other: Point to subtract

        Returns:
            BLS12_381_G2Point: Result of point subtraction
        """
        if not isinstance(other, BLS12_381_G2Point):
            raise TypeError("Can only subtract BLS12_381_G2Point instances")

        return self + (-other)

    def __mul__(self, scalar: int) -> BLS12_381_G2Point:
        """
        Multiply a point by a scalar using the group law.

        Args:
            scalar: Integer scalar to multiply by

        Returns:
            BLS12_381_G2Point: The result of scalar multiplication
        """
        if scalar == 0:
            return self.identity(self.curve)
        if scalar < 0:
            return (-self) * (-scalar)
        return self._from_py_ecc_point(multiply(self._py_ecc_point(), scalar), self.curve)

    @classmethod
    def encode_to_curve(
        cls,
        alpha_string: bytes | str,
        salt: bytes | str = b"",
        curve: SWCurve[Fp2] | None = None,
    ) -> BLS12_381_G2Point:
        if curve is None:
            raise ValueError("curve is required")
        if not isinstance(alpha_string, bytes):
            alpha_string = bytes.fromhex(alpha_string)
        if not isinstance(salt, bytes):
            salt = bytes.fromhex(salt)

        if curve.e2c_variant == E2C_Variant.SSWU_NU:
            return cls._encode_sswu_nu(alpha_string, curve, salt)
        if curve.e2c_variant == E2C_Variant.SSWU:
            return cls._encode_sswu_ro(alpha_string, curve, salt)
        raise ValueError(f"Unexpected E2C Variant: {curve.e2c_variant}")

    @classmethod
    def _encode_sswu_ro(
        cls,
        alpha_string: bytes,
        curve: SWCurve[Fp2],
        salt: bytes = b"",
    ) -> Self:
        """Encode with the random-oracle simplified-SWU hash-to-curve variant."""
        string_to_hash = salt + alpha_string

        # Get field elements - this returns [re0, im0, re1, im1]
        u_raw = curve.hash_to_field(string_to_hash, 2)
        u = (
            Fp2(u_raw[0], u_raw[1], curve.params.field_modulus),
            Fp2(u_raw[2], u_raw[3], curve.params.field_modulus),
        )

        q0 = cls.map_to_curve_simple_swu(u[0], curve)

        q1 = cls.map_to_curve_simple_swu(u[1], curve)

        R = q0 + q1
        return cast(Self, R * curve.params.cofactor)

    @classmethod
    def _encode_sswu_nu(
        cls,
        alpha_string: bytes,
        curve: SWCurve[Fp2],
        salt: bytes = b"",
    ) -> Self:
        """Encode with the nonuniform simplified-SWU hash-to-curve variant."""
        string_to_hash = salt + alpha_string
        u_raw = curve.hash_to_field(string_to_hash, 1)  # for nu

        u0 = Fp2(u_raw[0], u_raw[1], curve.params.field_modulus)
        q0 = cls.map_to_curve_simple_swu(u0, curve)
        return cast(Self, q0 * curve.params.cofactor)

    @classmethod
    def map_to_curve_simple_swu(cls, u: Fp2, curve: SWCurve) -> BLS12_381_G2Point:  # type: ignore[override]
        """
        Simplified SWU map with 3-isogeny for BLS12-381 G2
        Combines SSWU map and 3-isogeny map in one function
        """
        # 1. Map to the isogenous curve E'
        point_on_e_prime = cls._sswu_map_to_e_prime(u, curve)

        # 2. Apply 3-isogeny map from E' to E
        x, y = cls._apply_3_isogeny(point_on_e_prime, curve)

        point = cls(x, y, curve)
        if not point.is_on_curve():
            left = y * y
            right = x * x * x + cast(Fp2, curve.params.b)
            assert left == right, "point is not on the curve"
            raise ValueError("Mapped point is not on the curve")
        return point

    @staticmethod
    def _sgn0(x: Fp2) -> int:
        return x.sgn0()

    @staticmethod
    def _require_isogeny(curve: SWCurve) -> RationalIsogeny[Fp2]:
        isogeny = curve.params.hash_to_curve.isogeny
        if isogeny is None:
            raise ValueError("Missing isogeny")
        return cast(RationalIsogeny[Fp2], isogeny)

    @classmethod
    def _evaluate_fp2_polynomial(cls, coefficients: tuple[Fp2, ...], x: Fp2) -> Fp2:
        value = Fp2(0, 0, x.p)
        for coefficient in coefficients:
            value = value * x + coefficient
        return value

    @classmethod
    def _sswu_map_to_e_prime(cls, u: Fp2, curve: SWCurve) -> tuple[Fp2, Fp2]:
        isogeny = cls._require_isogeny(curve)
        Z = cast(Fp2, curve.params.hash_to_curve.z)
        A_prime = isogeny.map_curve.a
        B_prime = isogeny.map_curve.b

        u_sq = u * u
        u_4 = u_sq * u_sq
        tv1 = Z * Z * u_4 + Z * u_sq
        tv1 = Fp2(0, 0, u.p) if tv1.is_zero() else tv1.inv()

        if tv1.is_zero():
            x1 = B_prime * ((Z * A_prime).inv())
        else:
            x1 = (-B_prime * (A_prime.inv())) * (1 + tv1)
        gx1 = x1**3 + A_prime * x1 + B_prime

        if gx1.is_square():
            y1 = gx1.sqrt()
            assert y1 is not None
            left = y1 * y1
            right = x1 * x1 * x1 + A_prime * x1 + B_prime
            assert left == right, "Invalid point on E'"
            x, y = x1, y1
        else:
            x2 = Z * u_sq * x1
            gx2 = x2**3 + A_prime * x2 + B_prime
            y2 = gx2.sqrt()
            assert y2 is not None
            left = y2 * y2
            right = x2 * x2 * x2 + A_prime * x2 + B_prime
            assert left == right, "Invalid point on E'"
            x, y = x2, y2

        # Step 9: Ensure sgn0(u) == sgn0(y)
        if cls._sgn0(u) != cls._sgn0(cast(Fp2, y)):
            y = -cast(Fp2, y)
        return x, cast(Fp2, y)

    @classmethod
    def _apply_3_isogeny(cls, point: tuple[Fp2, Fp2], curve: SWCurve) -> tuple[Fp2, Fp2]:
        x_prime, y_prime = point
        isogeny = cls._require_isogeny(curve)

        x_num = cls._evaluate_fp2_polynomial(isogeny.x_numerator, x_prime)
        x_den = cls._evaluate_fp2_polynomial(isogeny.x_denominator, x_prime)
        x = x_num / x_den

        y_num = cls._evaluate_fp2_polynomial(isogeny.y_numerator, x_prime)
        y_den = cls._evaluate_fp2_polynomial(isogeny.y_denominator, x_prime)
        y = y_prime * (y_num / y_den)

        # Verify the point is on the curve
        left = y * y
        right = x * x * x + cast(Fp2, curve.params.b)
        assert left == right, "Mapped point is not on the curve"
        return x, y


BLS12_381_G2_NU = CurveVariant(
    name="BLS12_381_G2_NU",
    curve=SWCurve(params=BLS12_381_G2_PARAMS, e2c_variant=E2C_Variant.SSWU_NU),
    point_type=BLS12_381_G2Point,
)

BLS12_381_G2_RO = CurveVariant(
    name="BLS12_381_G2_RO",
    curve=SWCurve(params=BLS12_381_G2_PARAMS, e2c_variant=E2C_Variant.SSWU),
    point_type=BLS12_381_G2Point,
)
