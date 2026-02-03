from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final, Self, cast

from py_ecc.bls12_381 import FQ2, add, multiply

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..field_element import FieldElement
from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..short_weierstrass.sw_curve import SWCurve

Fp2 = tuple[int, int]


@dataclass(frozen=True)
class BLS12_381_G2Params:
    """
    BLS12-381 G2 curve parameters.

    The BLS12-381 curve is a pairing-friendly curve that is part of the BLS family.
    This implementation follows RFC 9380 Section 8.8.2 for hash-to-curve operations.
    """

    # From RFC 9380 Section 8.8.2: BLS12-381 G2
    SUITE_STRING = b"BLS12381G2_XMD:SHA-256_SSWU_RO_"
    DST = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"  # Use the suite string as DST by default per RFC 9380
    # Base field characteristic (modulus)
    PRIME_FIELD: Final[int] = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB

    # Subgroup order (r)
    ORDER: Final[int] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

    # Cofactor (h)
    COFACTOR: Final[int] = (
        0xBC69F08F2EE75B3584C6A0EA91B352888E2A8E9145AD7689986FF031508FFE1329C2F178731DB956D82BF015D1212B02EC0EC69D7477C1AE954CBC06689F6A359894C0ADEBBF6B4E8020005AAA95551  # noqa: E501
    )

    # Generator point (G2)
    GENERATOR_X: Final[Fp2] = (
        0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8,  # noqa: E501
        0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,  # noqa: E501
    )
    GENERATOR_Y: Final[Fp2] = (
        0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801,  # noqa: E501
        0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,  # noqa: E501
    )

    # Curve equation: y² = x³ + 4(1 + i)
    WEIERSTRASS_A: Final[Fp2] = (0, 0)
    WEIERSTRASS_B: Final[Fp2] = (4, 4)  # 4 * (1 + i)

    # Z parameter for SSWU mapping (from RFC 9380 Section 8.8.2)
    Z: Final[Fp2] = (-2, -1)  # 1 + i

    # Security parameters
    M: Final[int] = 2  # Extension field degree (Fp2)
    K: Final[int] = 128  # Security level in bits
    L: Final[int] = 64  # Number of bytes for XMD
    S_in_bytes: Final[int] = 64  # Length of domain separation tag
    H_A = hashlib.sha256
    ENDIAN = "little"
    # VRF parameters
    CHALLENGE_LENGTH: Final[int] = 32  # 256-bit challenge

    # Isogeny parameters
    Requires_Isogeny: Final[bool] = True
    Isogeny_Coeffs = None

    # Blinding base for Pedersen VRF (not used in basic implementation)
    BBx: Final[Fp2 | None] = None
    BBy: Final[Fp2 | None] = None
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 32


class BLS12_381_G2Curve(SWCurve):
    """
    BLS12-381 G2 curve implementation.

    This curve is defined over a quadratic extension field Fp2 and is primarily
    used for cryptographic pairings in the BLS signature scheme.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> None:
        SUITE_STRING = BLS12_381_G2Params.SUITE_STRING
        DST = BLS12_381_G2Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        super().__init__(
            PRIME_FIELD=BLS12_381_G2Params.PRIME_FIELD,
            ORDER=BLS12_381_G2Params.ORDER,
            GENERATOR_X=BLS12_381_G2Params.GENERATOR_X,
            GENERATOR_Y=BLS12_381_G2Params.GENERATOR_Y,
            COFACTOR=BLS12_381_G2Params.COFACTOR,
            Z=BLS12_381_G2Params.Z,
            WeierstrassA=BLS12_381_G2Params.WEIERSTRASS_A,
            WeierstrassB=BLS12_381_G2Params.WEIERSTRASS_B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=BLS12_381_G2Params.BBx,
            BBy=BLS12_381_G2Params.BBy,
            M=BLS12_381_G2Params.M,
            K=BLS12_381_G2Params.K,
            L=BLS12_381_G2Params.L,
            S_in_bytes=BLS12_381_G2Params.S_in_bytes,
            H_A=BLS12_381_G2Params.H_A,
            Requires_Isogeny=BLS12_381_G2Params.Requires_Isogeny,
            Isogeny_Coeffs=BLS12_381_G2Params.Isogeny_Coeffs,
            UNCOMPRESSED=BLS12_381_G2Params.UNCOMPRESSED,
            ENDIAN=BLS12_381_G2Params.ENDIAN,
            POINT_LEN=BLS12_381_G2Params.POINT_LEN,
            CHALLENGE_LENGTH=BLS12_381_G2Params.CHALLENGE_LENGTH,
        )


# Singleton instance for convenience
BLS12_381_G2_SW_Curve: Final[BLS12_381_G2Curve] = BLS12_381_G2Curve()


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> type[BLS12_381_G2Point]:
    # Create curve with the specified variant
    curve = BLS12_381_G2Curve(e2c_variant)

    # Create and return a point class with this curve
    class BLS12_381_G2PointVariant(BLS12_381_G2Point):
        """Point on BLS12_381_G1 with custom E2C variant"""

        def __init__(self, x: int, y: int) -> None:
            """Initialize a point with the variant curve."""
            SWAffinePoint.__init__(self, x, y, curve)

    # Set the curve as a class attribute
    BLS12_381_G2PointVariant.curve = curve

    return BLS12_381_G2PointVariant


class BLS12_381_G2Point(SWAffinePoint):
    """
    Point on the BLS12-381 G2 curve.

    Implements point operations specific to the BLS12-381 G2 curve.
    """

    curve: BLS12_381_G2Curve = BLS12_381_G2_SW_Curve

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

        # Helper function to convert coordinates to FQ2 format
        def to_fq2(
            x: int | tuple[int, int] | FieldElement,
            y: int | tuple[int, int] | FieldElement,
        ) -> tuple[FQ2, FQ2]:
            # If x is a tuple, use it directly
            if isinstance(x, tuple) and isinstance(y, tuple):
                return (FQ2([x[0], x[1]]), FQ2([y[0], y[1]]))
            # If x is a FieldElement, use its re and im attributes
            elif hasattr(x, "re") and hasattr(x, "im"):
                x = cast(FieldElement, x)
                y = cast(FieldElement, y)
                return (FQ2([x.re, x.im]), FQ2([y.re, y.im]))
            # Fallback for other cases (shouldn't happen)
            else:
                return (FQ2([cast(int, x), 0]), FQ2([cast(int, y), 0]))

        # Convert points to FQ2 format for py_ecc
        p1 = to_fq2(
            cast(int | tuple[int, int] | FieldElement, self.x),
            cast(int | tuple[int, int] | FieldElement, self.y),
        )
        p2 = to_fq2(
            cast(int | tuple[int, int] | FieldElement, other.x),
            cast(int | tuple[int, int] | FieldElement, other.y),
        )

        # Perform addition using py_ecc
        result = add(p1, p2)
        if result is None:
            return self.identity()

        # Convert back to tuple format
        x = (int(result[0].coeffs[0]), int(result[0].coeffs[1]))
        y = (int(result[1].coeffs[0]), int(result[1].coeffs[1]))

        return self.__class__(x, y)

    def __neg__(self) -> BLS12_381_G2Point:
        """
        Negate a point on the BLS12-381 G2 curve.
        For a point (x, y), the negation is (x, -y).

        Returns:
            BLS12_381_G2Point: The negated point
        """
        if self.is_identity():
            return self

        # Use FieldElement's negation if y is a FieldElement
        if hasattr(self.y, "__neg__"):
            neg_y = -self.y  # type: ignore[operator]
        # Handle tuple case (Fp2 elements)
        elif isinstance(self.y, tuple):
            from ..field_element import FieldElement

            p = self.curve.PRIME_FIELD
            # Convert tuple to FieldElement, negate, then convert back
            y_fe = FieldElement(self.y[0], self.y[1], p)
            neg_y_fe = -y_fe
            neg_y = (neg_y_fe.re, neg_y_fe.im)
        else:
            # Fallback for regular integers
            if self.y is None:
                raise ValueError("Cannot negate identity point")
            neg_y = (-self.y) % self.curve.PRIME_FIELD

        return self.__class__(self.x, neg_y)

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
            return self.identity()
        if scalar < 0:
            return (-self) * (-scalar)
        try:
            # Convert point to FQ2 format for py_ecc
            # Try treating as tuple/list first
            p = (
                FQ2([cast(Any, self.x)[0], cast(Any, self.x)[1]]),
                FQ2([cast(Any, self.y)[0], cast(Any, self.y)[1]]),
            )

        except (TypeError, IndexError):
            # Fallback to .re/.im attributes (FieldElement)
            x_num = [cast(Any, self.x).re, cast(Any, self.x).im]
            y_num = [cast(Any, self.y).re, cast(Any, self.y).im]
            p = (FQ2(x_num), FQ2(y_num))

        # Perform scalar multiplication using py_ecc
        result = multiply(p, scalar)

        if result is None:
            return self.identity()

        # Convert back to tuple format
        x = (int(result[0].coeffs[0]), int(result[0].coeffs[1]))
        y = (int(result[1].coeffs[0]), int(result[1].coeffs[1]))

        return self.__class__(x, y)

    @classmethod
    def sswu_hash2_curve_ro(cls, alpha_string: bytes, salt: bytes = b"", General_Check: bool = False) -> dict | Self:
        """
        Encode a string to a curve point using SSWU map with 3-isogeny (Random Oracle variant).

        Args:
            alpha_string: String to encode
            salt: Optional salt for domain separation
            General_Check: Flag for test suite compatibility

        Returns:
            dict: Dictionary containing the resulting point and raw U values
        """
        string_to_hash = salt + alpha_string

        # Get field elements - this returns [re0, im0, re1, im1]
        u = cls.curve.hash_to_field(string_to_hash, 2)
        u0 = FieldElement(u[0], u[1], cls.curve.PRIME_FIELD)
        u1 = FieldElement(u[2], u[3], cls.curve.PRIME_FIELD)

        q0 = cls.map_to_curve_simple_swu(u0)

        q1 = cls.map_to_curve_simple_swu(u1)

        R = q0 + q1
        R = R * cls.curve.COFACTOR
        if General_Check:
            return {"u": [u0, u1], "Q0": q0, "Q1": q1, "R": R}
        return cast(Self, R)

    @classmethod
    def sswu_hash2_curve_nu(cls, alpha_string: bytes, salt: bytes = b"", General_Check: bool = False) -> Self | Any:
        """
        Encode a string to a curve point using Elligator 2.

        Args:
            alpha_string: String to encode
            salt: Optional salt for the encoding
            General_Check:Just for printing all test suites

        Returns:
            TEAffinePoint: Resulting curve point
        """
        string_to_hash = salt + alpha_string
        u = cls.curve.hash_to_field(string_to_hash, 1)  # for nu

        u0 = FieldElement(u[0], u[1], cls.curve.PRIME_FIELD)
        q0 = cls.map_to_curve_simple_swu(u0)
        R = q0 * cls.curve.COFACTOR
        if General_Check:
            return {"u": u, "Q0": q0, "R": R}

        return R

    @classmethod
    def map_to_curve_simple_swu(cls, u: FieldElement) -> BLS12_381_G2Point:  # type: ignore[override]
        """
        Simplified SWU map with 3-isogeny for BLS12-381 G2
        Combines SSWU map and 3-isogeny map in one function
        """
        # 1. Map to the isogenous curve E'
        point_on_e_prime = cls._sswu_map_to_e_prime(u)

        # 2. Apply 3-isogeny map from E' to E
        x, y = cls._apply_3_isogeny(point_on_e_prime)

        # 3. Wrap into a BLS12_381_G2Point object
        # Convert FieldElements to tuples
        x_tuple = (x.re, x.im)
        y_tuple = (y.re, y.im)
        point = cls(x_tuple, y_tuple)
        if not point.is_on_curve():
            print("ERROR: Point is not on the curve after mapping!")
            # Print curve equation and point for debugging
            left = y * y
            right = x * x * x + FieldElement(4, 4, x.p)  # 4 * (1 + i)
            assert left == right, "point is not on the curve"
            raise ValueError("Mapped point is not on the curve")
        return point

    @staticmethod
    def _sgn0(x: FieldElement) -> int:
        """
        Return the sign of x: 1 if odd, 0 if even.

        Args:
            x: Field element (Fp2)

        Returns:
            int: 1 if the integer representation is odd, 0 if even
        """
        # For Fp2, we use the lexicographic order as specified in RFC 9380
        # sgn0(x) = sgn0(x0) if x0 != 0 else sgn0(x1)
        x0, x1 = x.re, x.im

        # sgn0 for Fp: 1 if odd, 0 if even
        def sgn0_fp(a: int) -> int:
            return a % 2

        if x0 != 0:
            return sgn0_fp(x0)
        return sgn0_fp(x1)

    @classmethod
    def _sswu_map_to_e_prime(cls, u: FieldElement) -> tuple[FieldElement, FieldElement]:
        p = u.p
        Z = FieldElement(-2, -1, p)  # -(2 + I)
        A_prime = FieldElement(0, 240, p)  # 240*I
        B_prime = FieldElement(1012, 1012, p)  # 1012*(1+I)

        u_sq = u * u
        u_4 = u_sq * u_sq
        tv1 = Z * Z * u_4 + Z * u_sq
        tv1 = tv1.inv()

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
        if cls._sgn0(u) != cls._sgn0(cast(FieldElement, y)):
            y = -cast(FieldElement, y)
        return x, cast(FieldElement, y)

    @classmethod
    def _apply_3_isogeny(cls, point: tuple[FieldElement, FieldElement]) -> tuple[FieldElement, FieldElement]:
        x_prime, y_prime = point
        p = cls.curve.PRIME_FIELD

        # Constants from RFC 9380
        k_1_0 = FieldElement(
            0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97D6,
            0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97D6,
            p,
        )
        k_1_1 = FieldElement(
            0,
            0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71A,
            p,
        )
        k_1_2 = FieldElement(
            0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71E,
            0x8AB05F8BDD54CDE190937E76BC3E447CC27C3D6FBD7063FCD104635A790520C0A395554E5C6AAAA9354FFFFFFFFE38D,
            p,
        )
        k_1_3 = FieldElement(
            0x171D6541FA38CCFAED6DEA691F5FB614CB14B4E7F4E810AA22D6108F142B85757098E38D0F671C7188E2AAAAAAAA5ED1,
            0,
            p,
        )

        k_2_0 = FieldElement(
            0,
            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA63,
            p,
        )
        k_2_1 = FieldElement(
            0xC,
            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA9F,
            p,
        )

        k_3_0 = FieldElement(
            0x1530477C7AB4113B59A4C18B076D11930F7DA5D4A07F649BF54439D87D27E500FC8C25EBF8C92F6812CFC71C71C6D706,
            0x1530477C7AB4113B59A4C18B076D11930F7DA5D4A07F649BF54439D87D27E500FC8C25EBF8C92F6812CFC71C71C6D706,
            p,
        )
        k_3_1 = FieldElement(
            0,
            0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97BE,
            p,
        )
        k_3_2 = FieldElement(
            0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71C,
            0x8AB05F8BDD54CDE190937E76BC3E447CC27C3D6FBD7063FCD104635A790520C0A395554E5C6AAAA9354FFFFFFFFE38F,
            p,
        )
        k_3_3 = FieldElement(
            0x124C9AD43B6CF79BFBF7043DE3811AD0761B0F37A1E26286B0E977C69AA274524E79097A56DC4BD9E1B371C71C718B10,
            0,
            p,
        )

        k_4_0 = FieldElement(
            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA8FB,
            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA8FB,
            p,
        )
        k_4_1 = FieldElement(
            0,
            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA9D3,
            p,
        )
        k_4_2 = FieldElement(
            0x12,
            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA99,
            p,
        )

        x_num = k_1_3 * (x_prime**3) + k_1_2 * (x_prime**2) + k_1_1 * x_prime + k_1_0
        x_den = x_prime**2 + k_2_1 * x_prime + k_2_0
        x = x_num / x_den  # can use inv as well

        # Calculate y numerator and denominator
        y_num = k_3_3 * (x_prime**3) + k_3_2 * (x_prime**2) + k_3_1 * x_prime + k_3_0
        y_den = x_prime**3 + k_4_2 * (x_prime**2) + k_4_1 * x_prime + k_4_0
        y = y_prime * (y_num / y_den)  # can u inv() as well

        # Verify the point is on the curve
        left = y * y
        right = x * x * x + FieldElement(4, 4, p)  # 4 * (1 + i)
        assert left == right, "Mapped point is not on the curve"
        return x, y


BLS12_381_G2_NU = CurveVariant(
    name="BLS12_381_G2_NU",
    curve=BLS12_381_G2Curve(e2c_variant=E2C_Variant.SSWU_NU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU_NU),
)

BLS12_381_G2_RO = CurveVariant(
    name="BLS12_381_G2_RO",
    curve=BLS12_381_G2Curve(e2c_variant=E2C_Variant.SSWU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU),
)
