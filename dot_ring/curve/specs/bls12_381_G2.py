from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Tuple, Optional, Any

from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..short_weierstrass.sw_curve import SWCurve
from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..field_element import FieldElement

Fp2 = Tuple[int, int]
from py_ecc.bls12_381 import add, FQ2, multiply

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
    PRIME_FIELD: Final[
        int] = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

    # Subgroup order (r)
    ORDER: Final[int] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

    # Cofactor (h)
    COFACTOR: Final[
        int] =  0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551#0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5

    # Generator point (G2)
    GENERATOR_X: Final[Fp2] = (
        0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
    )
    GENERATOR_Y: Final[Fp2] = (
        0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801,
        0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
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
    H_A: Final[str] = "SHA-256"  # Hash function

    # VRF parameters
    CHALLENGE_LENGTH: Final[int] = 32  # 256-bit challenge

    # Isogeny parameters
    Requires_Isogeny: Final[bool] = True
    Isogeny_Coeffs = None

    # Blinding base for Pedersen VRF (not used in basic implementation)
    BBx: Final[Fp2] = None
    BBy: Final[Fp2] = None


class BLS12_381_G2Curve(SWCurve):
    """
    BLS12-381 G2 curve implementation.

    This curve is defined over a quadratic extension field Fp2 and is primarily
    used for cryptographic pairings in the BLS signature scheme.
    """

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for VRF."""
        return BLS12_381_G2Params.CHALLENGE_LENGTH

    def identity(self) -> BLS12_381_G2Point:
        """
        Return the point at infinity (identity element) for this curve.
        
        Returns:
            BLS12_381_G2Point: The identity point (point at infinity)
        """
        # Create a point with (0, 0) coordinates and set _is_identity to True
        # Using object.__setattr__ to work with frozen dataclass
        point = BLS12_381_G2Point((0, 0), (0, 0))
        object.__setattr__(point, '_is_identity', True)
        return point

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
            glv=DisabledGLV,  # No efficient GLV for this curve
            Z=BLS12_381_G2Params.Z,
            WeierstrassA=BLS12_381_G2Params.WEIERSTRASS_A,
            WeierstrassB=BLS12_381_G2Params.WEIERSTRASS_B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=E2C_Variant.SSWU,
            BBx=BLS12_381_G2Params.BBx,
            BBy=BLS12_381_G2Params.BBy,
            M=BLS12_381_G2Params.M,
            K=BLS12_381_G2Params.K,
            L=BLS12_381_G2Params.L,
            S_in_bytes=BLS12_381_G2Params.S_in_bytes,
            H_A=BLS12_381_G2Params.H_A,
            Requires_Isogeny=BLS12_381_G2Params.Requires_Isogeny,
            Isogeny_Coeffs=BLS12_381_G2Params.Isogeny_Coeffs,
        )


# Singleton instance
BLS12_381_G2: Final[BLS12_381_G2Curve] = BLS12_381_G2Curve()


@dataclass(frozen=True)
class BLS12_381_G2Point(SWAffinePoint):
    """
    Point on the BLS12-381 G2 curve.

    Implements point operations specific to the BLS12-381 G2 curve.
    """
    curve: Final[BLS12_381_G2Curve] = BLS12_381_G2

    def __init__(self, x: Fp2, y: Fp2) -> None:
        """
        Initialize a point on the BLS12-381 G2 curve.

        Args:
            x: x-coordinate as an element of Fp2
            y: y-coordinate as an element of Fp2

        Raises:
            ValueError: If point is not on the curve
        """
        super().__init__(x, y, self.curve)


    def __add__(self, other: BLS12_381_G2Point) -> BLS12_381_G2Point:
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

        # Convert points to FQ2 format for py_ecc
        p1 = (FQ2([self.x.re, self.x.im]), FQ2([self.y.re, self.y.im]))
        p2 = (FQ2([other.x.re, other.x.im]), FQ2([other.y.re, other.y.im]))

        # Perform addition using py_ecc
        result = add(p1, p2)

        # Convert back to tuple format
        x = (int(result[0].coeffs[0]), int(result[0].coeffs[1]))
        y = (int(result[1].coeffs[0]), int(result[1].coeffs[1]))

        return self.__class__(x, y)

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
            p = (FQ2([self.x[0], self.x[1]]), FQ2([self.y[0], self.y[1]]))

        except Exception as e:
            p = (FQ2([self.x.re, self.x.im]), FQ2([self.y.re, self.y.im]))


        # Perform scalar multiplication using py_ecc
        result = multiply(p, scalar)

        # Convert back to tuple format
        x = (int(result[0].coeffs[0]), int(result[0].coeffs[1]))
        y = (int(result[1].coeffs[0]), int(result[1].coeffs[1]))

        return self.__class__(x, y)


    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the generator point of the curve.

        Returns:
            BLS12_381_G2Point: Generator point
        """
        return cls(
            BLS12_381_G2Params.GENERATOR_X,
            BLS12_381_G2Params.GENERATOR_Y
        )

    @classmethod
    def sswu_hash2_curve_ro(cls, alpha_string: bytes, salt: bytes = b"", General_Check: bool = False) -> dict|Self:
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
        return R

    @classmethod
    def sswu_hash2_curve_nu(cls, alpha_string: bytes, salt: bytes = b"",
                            General_Check: bool = False) -> SWAffinePoint | Any:
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

        # Map to curve
        print("q0 is:",q0)
        R =q0*cls.curve.COFACTOR
        if General_Check:
            return {"u": u, "Q0": q0, "R": R}

        return R

    @classmethod
    def map_to_curve_simple_swu(cls, u: FieldElement) -> 'BLS12_381_G2Point':
        """
        Simplified SWU map with 3-isogeny for BLS12-381 G2
        Combines SSWU map and 3-isogeny map in one function
        """
        # 1. Map to the isogenous curve E'
        point_on_e_prime = cls._sswu_map_to_e_prime(u)

        # 2. Apply 3-isogeny map from E' to E
        x, y = cls._apply_3_isogeny(point_on_e_prime)

        # 3. Wrap into a BLS12_381_G2Point object
        point = cls(x, y)
        if not point.is_on_curve():
            print("ERROR: Point is not on the curve after mapping!")
            # Print curve equation and point for debugging
            left = y * y
            right = x * x * x + FieldElement(4, 4, x.p)  # 4 * (1 + i)
            assert left==right, 'point is not on the curve'
            raise ValueError("Mapped point is not on the curve")
        return point

    @staticmethod
    def _sgn0(x):
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
        def sgn0_fp(a):
            return a % 2
            
        if x0 != 0:
            return sgn0_fp(x0)
        return sgn0_fp(x1)

    @classmethod
    def _sswu_map_to_e_prime(cls, u):

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

        gx1 = x1 ** 3 + A_prime * x1 + B_prime

        if gx1.is_square():
            y1 = gx1.sqrt()
            left = y1 * y1
            right = x1 * x1 * x1 + A_prime * x1 + B_prime
            assert left==right, "Invalid point on E'"
            x, y = x1, y1
        else:
            x2 = Z * u_sq * x1
            gx2 = x2 ** 3 + A_prime * x2 + B_prime
            y2 = gx2.sqrt()
            left = y2 * y2
            right = x2 * x2 * x2 + A_prime * x2 + B_prime
            assert left == right, "Invalid point on E'"
            x, y = x2, y2

        # Step 9: Ensure sgn0(u) == sgn0(y)
        if cls._sgn0(u) != cls._sgn0(y):
            y = -y
        return x, y

    @classmethod
    def _apply_3_isogeny(cls, point):
        x_prime, y_prime = point
        p = cls.curve.PRIME_FIELD

        # Constants from RFC 9380
        k_1_0 = FieldElement(
            0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6,
            0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6,
            p
        )
        k_1_1 = FieldElement(
            0,
            0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a,
            p
        )
        k_1_2 = FieldElement(
            0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e,
            0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d,
            p
        )
        k_1_3 = FieldElement(
            0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1,
            0,
            p
        )

        k_2_0 = FieldElement(
            0,
            0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63,
            p
        )
        k_2_1 = FieldElement(
            0xc,
            0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f,
            p
        )

        k_3_0 = FieldElement(
            0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706,
            0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706,
            p
        )
        k_3_1 = FieldElement(
            0,
            0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be,
            p
        )
        k_3_2 = FieldElement(
            0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c,
            0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f,
            p
        )
        k_3_3 = FieldElement(
            0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10,
            0,
            p
        )

        k_4_0 = FieldElement(
            0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb,
            0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb,
            p
        )
        k_4_1 = FieldElement(
            0,
            0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3,
            p
        )
        k_4_2 = FieldElement(
            0x12,
            0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99,
            p
        )

        x_num = k_1_3 * (x_prime ** 3) + k_1_2 * (x_prime ** 2) + k_1_1 * x_prime + k_1_0
        x_den = x_prime ** 2 + k_2_1 * x_prime + k_2_0
        x = x_num / x_den # can use inv as well

        # Calculate y numerator and denominator
        y_num = k_3_3 * (x_prime ** 3) + k_3_2 * (x_prime ** 2) + k_3_1 * x_prime + k_3_0
        y_den = x_prime ** 3 + k_4_2 * (x_prime ** 2) + k_4_1 * x_prime + k_4_0
        y = y_prime *(y_num/ y_den) #can u inv() as well

        # Verify the point is on the curve
        left = y * y
        right = x * x * x + FieldElement(4, 4, p)  # 4 * (1 + i)
        assert left == right, "Mapped point is not on the curve"
        return x, y