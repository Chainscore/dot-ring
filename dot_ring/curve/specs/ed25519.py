from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Tuple, Union

from dot_ring.curve.e2c import E2C_Variant

from ..glv import DisabledGLV
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class Ed25519Params:
    """
    JubJub curve parameters.

    Specification of the JubJub curve in Twisted Edwards form.
    """
    SUITE_STRING = b"edwards25519_XMD:SHA-512_ELL2_RO_"
    DST = b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"

    # Curve parameters
    PRIME_FIELD: Final[int] = 2**255 - 19
    ORDER: Final[int] = 2 **252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    COFACTOR: Final[int] = 8
    # Generator point
    GENERATOR_X: Final[int] = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    GENERATOR_Y: Final[int] = 0x6666666666666666666666666666666666666666666666666666666666666658
    # Edwards curve parameters
    EDWARDS_A: Final[int] = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec
    EDWARDS_D: Final[int] = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3

    GLV_LAMBDA: Final[int] = 0
    GLV_B: Final[int] = 0
    GLV_C: Final[int] = 0

    # Z parameter for Elligator 2 mapping (from RFC 9380 Section 4.1)
    Z: Final[int] = 2  # Curve25519 uses Z = 2 for Elligator 2 mapping
    L: Final[int] = 48
    H_A: [Final] = "SHA-512"
    M: [Final] = 1
    K: [Final] = 128
    S_in_bytes: [Final] = 128  # 48 64 136 172\
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits

    BBx: Final[
        int
    ] = 52417091031015867055192825304177001039906336859819158874861527659737645967040
    BBy: Final[
        int
    ] = 24364467899048426341436922427697710961180476432856951893648702734568269272170

    UNCOMPRESSED=False

class Ed25519Curve(TECurve):
    """
    Bandersnatch curve implementation.

    A high-performance curve designed for zero-knowledge proofs and VRFs,
    offering both efficiency and security.
    """


    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for Ed25519 VRF."""
        return Ed25519Params.CHALLENGE_LENGTH

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> None:
        """Initialize Ed25519 curve with RFC-compliant parameters."""
        # Default suite and dst
        SUITE_STRING = Ed25519Params.SUITE_STRING
        DST= Ed25519Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")
        if e2c_variant.value=="TryAndIncrement":
            SUITE_STRING= b"Ed25519_SHA-512_TAI" #as per davxy
            DST = b""
        super().__init__(
            PRIME_FIELD=Ed25519Params.PRIME_FIELD,
            ORDER=Ed25519Params.ORDER,
            GENERATOR_X=Ed25519Params.GENERATOR_X,
            GENERATOR_Y=Ed25519Params.GENERATOR_Y,
            COFACTOR=Ed25519Params.COFACTOR,
            glv=DisabledGLV,
            Z=Ed25519Params.Z,
            EdwardsA=Ed25519Params.EDWARDS_A,
            EdwardsD=Ed25519Params.EDWARDS_D,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Ed25519Params.BBx,
            BBy=Ed25519Params.BBy,
            L=Ed25519Params.L,
            H_A=Ed25519Params.H_A,
            M=Ed25519Params.M,
            K=Ed25519Params.K,
            S_in_bytes=Ed25519Params.S_in_bytes,
            Requires_Isogeny=Ed25519Params.Requires_Isogeny,
            Isogeny_Coeffs=Ed25519Params.Isogeny_Coeffs,
            UNCOMPRESSED=Ed25519Params.UNCOMPRESSED
        )
        print("SUITE STRING:", self.SUITE_STRING)

    def modular_sqrt(self, a: int, p: int) -> int:
        """
        Tonelli-Shanks algorithm for finding modular square roots.

        Args:
            a: The number to find the square root of
            p: The prime modulus

        Returns:
            int: The square root of 'a' modulo 'p', or 0 if no square root exists
        """
        # Handle simple cases
        a = a % p
        if a == 0:
            return 0
        if p == 2:
            return a

        # Check if a is a quadratic residue
        if pow(a, (p - 1) // 2, p) != 1:
            return 0

        # Find Q and S such that p-1 = Q * 2^S
        Q = p - 1
        S = 0
        while Q % 2 == 0:
            Q //= 2
            S += 1

        # Find a quadratic non-residue z
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1

        # Initialize variables
        c = pow(z, Q, p)
        x = pow(a, (Q + 1) // 2, p)
        t = pow(a, Q, p)
        m = S

        # Main loop
        while t != 1:
            # Find the least i such that t^(2^i) ≡ 1 mod p
            i, temp = 0, t
            while temp != 1 and i < m:
                temp = (temp * temp) % p
                i += 1

            if i == m:
                return 0  # No solution

            # Update variables
            b = pow(c, 1 << (m - i - 1), p)
            x = (x * b) % p
            t = (t * b * b) % p
            c = (b * b) % p
            m = i

        return x

    @classmethod
    def calculate_j_k(cls) -> Tuple[int, int]:
        """
        Calculate curve parameters J and K for Elligator 2.

        Returns:
            Tuple[int, int]: J and K parameters
        """
        return (486662, 1) #As Curve25519 is its equivalent MGC


# Singleton instance
Ed25519_TE_Curve: Final[Ed25519Curve] = Ed25519Curve()

def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2_NU):
    # Create curve with the specified variant
    curve = Ed25519Curve(e2c_variant)
    print("Hey am i called?")
    # Create and return a point class with this curve
    class Ed25519PointVariant(Ed25519Point):
        """Point on Ed25519 with custom E2C variant"""
        def __init__(self, x: int, y: int) -> None:
            """Initialize a point with the variant curve."""
            # Call TEAffinePoint.__init__ directly to avoid Ed25519Point's __init__
            TEAffinePoint.__init__(self, x, y, curve)

    # Set the curve as a class attribute
    Ed25519PointVariant.curve = curve

    return Ed25519PointVariant

@dataclass(frozen=True)
class Ed25519Point(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """
    curve: Final[Ed25519Curve] = Ed25519_TE_Curve

    @classmethod
    def identity_point(cls) -> 'Ed25519Point':
        """
        Get the identity point (0, 1) of the curve.

        Returns:
            Ed25519Point: Identity point
        """
        # The identity point in Twisted Edwards coordinates is (0, 1)
        return cls(0, 1)

    def __init__(self, x: int, y: int) -> None:
        """
        Initialize a point on the Bandersnatch curve.

        Args:
            x: x-coordinate
            y: y-coordinate

        Raises:
            ValueError: If point is not on curve
        """
        super().__init__(x, y, self.curve)

    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the generator point of the curve.

        Returns:
            BandersnatchPoint: Generator point
        """
        return cls(
            Ed25519Params.GENERATOR_X,
            Ed25519Params.GENERATOR_Y
        )

    @classmethod
    def map_to_curve(cls, u: int):
        # Use a different mapping specifically for Ed25519
        s, t = cls.curve.map_to_curve_ell2(u)
        return cls.mont_to_ed25519(s, t)

    @classmethod
    def mont_to_ed25519(cls, u: int, v: int) -> Self:
        """
        Convert a point (u, v) from Montgomery form to Edwards form (x, y).
        Returns (x, y).
        """
        p = cls.curve.PRIME_FIELD
        # Precompute sqrt(-486664) mod p
        sqrt_neg_A_minus_2 = cls.curve.mod_sqrt(-486664 % p)
        # y = (u - 1) / (u + 1) mod p
        y = ((u - 1) * pow(u + 1, -1, p)) % p
        # x = sqrt(-486664) * u / v mod p
        x = (sqrt_neg_A_minus_2 * u * pow(v, -1, p)) % p
        return cls(x, y)