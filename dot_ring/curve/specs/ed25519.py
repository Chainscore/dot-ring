from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

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
    SUITE_STRING = b"Ed25519_SHA-512_TAI"  # b"\x03"
    DST = b""

    # Curve parameters
    PRIME_FIELD: Final[int] = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    ORDER: Final[int] = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
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

    # Z
    Z: Final[int] = 1

    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits

    # Blinding Base For Pedersen
    BBx: Final[
        int
    ] = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    BBy: Final[
        int
    ] = 0x6666666666666666666666666666666666666666666666666666666666666658


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

    def __init__(self) -> None:
        """Initialize Bandersnatch curve with its parameters."""
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
            SUITE_STRING=Ed25519Params.SUITE_STRING,
            DST=Ed25519Params.DST,
            E2C=E2C_Variant.TAI,
            BBx=Ed25519Params.BBx,
            BBy=Ed25519Params.BBy
        )

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


# Singleton instance
Ed25519_TE_Curve: Final[Ed25519Curve] = Ed25519Curve()


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