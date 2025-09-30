from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Tuple
from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class Ed448Params:
    """
    Ed448 curve parameters (edwards448).

    The Ed448 curve is a high-security Twisted Edwards curve providing ~224-bit security.
    Defined in RFC 8032 and hash-to-curve parameters from RFC 9380.
    """
    # RFC 9380 compliant suite string and DST for edwards448_XOF:SHAKE256_ELL2_RO_
    SUITE_STRING = b"edwards448_XOF:SHAKE256_ELL2_RO_"
    DST = b"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_"

    # Curve parameters from RFC 8032
    PRIME_FIELD: Final[int] = 2 ** 448 - 2 ** 224 - 1
    ORDER: Final[int] = 2 ** 446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
    COFACTOR: Final[int] = 4

    # Generator point (x, y) - Valid Ed448 base point that satisfies the curve equation
    # This point is on the curve: x² + y² = 1 + (-39081)*x²*y² (mod p)
    # GENERATOR_X: Final[int] = (
    #     3
    # )
    # GENERATOR_Y: Final[int] = (
    #     608248142315725548579089613027470755631970544493249636720114649005312536082174920317165848102547021453544566006733948867319461398184873
    # )

    GENERATOR_X: Final[int] = (
        224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710
    )
    GENERATOR_Y: Final[int] = (
        298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
    )

    # Twisted Edwards parameters: ax² + y² = 1 + dx²y² (mod p)
    # From RFC 8032: Ed448 uses a = 1 and d = -39081
    EDWARDS_A: Final[int] = 1  # a = 1 for Ed448 (untwisted Edwards form)
    EDWARDS_D: Final[int] =  -39081  # d = -39081

    # Z parameter for Elligator 2 mapping (RFC 9380)
    Z: Final[int] = -1
    L: Final[int] = 84
    H_A: [Final] = "Shake-256"
    M: [Final] = 1
    K: [Final] = 224
    S_in_bytes: [Final] = None
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 64  # 512 bits for Ed448 (higher security)

    # Independent blinding base for Pedersen VRF
    # Generated using a deterministic method from a different seed point
    # These should be cryptographically independent from the generator
    BBx: Final[int] = (
        0x5f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05f
    )
    BBy: Final[int] = (
        0x793f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa16
    )


class Ed448Curve(TECurve):
    """
    Ed448 curve implementation.

    A high-security Twisted Edwards curve providing ~224-bit security.
    Defined in RFC 8032 with hash-to-curve support per RFC 9380.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> None:
        """Initialize Ed448 curve with RFC-compliant parameters."""
        # Default suite and dst
        SUITE_STRING = Ed448Params.SUITE_STRING
        DST = Ed448Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        if e2c_variant.value=="TryAndIncrement":
            SUITE_STRING= b"Ed25519_SHA-512_TAI" #as per davxy
            DST = b""+SUITE_STRING

        super().__init__(
            PRIME_FIELD=Ed448Params.PRIME_FIELD,
            ORDER=Ed448Params.ORDER,
            GENERATOR_X=Ed448Params.GENERATOR_X,
            GENERATOR_Y=Ed448Params.GENERATOR_Y,
            COFACTOR=Ed448Params.COFACTOR,
            glv=DisabledGLV,  # Ed448 doesn't use GLV
            Z=Ed448Params.Z,
            EdwardsA=Ed448Params.EDWARDS_A,
            EdwardsD=Ed448Params.EDWARDS_D,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Ed448Params.BBx,
            BBy=Ed448Params.BBy,
            L=Ed448Params.L,
            H_A=Ed448Params.H_A,
            M=Ed448Params.M,
            K=Ed448Params.K,
            S_in_bytes=Ed448Params.S_in_bytes,
            Requires_Isogeny=Ed448Params.Requires_Isogeny,
            Isogeny_Coeffs=Ed448Params.Isogeny_Coeffs
        )



    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for Ed448 VRF."""
        return Ed448Params.CHALLENGE_LENGTH

    def is_on_curve(self, x: int, y: int) -> bool:
        """
        Check if point (x, y) is on the Ed448 curve.

        Ed448 equation: x² + y² = 1 + d*x²*y² (mod p)
        where a = 1 (untwisted Edwards form)

        Args:
            x: x-coordinate
            y: y-coordinate

        Returns:
            bool: True if point is on curve
        """
        p = self.PRIME_FIELD
        d = Ed448Params.EDWARDS_D

        # Compute left side: x² + y²
        left = (x * x + y * y) % p

        # Compute right side: 1 + d*x²*y²
        right = (1 + d * x * x * y * y) % p

        return left == right

    @classmethod
    def calculate_j_k(cls) -> Tuple[int, int]:
        """
        Calculate curve parameters J and K for Elligator 2.

        Returns:
            Tuple[int, int]: J and K parameters
        """
        return (156326,1)  # As Curve448 is its equivalent MGC


# Singleton instance
Ed448_TE_Curve: Final[Ed448Curve] = Ed448Curve()

def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2_NU):
    # Create curve with the specified variant
    curve = Ed448Curve(e2c_variant)

    # Create and return a point class with this curve
    class Ed448PointVariant(Ed448Point):
        """Point on Ed448 with custom E2C variant"""
        def __init__(self, x: int, y: int) -> None:
            """Initialize a point with the variant curve."""
            # Call TEAffinePoint.__init__ directly to avoid Ed448Point's __init__
            TEAffinePoint.__init__(self, x, y, curve)

    # Set the curve as a class attribute
    Ed448PointVariant.curve = curve

    return Ed448PointVariant

@dataclass(frozen=True)
class Ed448Point(TEAffinePoint):
    """
    Point on the Ed448 curve.

    Implements point operations specific to the Ed448 curve
    with RFC 8032 and RFC 9380 compliance.
    """
    curve: Final[Ed448Curve] = Ed448_TE_Curve

    def __init__(self, x: int, y: int) -> None:
        """
        Initialize a point on the Ed448 curve.

        Args:
            x: x-coordinate
            y: y-coordinate

        Raises:
            ValueError: If point is not on curve
        """
        if not self.curve.is_on_curve(x, y):
            raise ValueError(f"Point ({x}, {y}) is not on Ed448 curve")
        super().__init__(x, y, self.curve)

    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the RFC 8032 standard generator point of the curve.

        Returns:
            Ed448Point: Standard Ed448 generator point
        """
        return cls(
            Ed448Params.GENERATOR_X,
            Ed448Params.GENERATOR_Y
        )

    @classmethod
    def identity(cls) -> Self:
        """
        Get the identity element (point at infinity).

        For Edwards curves: (0, 1) is the identity element.

        Returns:
            Ed448Point: Identity element
        """
        return cls(0, 1)

    @classmethod
    def blinding_base(cls) -> Self:
        """
        Get the blinding base point for VRF operations.

        This point is cryptographically independent from the generator
        for secure Pedersen VRF implementations.

        Returns:
            Ed448Point: Blinding base point
        """
        return cls(
            Ed448Params.BBx,
            Ed448Params.BBy
        )

    @classmethod
    def map_to_curve(cls, u: int):
        # Use a different mapping specifically for Ed25519
        s, t = cls.curve.map_to_curve_ell2(u)
        return cls.mont_to_ed448(s, t)


    @classmethod
    def mont_to_ed448(cls, u:int, v:int)->Self:
        """
        Convert a point (u, v) from Curve448 (Montgomery form)
        to Ed448 (Twisted Edwards form).

        Args:
            u (int): Montgomery u-coordinate (mod p)
            v (int): Montgomery v-coordinate (mod p)

        Returns:
            (x, y): Edwards coordinates as integers mod p
        """
        p=cls.curve.PRIME_FIELD

        # x numerator: 4 * v * (u^2 - 1)
        x_num = (4 * v * ((u * u - 1) % p)) % p

        # x denominator: u^4 - 2u^2 + 4v^2 + 1
        x_den = (pow(u, 4, p) - 2 * pow(u, 2, p) + 4 * pow(v, 2, p) + 1) % p

        x = (x_num * cls.curve.inv(x_den)) % p

        # y numerator: -(u^5 - 2u^3 - 4uv^2 + u)
        y_num = -(pow(u, 5, p) - 2 * pow(u, 3, p) - 4 * u * pow(v, 2, p) + u) % p

        # y denominator: u^5 - 2u^2v^2 - 2u^3 - 2v^2 + u
        y_den = (pow(u, 5, p) - 2 * pow(u, 2, p) * pow(v, 2, p) - 2 * pow(u, 3, p) - 2 * pow(v, 2, p) + u) % p

        y = (y_num * cls.curve.inv(y_den)) % p
        return cls(x, y)

    def encode_point(self) -> bytes:
        """
        Encode point according to RFC 8032 Ed448 encoding.
        Uses the base class point_to_string method with the curve's ENCODING_LENGTH.

        Returns:
            bytes: 57-byte encoded point
        """
        return super().point_to_string()

    def to_bytes(self) -> bytes:
        """
        Convert point to bytes using Ed448 encoding.
        Alias for encode_point() for compatibility with existing code.

        Returns:
            bytes: 57-byte encoded point
        """
        return self.encode_point()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        Create point from bytes using Ed448 decoding.
        Uses the base class string_to_point method.

        Args:
            data: 57-byte encoded point

        Returns:
            Ed448Point: Decoded point
        """
        return cls.string_to_point(data)

    @classmethod
    def decode_point(cls, data: bytes) -> Self:
        """
        Decode point according to RFC 8032 Ed448 encoding.
        Alias for from_bytes for compatibility with existing code.

        Args:
            data: 57-byte encoded point

        Returns:
            Ed448Point: Decoded point

        Raises:
            ValueError: If decoding fails
        """
        return cls.from_bytes(data)
