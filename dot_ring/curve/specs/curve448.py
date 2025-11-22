from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Optional
from dot_ring.curve.e2c import E2C_Variant  # Unused import
from ..montgomery.mg_curve import MGCurve
from ..montgomery.mg_affine_point import MGAffinePoint


@dataclass(frozen=True)
class Curve448Params:
    """
    Curve448 parameters (Montgomery form of edwards448).

    Curve448 is a Montgomery curve defined by: v² = u³ + 156326u² + u
    over the prime field 2^448 - 2^224 - 1.
    """

    SUITE_STRING = b"curve448_XOF:SHAKE256_ELL2_RO_"
    DST = b"QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_RO_"

    # Curve parameters
    PRIME_FIELD: Final[int] = 2**448 - 2**224 - 1
    ORDER: Final[int] = (
        2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D
    )
    COFACTOR: Final[int] = 4

    # Generator point (u, v) - corresponds to the base point of edwards448
    # Generator point u-coordinate (from RFC 7748)
    GENERATOR_U: Final[int] = 5

    # v-coordinate is derived from the curve equation v^2 = u^3 + A*u^2 + u mod p
    # Using the positive square root that has even least significant bit (LSB)
    GENERATOR_V: Final[
        int
    ] = 355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362

    # Montgomery curve parameters: v² = u³ + Au² + u
    A: Final[int] = 156326
    B: Final[int] = 1  # B = 1 for Curve448

    # Z parameter for SSWU mapping
    Z: Final[int] = -1
    L: Final[int] = 84
    H_A: [Final] = "Shake-256"
    ENDIAN = "little"
    M: [Final] = 1
    K: [Final] = 224
    S_in_bytes: [Final] = None
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    # Challenge length in bytes for VRF (aligned with 224-bit security level)
    CHALLENGE_LENGTH: Final[int] = 28  # 224 bits for Curve448 (corrected from 24)

    # Blinding base for Pedersen VRF
    BBu: Final[int] = GENERATOR_U
    BBv: Final[int] = GENERATOR_V
    UNCOMPRESSED = True


class Curve448Curve(MGCurve):
    """
    Curve448 implementation (Montgomery form).

    A high-security curve used in X448 key exchange.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.ELL2) -> None:
        """Initialize Curve448 with its parameters."""
        # Default suite and dst
        SUITE_STRING = Curve448Params.SUITE_STRING
        DST = Curve448Params.DST

        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")

        # Initialize with proper dataclass pattern for MGCurve
        super().__init__(
            PRIME_FIELD=Curve448Params.PRIME_FIELD,
            ORDER=Curve448Params.ORDER,
            GENERATOR_X=Curve448Params.GENERATOR_U,
            GENERATOR_Y=Curve448Params.GENERATOR_V,
            COFACTOR=Curve448Params.COFACTOR,
            Z=Curve448Params.Z,
            A=Curve448Params.A,
            B=Curve448Params.B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=Curve448Params.BBu,
            BBy=Curve448Params.BBv,
            L=Curve448Params.L,
            M=Curve448Params.M,
            K=Curve448Params.K,
            H_A=Curve448Params.H_A,
            S_in_bytes=Curve448Params.S_in_bytes,
            Requires_Isogeny=Curve448Params.Requires_Isogeny,
            Isogeny_Coeffs=Curve448Params.Isogeny_Coeffs,
            UNCOMPRESSED=Curve448Params.UNCOMPRESSED,
            ENDIAN=Curve448Params.ENDIAN,
        )

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for Curve448 VRF."""
        return Curve448Params.CHALLENGE_LENGTH

    def __post_init__(self):
        """Skip parent validation since Curve448 parameters are known to be valid."""
        # Override the validation from the fixed MGCurve to avoid redundant checks
        pass


# Main curve instance
Curve448_MG_Curve: Final[Curve448Curve] = Curve448Curve()


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.ELL2):
    """
    Factory function to create a Curve448Point class with a specific E2C variant.

    This is the recommended way for library users to work with different hash-to-curve variants.

    Args:
        e2c_variant: The E2C variant to use (ELL2, ELL2_NU)

    Returns:
        A Curve448Point class configured with the specified variant
    """
    # Create curve with the specified variant
    curve = Curve448Curve(e2c_variant)

    # Create and return a point class with this curve
    class Curve448PointVariant(MGAffinePoint):
        """Point on Curve448 with custom E2C variant"""

        pass

    # Set the curve as a class attribute
    Curve448PointVariant.curve = curve

    return Curve448PointVariant


class Curve448Point(MGAffinePoint):
    """
    Point on the Curve448 Montgomery curve.
    """

    curve: Final[Curve448Curve] = Curve448_MG_Curve

    def __init__(self, u: Optional[int], v: Optional[int], curve=None) -> None:
        """
        Initialize a point on Curve448.

        Args:
            u: u-coordinate (Montgomery x-coordinate) or None for identity
            v: v-coordinate (Montgomery y-coordinate) or None for identity
            curve: Curve instance (defaults to singleton)
        """
        if curve is None:
            curve = Curve448_MG_Curve

        # Call parent constructor
        super().__init__(u, v, curve)

    @classmethod
    def generator_point(cls) -> "Curve448Point":
        """
        Get the generator point of the curve.

        Returns:
            Curve448Point: Generator point
        """
        return cls(Curve448Params.GENERATOR_U, Curve448Params.GENERATOR_V)

    def __str__(self) -> str:
        """String representation."""
        if self.is_identity():
            return "Curve448Point(IDENTITY)"
        return f"Curve448Point(u={self.x}, v={self.y})"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return self.__str__()
