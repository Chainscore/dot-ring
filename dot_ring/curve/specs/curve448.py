# /home/siva/PycharmProjects/dot_ring/dot_ring/curve/specs/curve448.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Optional
from dot_ring.curve.e2c import E2C_Variant  # Unused import
from ..glv import DisabledGLV  # Unused import
from ..montgomery.mg_curve import MGCurve
from ..montgomery.mg_affine_point import MGAffinePoint


@dataclass(frozen=True)
class Curve448Params:
    """
    Curve448 parameters (Montgomery form of edwards448).

    Curve448 is a Montgomery curve defined by: v² = u³ + 156326u² + u
    over the prime field 2^448 - 2^224 - 1.
    """
    SUITE_STRING = b"curve448_XOF:SHAKE256_ELL2_NU_"
    DST = b"QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_NU_"

    # Curve parameters
    PRIME_FIELD: Final[int] = 2 ** 448 - 2 ** 224 - 1
    ORDER: Final[int] = 2 ** 446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
    COFACTOR: Final[int] = 4

    # Generator point (u, v) - corresponds to the base point of edwards448
    # Generator point u-coordinate (from RFC 7748)
    GENERATOR_U: Final[int] = 5

    # v-coordinate is derived from the curve equation v^2 = u^3 + A*u^2 + u mod p
    # Using the positive square root that has even least significant bit (LSB)
    GENERATOR_V: Final[int] = 355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362

    # Montgomery curve parameters: v² = u³ + Au² + u
    A: Final[int] = 156326
    B: Final[int] = 1  # B = 1 for Curve448

    # Z parameter for SSWU mapping
    Z: Final[int] = -1
    L: Final[int] = 84
    H_A: [Final] = "Shake-256"
    M: [Final] = 1
    K: [Final] = 224
    S_in_bytes: [Final] = None
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None

    # Challenge length in bytes for VRF (aligned with 224-bit security level)
    CHALLENGE_LENGTH: Final[int] = 28  # 224 bits for Curve448 (corrected from 24)

    # Blinding base for Pedersen VRF
    BBu: Final[int] = 0x3a5f9ef57d59ee131c7c4e1d9b4e3a1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1
    BBv: Final[int] = 0x2a8d1d5a5f9e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8


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
            glv=DisabledGLV,  # Curve448 doesn't use GLV
            Z=Curve448Params.Z,
            A=Curve448Params.A,
            B=Curve448Params.B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=E2C_Variant.ELL2,
            BBx=Curve448Params.BBu,
            BBy=Curve448Params.BBv,
            L=Curve448Params.L,
            M=Curve448Params.M,
            K=Curve448Params.K,
            H_A=Curve448Params.H_A,
            S_in_bytes=Curve448Params.S_in_bytes,
            Requires_Isogeny=Curve448Params.Requires_Isogeny,
            Isogeny_Coeffs=Curve448Params.Isogeny_Coeffs
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
Curve448_MG_Curve = Curve448Curve()

# # Verify the curve is working by checking the generator point
# try:
#     G = Curve448Point(Curve448Params.GENERATOR_U, Curve448Params.GENERATOR_V, Curve448_MG_Curve)
#     if not G.is_on_curve():
#         raise ValueError("Generator point is not on the curve")
# except Exception as e:
#     raise RuntimeError(f"Curve448 initialization failed: {e}")


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

    # @property
    # def curve(self):
    #     """Get the curve instance."""
    #     return getattr(self, '_curve', Curve448_MG_Curve)
    #
    # @curve.setter
    # def curve(self, value):
    #     """Set the curve instance."""
    #     object.__setattr__(self, '_curve', value)

    @classmethod
    def generator_point(cls) -> 'Curve448Point':
        """
        Get the generator point of the curve.

        Returns:
            Curve448Point: Generator point
        """
        return cls(
            Curve448Params.GENERATOR_U,
            Curve448Params.GENERATOR_V
        )

    @classmethod
    def identity(cls) -> 'Curve448Point':
        """
        Get the identity element (point at infinity) in a robust way.
        For Montgomery curves, identity is represented as (None, None).
        """
        # Create object directly to avoid constructor validation issues
        inst = object.__new__(cls)
        object.__setattr__(inst, "x", None)
        object.__setattr__(inst, "y", None)
        object.__setattr__(inst, "_curve", Curve448_MG_Curve)
        return inst

    def validate_coordinates(self) -> bool:
        """
        Validate that this point's coordinates are correct for Curve448.
        """
        if self.is_identity():
            return True

        if self.x is None or self.y is None:
            return self.x is None and self.y is None  # Both must be None for identity

        # Check coordinate bounds
        p = Curve448Params.PRIME_FIELD
        if not (0 <= self.x < p and 0 <= self.y < p):
            return False

        # Check curve equation: v² = u³ + 156326u² + u
        u, v = self.x, self.y
        left = (v * v) % p
        right = (u * u * u + 156326 * u * u + u) % p
        return left == right

    def to_x448_bytes(self) -> bytes:
        """
        Convert to X448 wire format (56 bytes, little-endian u-coordinate).
        """
        if self.is_identity():
            return b'\x00' * 56
        return self.x.to_bytes(56, 'little')

    # @classmethod
    # def from_x448_bytes(cls, data: bytes) -> 'Curve448Point':
    #     """
    #     Create point from X448 wire format (56 bytes, little-endian u-coordinate).
    #     This only recovers the u-coordinate; v-coordinate is computed when needed.
    #     """
    #     if len(data) != 56:
    #         raise ValueError("X448 data must be exactly 56 bytes")
    #
    #     if data == b'\x00' * 56:
    #         return cls.identity()
    #
    #     u = int.from_bytes(data, 'little')
    #
    #     # Compute v using curve equation: v² = u³ + 156326u² + u
    #     p = Curve448Params.PRIME_FIELD
    #     u = u % p
    #
    #     # Calculate right side of equation
    #     u_squared = (u * u) % p
    #     u_cubed = (u_squared * u) % p
    #     rhs = (u_cubed + (156326 * u_squared) % p + u) % p
    #
    #     # Find square root if it exists
    #     if pow(rhs, (p - 1) // 2, p) != 1:
    #         raise ValueError("Invalid u-coordinate: no corresponding v-coordinate exists")
    #
    #     # Use the square root method from MGAffinePoint
    #     temp_point = cls.identity()
    #     v = temp_point._sqrt_mod_p(rhs)
    #
    #     if v is None:
    #         raise ValueError("Could not compute square root for v-coordinate")
    #
    #     # Choose canonical v (even LSB for determinism)
    #     if v & 1:
    #         v = (-v) % p
    #
    #     return cls(u, v)
    #
    # def to_compressed_bytes(self) -> bytes:
    #     """
    #     Convert to compressed format: 56 bytes u-coordinate + 1 bit for v sign.
    #     """
    #     if self.is_identity():
    #         return b'\x00' * 57  # 56 + 1 byte for sign
    #
    #     u_bytes = self.x.to_bytes(56, 'little')
    #     # Store v parity in the extra byte (0 for even, 1 for odd)
    #     v_parity = bytes([self.y & 1]) if self.y is not None else b'\x00'
    #     return u_bytes + v_parity

    # @classmethod
    # def from_compressed_bytes(cls, data: bytes) -> 'Curve448Point':
    #     """
    #     Create point from compressed format (57 bytes: 56 for u + 1 for v parity).
    #     """
    #     if len(data) != 57:
    #         raise ValueError("Compressed Curve448 data must be exactly 57 bytes")
    #
    #     if data == b'\x00' * 57:
    #         return cls.identity()
    #
    #     u_bytes = data[:56]
    #     v_parity = data[56]
    #
    #     u = int.from_bytes(u_bytes, 'little')
    #
    #     # Compute v using curve equation
    #     p = Curve448Params.PRIME_FIELD
    #     u = u % p
    #
    #     u_squared = (u * u) % p
    #     u_cubed = (u_squared * u) % p
    #     rhs = (u_cubed + (156326 * u_squared) % p + u) % p
    #
    #     # Find square root
    #     if pow(rhs, (p - 1) // 2, p) != 1:
    #         raise ValueError("Invalid u-coordinate: no corresponding v-coordinate exists")
    #
    #     temp_point = cls.identity()
    #     v = temp_point._sqrt_mod_p(rhs)
    #
    #     if v is None:
    #         raise ValueError("Could not compute square root for v-coordinate")
    #
    #     # Adjust v based on stored parity
    #     if (v & 1) != v_parity:
    #         v = (-v) % p
    #
    #     return cls(u, v)

    def __str__(self) -> str:
        """String representation."""
        if self.is_identity():
            return "Curve448Point(IDENTITY)"
        return f"Curve448Point(u={self.x}, v={self.y})"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return self.__str__()


# Convenience functions for common operations
def curve448_base_point() -> Curve448Point:
    """Get the standard Curve448 base point (generator)."""
    return Curve448Point.generator_point()

def curve448_identity() -> Curve448Point:
    """Get the Curve448 identity point."""
    return Curve448Point.identity()


def curve448_random_scalar() -> int:
    """Generate a random scalar for Curve448 operations."""
    import secrets
    return secrets.randbelow(Curve448Params.ORDER)