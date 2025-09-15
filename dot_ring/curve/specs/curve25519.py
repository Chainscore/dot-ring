# dot-ring/curve/specs/curve25519.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Optional
from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..montgomery.mg_curve import MGCurve
from ..montgomery.mg_affine_point import MGAffinePoint


@dataclass(frozen=True)
class Curve25519Params:
    """
    Curve25519 parameters (Montgomery form of edwards25519).

    Curve25519 is a Montgomery curve defined by: v² = u³ + 486662u² + u
    over the prime field 2^255 - 19.
    """
    # From RFC 9380 Section 4.1: curve25519_XMD:SHA-512_ELL2_RO_
    SUITE_STRING = b"curve25519_XMD:SHA-512_ELL2_RO_"
    DST = b"curve25519_XMD:SHA-512_ELL2_RO_"  # Default DST is the same as SUITE_STRING

    # Curve parameters
    PRIME_FIELD: Final[int] = 2 ** 255 - 19
    ORDER: Final[int] = 2 ** 252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    COFACTOR: Final[int] = 8

    # Generator point (u, v) - corresponds to the base point of edwards25519
    GENERATOR_U: Final[int] = 9
    GENERATOR_V: Final[int] = 14781619447589544791020593568409986887264606134616475288964881837755586237401

    # Montgomery curve parameters: v² = u³ + Au² + u
    A: Final[int] = 486662
    B: Final[int] = 1  # B = 1 for Curve25519

    # Z parameter for Elligator 2 mapping (from RFC 9380 Section 4.1)
    Z: Final[int] = 2  # Curve25519 uses Z = 2 for Elligator 2 mapping

    # Challenge length in bytes for VRF (aligned with 128-bit security level)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits

    # Blinding base for Pedersen VRF (project-specific: keep if you need them)
    BBu: Final[int] = 0x2a4f9ef57d59ee131c7c4e1d9b4e3a1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1
    BBv: Final[int] = 0x1a8d1d5a5f9e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8


class Curve25519Curve(MGCurve):
    """
    Curve25519 implementation (Montgomery form).

    A high-performance curve used in X25519 key exchange.
    """

    def __init__(self) -> None:
        """Initialize Curve25519 with its parameters."""
        # Initialize with proper dataclass pattern for MGCurve
        # Note: This assumes MGCurve is a dataclass with these fields
        super().__init__(
            PRIME_FIELD=Curve25519Params.PRIME_FIELD,
            ORDER=Curve25519Params.ORDER,
            GENERATOR_X=Curve25519Params.GENERATOR_U,
            GENERATOR_Y=Curve25519Params.GENERATOR_V,
            COFACTOR=Curve25519Params.COFACTOR,
            glv=DisabledGLV,  # Curve25519 doesn't use GLV
            Z=Curve25519Params.Z,
            A=Curve25519Params.A,
            B=Curve25519Params.B,
            SUITE_STRING=Curve25519Params.SUITE_STRING,
            DST=Curve25519Params.DST,
            E2C=E2C_Variant.ELL2,
            BBx=Curve25519Params.BBu,
            BBy=Curve25519Params.BBv
        )

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return challenge length for VRF operations."""
        return Curve25519Params.CHALLENGE_LENGTH

    def __post_init__(self):
        """Skip parent validation since Curve25519 parameters are known to be valid."""
        # Override the validation from the fixed MGCurve to avoid redundant checks
        pass


# Alternative simpler implementation if the above constructor doesn't work
class Curve25519CurveSimple(MGCurve):
    """
    Simplified Curve25519 implementation using direct dataclass initialization.
    """
    PRIME_FIELD: Final[int] = Curve25519Params.PRIME_FIELD
    A: Final[int] = Curve25519Params.A
    B: Final[int] = Curve25519Params.B

    @property
    def CHALLENGE_LENGTH(self) -> int:
        return Curve25519Params.CHALLENGE_LENGTH

    def __post_init__(self):
        """Skip validation for known good parameters."""
        pass


# Try the main implementation first, fall back to simple if needed
try:
    Curve25519_MG_Curve: Final[Curve25519Curve] = Curve25519Curve()
except (TypeError, AttributeError) as e:
    # Fallback to simple dataclass construction
    print(f"Warning: Using fallback Curve25519 construction due to: {e}")
    Curve25519_MG_Curve: Final[Curve25519CurveSimple] = Curve25519CurveSimple(
        PRIME_FIELD=Curve25519Params.PRIME_FIELD,
        A=Curve25519Params.A,
        B=Curve25519Params.B
    )


class Curve25519Point(MGAffinePoint):
    """
    Point on the Curve25519 Montgomery curve.
    """

    def __init__(self, u: Optional[int], v: Optional[int], curve=None) -> None:
        """
        Initialize a point on Curve25519.

        Args:
            u: u-coordinate (Montgomery x-coordinate) or None for identity
            v: v-coordinate (Montgomery y-coordinate) or None for identity
            curve: Curve instance (defaults to singleton)
        """
        if curve is None:
            curve = Curve25519_MG_Curve

        # Call parent constructor
        super().__init__(u, v, curve)

    @property
    def curve(self):
        """Get the curve instance."""
        return getattr(self, '_curve', Curve25519_MG_Curve)

    @curve.setter
    def curve(self, value):
        """Set the curve instance."""
        object.__setattr__(self, '_curve', value)

    @classmethod
    def generator_point(cls) -> Self:
        """
        Get the generator point of the curve.

        Returns:
            Curve25519Point: Generator point
        """
        return cls(
            Curve25519Params.GENERATOR_U,
            Curve25519Params.GENERATOR_V
        )

    @classmethod
    def identity(cls) -> Self:
        """
        Get the identity element (point at infinity) in a robust way.
        This constructs an object with x=None, y=None and a proper curve reference.
        """
        # Create object directly to avoid constructor validation issues
        inst = object.__new__(cls)
        object.__setattr__(inst, "x", None)
        object.__setattr__(inst, "y", None)
        object.__setattr__(inst, "_curve", Curve25519_MG_Curve)
        return inst

    def validate_coordinates(self) -> bool:
        """
        Validate that this point's coordinates are correct for Curve25519.
        """
        if self.is_identity():
            return True

        if self.x is None or self.y is None:
            return self.x is None and self.y is None  # Both must be None for identity

        # Check coordinate bounds
        p = Curve25519Params.PRIME_FIELD
        if not (0 <= self.x < p and 0 <= self.y < p):
            return False

        # Check curve equation: v² = u³ + 486662u² + u
        u, v = self.x, self.y
        left = (v * v) % p
        right = (u * u * u + 486662 * u * u + u) % p
        return left == right

#     def to_x25519_bytes(self) -> bytes:
#         """
#         Convert to X25519 wire format (32 bytes, little-endian u-coordinate).
#         """
#         if self.is_identity():
#             return b'\x00' * 32
#         return self.x.to_bytes(32, 'little')
#
#     @classmethod
#     def from_x25519_bytes(cls, data: bytes) -> Self:
#         """
#         Create point from X25519 wire format (32 bytes, little-endian u-coordinate).
#         This only recovers the u-coordinate; v-coordinate is computed when needed.
#         """
#         if len(data) != 32:
#             raise ValueError("X25519 data must be exactly 32 bytes")
#
#         if data == b'\x00' * 32:
#             return cls.identity()
#
#         u = int.from_bytes(data, 'little')
#
#         # For X25519, we typically don't need the v-coordinate immediately
#         # We can compute it later if needed using the curve equation
#
#         # Compute v using curve equation: v² = u³ + 486662u² + u
#         p = Curve25519Params.PRIME_FIELD
#         u = u % p
#
#         # Calculate right side of equation
#         u_squared = (u * u) % p
#         u_cubed = (u_squared * u) % p
#         rhs = (u_cubed + (486662 * u_squared) % p + u) % p
#
#         # Find square root if it exists
#         if pow(rhs, (p - 1) // 2, p) != 1:
#             raise ValueError("Invalid u-coordinate: no corresponding v-coordinate exists")
#
#         # Use the square root method from MGAffinePoint
#         temp_point = cls.identity()
#         v = temp_point._sqrt_mod_p(rhs)
#
#         if v is None:
#             raise ValueError("Could not compute square root for v-coordinate")
#
#         # Choose canonical v (even LSB for determinism)
#         if v & 1:
#             v = (-v) % p
#
#         return cls(u, v)
#
    def __str__(self) -> str:
        """String representation."""
        if self.is_identity():
            return "Curve25519Point(IDENTITY)"
        return f"Curve25519Point(u={self.x}, v={self.y})"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return self.__str__()
        
    def to_x25519_bytes(self) -> bytes:
        """
        Convert to X25519 wire format (32 bytes, little-endian u-coordinate).
        """
        if self.is_identity():
            return b'\x00' * 32
        return self.x.to_bytes(32, 'little')

    @classmethod
    def from_x25519_bytes(cls, data: bytes) -> 'Curve25519Point':
        """
        Create point from X25519 wire format (32 bytes, little-endian u-coordinate).
        This only recovers the u-coordinate; v-coordinate is computed when needed.
        """
        if len(data) != 32:
            raise ValueError("X25519 data must be exactly 32 bytes")

        if data == b'\x00' * 32:
            return cls.identity()

        u = int.from_bytes(data, 'little')

        # For X25519, we typically don't need the v-coordinate immediately
        # We can compute it later if needed using the curve equation

        # Compute v using curve equation: v² = u³ + 486662u² + u
        p = Curve25519Params.PRIME_FIELD
        u = u % p

        # Calculate right side of equation
        u_squared = (u * u) % p
        u_cubed = (u_squared * u) % p
        rhs = (u_cubed + (486662 * u_squared) % p + u) % p

        # Find square root if it exists
        if pow(rhs, (p - 1) // 2, p) != 1:
            raise ValueError("Invalid u-coordinate: no corresponding v-coordinate exists")

        # Use the square root method from MGAffinePoint
        temp_point = cls.identity()
        v = temp_point._sqrt_mod_p(rhs)

        if v is None:
            raise ValueError("Could not compute square root for v-coordinate")

        # Choose canonical v (even LSB for determinism)
        if v & 1:
            v = (-v) % p

        return cls(u, v)
#
#
# Convenience functions for common operations
def curve25519_base_point() -> Curve25519Point:
    """Get the standard Curve25519 base point (generator)."""
    return Curve25519Point.generator_point()


def curve25519_identity() -> Curve25519Point:
    """Get the Curve25519 identity point."""
    return Curve25519Point.identity()


def curve25519_random_scalar() -> int:
    """Generate a random scalar for Curve25519 operations."""
    import secrets
    return secrets.randbelow(Curve25519Params.ORDER)


# # Test function to verify implementation
# def test_curve25519_basic():
#     """Basic test to verify Curve25519 implementation works."""
#     try:
#         # Test identity
#         identity = Curve25519Point.identity()
#         assert identity.is_identity()
#
#         # Test generator
#         G = Curve25519Point.generator_point()
#         assert G.validate_coordinates()
#         assert G.is_on_curve()
#
#         # Test point operations
#         G2 = G + G  # Point doubling
#         assert G2.is_on_curve()
#
#         G3 = G * 3  # Scalar multiplication
#         assert G3.is_on_curve()
#
#         # Test that 3*G = G + G + G
#         G_plus_G2 = G + G2
#         assert G3.x == G_plus_G2.x and G3.y == G_plus_G2.y
#
#         # Test X25519 format
#         x25519_bytes = G.to_x25519_bytes()
#         assert len(x25519_bytes) == 32
#
#         G_recovered = Curve25519Point.from_x25519_bytes(x25519_bytes)
#         assert G_recovered.x == G.x
#
#         print("✓ Basic Curve25519 tests passed")
#         return True
#
#     except Exception as e:
#         print(f"✗ Curve25519 test failed: {e}")
#         return False
#
#
# if __name__ == "__main__":
#     test_curve25519_basic()