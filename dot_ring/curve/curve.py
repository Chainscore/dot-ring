from __future__ import annotations

from enum import Enum
import math
import hashlib
from dataclasses import dataclass
from typing import List, Dict, TYPE_CHECKING
from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.fast_math import powmod, invert, is_square as fast_is_square, sqrt_mod

if TYPE_CHECKING:
    from dot_ring.curve.point import CurvePoint



@dataclass(frozen=True)
class Curve:
    """
    Base implementation of an elliptic curve.

    This class provides the core functionality for elliptic curve operations,
    particularly focused on hash-to-curve operations as specified in the
    IETF draft-irtf-cfrg-hash-to-curve.

    Attributes:
        PRIME_FIELD: The prime field characteristic
        ORDER: The order of the curve
        GENERATOR_X: X-coordinate of the generator point
        GENERATOR_Y: Y-coordinate of the generator point
        COFACTOR: The cofactor of the curve
        Z: The Z parameter for the curve
    """

    # Curve Parameters
    PRIME_FIELD: int
    ORDER: int
    GENERATOR_X: int
    GENERATOR_Y: int
    COFACTOR: int
    Z: int
    E2C: E2C_Variant

    M: int  # 1
    K: int  # 128
    L: int
    S_in_bytes: int
    H_A: str
    ENDIAN: str
    
    CHALLENGE_LENGTH: int

    # Isogeny
    Requires_Isogeny: bool
    Isogeny_Coeffs: Dict[str, List[int]]

    # Suite String Parameters
    SUITE_STRING: bytes
    DST: bytes

    # Blinding Base For Pedersen
    BBx: int
    BBy: int
    UNCOMPRESSED: bool
    POINT_LEN: int

    def __post_init__(self) -> None:
        """Validate curve parameters after initialization."""
        if not self._validate_parameters():
            raise ValueError("Invalid curve parameters")

    def _validate_parameters(self) -> bool:
        """
        Validate that the curve parameters are correct.

        Returns:
            bool: True if parameters are valid, False otherwise
        """
        # For extension fields (like Fp2), we need to check each component
        if hasattr(self.GENERATOR_X, "__iter__"):
            # Handle Fp2 points (tuples of two integers)
            if not (
                isinstance(self.GENERATOR_X, (tuple, list))
                and len(self.GENERATOR_X) == 2
                and all(isinstance(x, int) for x in self.GENERATOR_X)
                and all(0 <= x < self.PRIME_FIELD for x in self.GENERATOR_X)
            ):
                return False

            if not (
                isinstance(self.GENERATOR_Y, (tuple, list))
                and len(self.GENERATOR_Y) == 2
                and all(isinstance(y, int) for y in self.GENERATOR_Y)
                and all(0 <= y < self.PRIME_FIELD for y in self.GENERATOR_Y)
            ):
                return False

            # Convert to a point for the on-curve check
            from dot_ring.curve.short_weierstrass.sw_affine_point import SWAffinePoint

            point = SWAffinePoint(self.GENERATOR_X, self.GENERATOR_Y, self)
            if not point.is_on_curve():
                return False

        else:
            # Original scalar field validation
            if not (
                0 <= self.GENERATOR_X < self.PRIME_FIELD
                and 0 <= self.GENERATOR_Y < self.PRIME_FIELD
            ):
                return False

            # if not self.is_on_curve(self.GENERATOR_X, self.GENERATOR_Y): #already given in point class
            #     return False

        return (
            self.PRIME_FIELD > 2
            and self.ORDER > 2
            and self.COFACTOR > 0
            and self.PRIME_FIELD != self.ORDER
        )

    def hash_to_field(self, msg: bytes, count: int) -> List[int]:
        """
        Hash an arbitrary string to one or more field elements.

        Args:
            msg: The message to hash
            count: Number of field elements to generate

        Returns:
            List[int]: List of field elements

        Raises:
            ValueError: If count is negative or msg is None
        """
        if count < 0:
            raise ValueError("Count must be non-negative")
        if msg is None:
            raise ValueError("Message cannot be None")

        len_in_bytes = count * self.M * self.L
        if self._uses_xof():
            uniform_bytes = self.expand_message_xof(msg, len_in_bytes)
        else:
            uniform_bytes = self.expand_message_xmd(msg, len_in_bytes)
        u_values: List[int] = []
        for i in range(count):
            for j in range(self.M):
                elm_offset = self.L * (j + i * self.M)
                tv = uniform_bytes[elm_offset : elm_offset + self.L]
                e_j = int.from_bytes(tv, "big") % self.PRIME_FIELD
                u_values.append(e_j % self.PRIME_FIELD)  # modulo

        return u_values

    def expand_message_xmd(self, msg: bytes, len_in_bytes: int) -> bytes:
        """
        Expand a message using XMD (eXpandable Message Digest).
        Args:
            msg: The message to expand
            len_in_bytes: Desired length of the output in bytes

        Returns:
            bytes: The expanded message

        Raises:
            ValueError: If the input parameters are invalid
        """
        b_in_bytes = self.H_A().digest_size
        ell = math.ceil(len_in_bytes / b_in_bytes)

        if ell > 255 or len_in_bytes > 65535 or len(self.DST) > 255:
            raise ValueError("Invalid input size parameters")

        DST_prime = self.DST + self.I2OSP(len(self.DST), 1)
        Z_pad = self.I2OSP(0, self.S_in_bytes)

        l_i_b_str = self.I2OSP(len_in_bytes, 2)

        msg_prime = Z_pad + msg + l_i_b_str + self.I2OSP(0, 1) + DST_prime

        b_0 = self.H_A(msg_prime).digest()

        b_1 = self.H_A(b_0 + self.I2OSP(1, 1) + DST_prime).digest()

        b_values = [b_1]
        for i in range(2, ell + 1):
            b_i = self.H_A(
                self.strxor(b_0, b_values[-1]) + self.I2OSP(i, 1) + DST_prime
            ).digest()
            b_values.append(b_i)

        uniform_bytes = b"".join(b_values)

        return uniform_bytes[:len_in_bytes]

    def _uses_xof(self) -> bool:
        """Return True when the curve suite requires XOF-based expansion."""
        if self.S_in_bytes in (None, 0):
            return True
        suite = self.SUITE_STRING or b""
        if b"_XOF" in suite:
            return True
        hash_name = getattr(getattr(self.H_A, "__name__", ""), "lower", lambda: "")()
        return "shake" in hash_name

    def _default_xof_len(self) -> int:
        scalar_len = (self.ORDER.bit_length() + 7) // 8
        return max(self.L, self.CHALLENGE_LENGTH, 2 * scalar_len)

    def expand_message_xof(self, msg: bytes, len_in_bytes: int) -> bytes:
        # 1.ABORT if len_in_bytes > 65535 or len(DST) > 255
        # 2.DST_prime = DST | | I2OSP(len(DST), 1)
        # 3.msg_prime = msg | | I2OSP(len_in_bytes, 2) | | DST_prime
        # 4.uniform_bytes = H(msg_prime, len_in_bytes)
        # 5.return uniform_bytes

        if len_in_bytes > 65535:
            raise ValueError("len_in_bytes too large")
        if len(self.DST) > 255:
            raise ValueError("DST too long")

        # Step 2: DST_prime = DST || I2OSP(len(DST), 1)
        DST_prime = self.DST + self.I2OSP(len(self.DST), 1)

        # Step 3: msg_prime = msg || I2OSP(len_in_bytes, 2) || DST_prime
        msg_prime = msg + self.I2OSP(len_in_bytes, 2) + DST_prime

        # Step 4: uniform_bytes = SHAKE256(msg_prime, len_in_bytes)
        xof = self.H_A()
        xof.update(msg_prime)
        uniform_bytes = xof.digest(len_in_bytes)
        # Step 5: return uniform_bytes
        return uniform_bytes

    def hash(self, data: bytes, out_len: int | None = None) -> bytes:
        """Hash helper that handles both XOF and XMD suites."""
        if self._uses_xof():
            length = out_len or self._default_xof_len()
            xof = self.H_A()
            xof.update(data)
            return xof.digest(length)

        hasher = self.H_A()
        hasher.update(data)
        digest = hasher.digest()
        if out_len is not None:
            return digest[:out_len]
        return digest

    def mod_inverse(self, val: int) -> int:
        """
        Compute modular multiplicative inverse using gmpy2 if available.

        Args:
            val: Value to invert

        Returns:
            int: Modular inverse

        Raises:
            ValueError: If inverse doesn't exist
        """
        if powmod(val, self.PRIME_FIELD - 1, self.PRIME_FIELD) != 1:
            raise ValueError("No inverse exists")
        return invert(val, self.PRIME_FIELD)

    @staticmethod
    def CMOV(a: int, b: int, cond: int) -> int:
        """Constant-time conditional move: if cond is True, return b; else return a."""
        return b if cond else a

    @staticmethod
    def sgn0(x: int) -> int:
        """Return the sign of x: 1 if odd, 0 if even."""
        return x % 2

    def find_z_ell2(self) -> int:
        return 5  # 5 is only for bandersnatch

    def is_square(self, val: int) -> bool:
        """Check if val is a quadratic residue mod p using gmpy2 if available."""
        return fast_is_square(val, self.PRIME_FIELD)

    def mod_sqrt(self, val: int) -> int:
        """
        Compute the square root modulo prime field using gmpy2 if available.

        Args:
            val: Value to compute square root of

        Returns:
            int: Square root of val modulo prime field

        Raises:
            ValueError: If no square root exists
        """
        result = sqrt_mod(val, self.PRIME_FIELD)
        if result is None:
            raise ValueError("No square root exists")
        return result

    def inv(self, x: int) -> int:
        # modular inverse in GF(p)
        return pow(x, self.PRIME_FIELD - 2, self.PRIME_FIELD)

    def legendre_symbol(self, x: int) -> int:
        return pow(x, (self.PRIME_FIELD - 1) // 2, self.PRIME_FIELD)

    @staticmethod
    def sha512(data: bytes) -> bytes:
        """Calculate SHA-512 hash"""
        return hashlib.sha512(data).digest()

    @staticmethod
    def I2OSP(value: int, length: int) -> bytes:
        if value >= 256**length:
            raise ValueError("integer too large")
        return value.to_bytes(length, "big")

    @staticmethod
    def OS2IP(octets: bytearray) -> int:
        return int.from_bytes(octets, "big")

    @staticmethod
    def strxor(s1: bytes, s2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(s1, s2))


@dataclass
class CurveVariant:
    name: str
    curve: Curve
    point: type[CurvePoint]