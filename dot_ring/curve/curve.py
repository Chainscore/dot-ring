from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, Literal, TypeVar, cast

from gmpy2 import invert as _invert
from gmpy2 import mpz as _mpz
from gmpy2 import powmod as _powmod

from dot_ring.curve.e2c import E2C_Variant
from dot_ring.curve.fp2 import Fp2
from dot_ring.curve.specs.parameters import CurveParams, HashConstructor

if TYPE_CHECKING:
    from dot_ring.curve.point import CurvePoint

CoordT = TypeVar("CoordT", int, Fp2)


@dataclass(frozen=True, kw_only=True)
class Curve(Generic[CoordT]):
    """
    Base implementation of an elliptic curve.

    This class provides the core functionality for elliptic curve operations,
    particularly focused on hash-to-curve operations as specified in the
    IETF draft-irtf-cfrg-hash-to-curve.

    Attributes:
        params: Stable curve-suite constants.
        e2c_variant: Selected hash-to-curve/runtime variant.
    """

    params: CurveParams[CoordT]
    e2c_variant: E2C_Variant

    def __post_init__(self) -> None:
        """Validate curve parameters after initialization."""
        self._validate()

    def hash_to_curve_dst(self) -> bytes:
        """Return the DST for the selected hash-to-curve variant."""
        if self.e2c_variant == E2C_Variant.TAI:
            return b""
        dst = self.params.hash_to_curve.dst
        if self.e2c_variant.value.endswith("_NU_"):
            return dst.replace(b"_RO_", b"_NU_")
        return dst

    def encoding_endian(self) -> Literal["little", "big"]:
        """Return point/scalar endianness for the selected variant."""
        if self.e2c_variant == E2C_Variant.TAI:
            return "little"
        return self.params.encoding.endian

    def _validate(self):
        """
        Validate that the curve parameters are correct.

        Returns:
            None
        """
        generator_x, generator_y = self.params.generator
        field_modulus = self.params.field_modulus

        if isinstance(generator_x, Fp2) or isinstance(generator_y, Fp2):
            if not (
                isinstance(generator_x, Fp2) and isinstance(generator_y, Fp2) and generator_x.p == field_modulus and generator_y.p == field_modulus
            ):
                raise ValueError("Generator coordinates must be Fp2 elements with the correct field modulus")
            if not self.is_on_curve((generator_x, generator_y)):  # type: ignore[attr-defined]
                raise ValueError("Generator point is not on the curve")

        else:
            # Original scalar field validation
            # Allow int or custom Scalar types
            if isinstance(generator_x, int) and isinstance(generator_y, int):
                if not (0 <= generator_x < field_modulus and 0 <= generator_y < field_modulus):
                    raise ValueError("Generator coordinates must be in the field range")
            elif not (isinstance(generator_x, (tuple, list)) or isinstance(generator_y, (tuple, list))):
                # Opaque field elements are accepted here; point classes validate curve membership.
                pass
            else:
                raise ValueError("Generator coordinates must be either int, Fp2, or opaque field elements")

        if not (
            self.params.field_modulus > 2
            and self.params.subgroup_order > 2
            and self.params.cofactor > 0
            and self.params.field_modulus != self.params.subgroup_order
        ):
            raise ValueError("Invalid curve parameters")

    def _hash_to_curve_fn(self) -> HashConstructor:
        return self.params.hash_to_curve.hash_fn or self.params.hash_fn

    def hash_to_field(self, msg: bytes, count: int) -> list[int]:
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

        hash_to_curve = self.params.hash_to_curve
        len_in_bytes = count * hash_to_curve.field_extension_degree * hash_to_curve.field_length
        if self._uses_xof():
            uniform_bytes = self.expand_message_xof(msg, len_in_bytes)
        else:
            uniform_bytes = self.expand_message_xmd(msg, len_in_bytes)
        u_values: list[int] = []
        for i in range(count):
            for j in range(hash_to_curve.field_extension_degree):
                elm_offset = hash_to_curve.field_length * (j + i * hash_to_curve.field_extension_degree)
                tv = uniform_bytes[elm_offset : elm_offset + hash_to_curve.field_length]
                e_j = int.from_bytes(tv, "big") % self.params.field_modulus
                u_values.append(e_j % self.params.field_modulus)  # modulo

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
        hash_to_curve = self.params.hash_to_curve
        hash_fn = self._hash_to_curve_fn()
        b_in_bytes = hash_fn().digest_size
        ell = math.ceil(len_in_bytes / b_in_bytes)

        dst = self.hash_to_curve_dst()
        if ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
            raise ValueError(f"Invalid XMD input size parameters: ell={ell}, len_in_bytes={len_in_bytes}, dst_len={len(dst)}")

        DST_prime = dst + self.I2OSP(len(dst), 1)
        Z_pad = self.I2OSP(0, cast(int, hash_to_curve.expand_len))

        l_i_b_str = self.I2OSP(len_in_bytes, 2)

        msg_prime = Z_pad + msg + l_i_b_str + self.I2OSP(0, 1) + DST_prime

        b_0 = hash_fn(msg_prime).digest()

        b_1 = hash_fn(b_0 + self.I2OSP(1, 1) + DST_prime).digest()

        b_values = [b_1]
        for i in range(2, ell + 1):
            b_i = hash_fn(self.strxor(b_0, b_values[-1]) + self.I2OSP(i, 1) + DST_prime).digest()
            b_values.append(b_i)

        uniform_bytes = b"".join(b_values)

        return uniform_bytes[:len_in_bytes]

    def _uses_xof(self) -> bool:
        """Return True when the curve suite requires XOF-based expansion."""
        hash_to_curve = self.params.hash_to_curve
        if hash_to_curve.expand_len in (None, 0):
            return True
        if b"_XOF" in self.params.suite_id or b"_XOF" in hash_to_curve.dst:
            return True
        hash_name = getattr(getattr(self._hash_to_curve_fn(), "__name__", ""), "lower", lambda: "")()
        return "shake" in hash_name

    def _default_xof_len(self) -> int:
        scalar_len = (self.params.subgroup_order.bit_length() + 7) // 8
        return max(self.params.hash_to_curve.field_length, self.params.encoding.challenge_len, 2 * scalar_len)

    def expand_message_xof(self, msg: bytes, len_in_bytes: int) -> bytes:
        # 1.ABORT if len_in_bytes > 65535 or len(DST) > 255
        # 2.DST_prime = DST | | I2OSP(len(DST), 1)
        # 3.msg_prime = msg | | I2OSP(len_in_bytes, 2) | | DST_prime
        # 4.uniform_bytes = H(msg_prime, len_in_bytes)
        # 5.return uniform_bytes

        if len_in_bytes > 65535:
            raise ValueError("len_in_bytes too large")
        dst = self.hash_to_curve_dst()
        if len(dst) > 255:
            raise ValueError("DST too long")

        # Step 2: DST_prime = DST || I2OSP(len(DST), 1)
        DST_prime = dst + self.I2OSP(len(dst), 1)

        # Step 3: msg_prime = msg || I2OSP(len_in_bytes, 2) || DST_prime
        msg_prime = msg + self.I2OSP(len_in_bytes, 2) + DST_prime

        # Step 4: uniform_bytes = SHAKE256(msg_prime, len_in_bytes)
        xof = self._hash_to_curve_fn()()
        xof.update(msg_prime)
        uniform_bytes = xof.digest(len_in_bytes)
        # Step 5: return uniform_bytes
        return cast(bytes, uniform_bytes)

    def hash(self, data: bytes, out_len: int | None = None) -> bytes:
        """Hash helper that handles both XOF and XMD suites."""
        if self._uses_xof():
            length = out_len or self._default_xof_len()
            xof = self.params.hash_fn()
            xof.update(data)
            return cast(bytes, xof.digest(length))

        hasher = self.params.hash_fn()
        hasher.update(data)
        digest = hasher.digest()
        if out_len is not None:
            return cast(bytes, digest[:out_len])
        return cast(bytes, digest)

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
        field_modulus = self.params.field_modulus
        modulus = _mpz(field_modulus)
        if _powmod(_mpz(val), _mpz(field_modulus - 1), modulus) != 1:
            raise ValueError("No inverse exists")
        return int(_invert(_mpz(val), modulus))

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
        if val == 0:
            return True
        modulus = _mpz(self.params.field_modulus)
        exponent = _mpz((self.params.field_modulus - 1) // 2)
        return _powmod(_mpz(val), exponent, modulus) == 1

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
        p = self.params.field_modulus
        if val == 0:
            return 0

        modulus = _mpz(p)
        value = _mpz(val)
        if _powmod(value, _mpz((p - 1) // 2), modulus) != 1:
            raise ValueError("No square root exists")

        q = _mpz(p - 1)
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1

        z = _mpz(2)
        while self.is_square(int(z)):
            z += 1

        c = _powmod(z, q, modulus)
        m = s
        t = _powmod(value, q, modulus)
        r = _powmod(value, _mpz((q + 1) // 2), modulus)

        while True:
            if t == 0:
                return 0
            if t == 1:
                return int(r)

            i = 1
            temp = (t * t) % p
            while temp != 1:
                temp = (temp * temp) % p
                i += 1

            b = c
            for _ in range(m - i - 1):
                b = (b * b) % p
            m = i
            c = (b * b) % p
            t = (t * c) % p
            r = (r * b) % p

    def inv(self, x: int) -> int:
        # modular inverse in GF(p)
        return pow(x, self.params.field_modulus - 2, self.params.field_modulus)

    def legendre_symbol(self, x: int) -> int:
        return pow(x, (self.params.field_modulus - 1) // 2, self.params.field_modulus)

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
        n = min(len(s1), len(s2))
        if n == 0:
            return b""
        if len(s1) != n:
            s1 = s1[:n]
        if len(s2) != n:
            s2 = s2[:n]
        return (int.from_bytes(s1, "big") ^ int.from_bytes(s2, "big")).to_bytes(n, "big")


@dataclass
class CurveVariant(Generic[CoordT]):
    name: str
    curve: Curve[CoordT]
    point_type: type[CurvePoint[Curve[CoordT], CoordT]]

    def point(self, x: CoordT, y: CoordT) -> CurvePoint[Curve[CoordT], CoordT]:
        return self.point_type(x, y, self.curve)

    def identity(self) -> CurvePoint[Curve[CoordT], CoordT]:
        return self.point_type.identity(self.curve)

    def generator_point(self) -> CurvePoint[Curve[CoordT], CoordT]:
        return self.point_type.generator_point(self.curve)

    def string_to_point(self, data: str | bytes) -> CurvePoint[Curve[CoordT], CoordT]:
        return self.point_type.string_to_point(data, self.curve)

    def encode_to_curve(self, alpha_string: bytes | str, salt: bytes | str = b"") -> CurvePoint[Curve[CoordT], CoordT]:
        return self.point_type.encode_to_curve(alpha_string, salt, self.curve)

    def msm(
        self,
        points: list[CurvePoint[Curve[CoordT], CoordT]],
        scalars: list[int],
    ) -> CurvePoint[Curve[CoordT], CoordT]:
        return self.point_type.msm(points, scalars, self.curve)
