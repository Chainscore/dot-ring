from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Literal, Self, cast

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..short_weierstrass.sw_curve import SWCurve


@dataclass(frozen=True)
class BandersnatchSWParams:
    SUITE_STRING = b"Bandersnatch_SW_SHA-512_TAI"
    DST = b"ECVRF_Bandersnatch_XMD:SHA-512_TAI_RO_Bandersnatch_SW_SHA-512_TAI"

    PRIME_FIELD: Final[int] = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    ORDER: Final[int] = 0x1CFB69D4CA675F520CCE760202687600FF8F87007419047174FD06B52876E7E1
    COFACTOR: Final[int] = 4

    WEIERSTRASS_A: Final[int] = 10773120815616481058602537765553212789256758185246796157495669123169359657269
    WEIERSTRASS_B: Final[int] = 29569587568322301171008055308580903175558631321415017492731745847794083609535

    GENERATOR_X: Final[int] = 30900340493481298850216505686589334086208278925799850409469406976849338430199
    GENERATOR_Y: Final[int] = 12663882780877899054958035777720958383845500985908634476792678820121468453298

    Z: Final[int] = -11
    M: Final[int] = 1
    L: Final[int] = 64
    K: Final[int] = 1
    S_in_bytes: Final[int] = 64
    H_A = hashlib.sha512
    ENDIAN = "little"
    BBx: Final[int] = 43295201540795761503961631609120105078472641399392666499799525033203881929458
    BBy: Final[int] = 47295792057744344182638225978402781315571475472700428341116949953237551542374

    CHALLENGE_LENGTH: Final[int] = 32
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 33


Bandersnatch_SW_SW_Curve: Final[SWCurve] = SWCurve(
    PRIME_FIELD=BandersnatchSWParams.PRIME_FIELD,
    ORDER=BandersnatchSWParams.ORDER,
    GENERATOR_X=BandersnatchSWParams.GENERATOR_X,
    GENERATOR_Y=BandersnatchSWParams.GENERATOR_Y,
    COFACTOR=BandersnatchSWParams.COFACTOR,
    Z=BandersnatchSWParams.Z,
    WeierstrassA=BandersnatchSWParams.WEIERSTRASS_A,
    WeierstrassB=BandersnatchSWParams.WEIERSTRASS_B,
    SUITE_STRING=BandersnatchSWParams.SUITE_STRING,
    DST=BandersnatchSWParams.DST,
    E2C=E2C_Variant.TAI,
    BBx=BandersnatchSWParams.BBx,
    BBy=BandersnatchSWParams.BBy,
    M=BandersnatchSWParams.M,
    K=BandersnatchSWParams.K,
    L=BandersnatchSWParams.L,
    S_in_bytes=BandersnatchSWParams.S_in_bytes,
    H_A=BandersnatchSWParams.H_A,
    Requires_Isogeny=BandersnatchSWParams.Requires_Isogeny,
    Isogeny_Coeffs=BandersnatchSWParams.Isogeny_Coeffs,
    UNCOMPRESSED=BandersnatchSWParams.UNCOMPRESSED,
    ENDIAN=BandersnatchSWParams.ENDIAN,
    POINT_LEN=BandersnatchSWParams.POINT_LEN,
    CHALLENGE_LENGTH=BandersnatchSWParams.CHALLENGE_LENGTH,
)


class Bandersnatch_SW_Point(SWAffinePoint):
    curve: SWCurve = Bandersnatch_SW_SW_Curve

    @classmethod
    def identity_point(cls) -> None:
        return None

    @classmethod
    def _x_recover(cls, y: int) -> tuple[int, int]:
        return SWAffinePoint._x_recover(y)

    def point_to_string(self, compressed: bool = False) -> bytes:
        """ """

        p = self.curve.PRIME_FIELD
        field_bit_len = p.bit_length()
        flag_bit_len = 2  # SWFlags: YIsNegative + PointAtInfinity
        total_bits = field_bit_len + flag_bit_len

        # Compute number of bytes to hold field + flags
        output_byte_len = (total_bits + 7) // 8  # ceil(total_bits/8)

        # Handle point at infinity
        if self.x is None and self.y is None:
            # field = 0, flags = 0b01 << 6 = 0x40
            result = bytearray(output_byte_len)
            result[-1] |= 1 << 6  # PointAtInfinity flag
            return bytes(result)

        # Determine flags
        if self.y is None:
             raise ValueError("Cannot serialize identity point")
        y_int = cast(int, self.y)
        if y_int <= (-y_int % p):
            flag = 0  # Y positive
        else:
            flag = 1 << 7  # Y negative

        # Serialize x-coordinate
        if self.x is None:
             raise ValueError("Cannot serialize identity point")
        x_bytes = int(cast(int, self.x)).to_bytes((field_bit_len + 7) // 8, cast(Literal["little", "big"], self.curve.ENDIAN))

        # Copy x_bytes into buffer of total length
        result = bytearray(output_byte_len)
        result[: len(x_bytes)] = x_bytes

        # Merge flag bits into last byte
        result[-1] |= flag

        return bytes(result)

    @classmethod
    def _y_recover(cls, x: int) -> tuple[int, int] | None:
        p = cls.curve.PRIME_FIELD
        A = cast(int, cls.curve.WeierstrassA)
        B = cast(int, cls.curve.WeierstrassB)
        y_square = (pow(x, 3, p) + A * x + B) % p
        try:
            y = cls.curve.mod_sqrt(y_square)
        except ValueError:
            return None

        if not y:
            return None
        neg_y = -y % p
        if isinstance(y, int) and y <= (p - 1) // 2:
            return y, neg_y
        return neg_y, y

    @classmethod
    def string_to_point(cls, data: str | bytes) -> Self:
        if isinstance(data, str):
            data = bytes.fromhex(data)

        if len(data) == 0:
            raise ValueError("Empty octet string")

        # Assuming the input `data` is still an octet string as per original logic
        # and the `x_str`, `y_str`, `Helpers` part was a mis-paste or incomplete change.
        # Reverting to original parsing logic but using `data` instead of `octet_string`.
        x_bytes = data[:-1]
        x = int.from_bytes(x_bytes, cast(Literal["little", "big"], cls.curve.ENDIAN))
        y_candidates = cls._y_recover(x)
        if not y_candidates:
            raise ValueError("INVALID point: no y-coordinate found for x")
        y, y_neg = y_candidates

        is_negative = (data[-1] >> 7) & 1
        is_infinity = (data[-1] >> 6) & 1

        if is_infinity:
            if is_negative:
                raise ValueError("INVALID: Infinity point cannot be negative")
            raise ValueError("INVALID: Infinity point not supported")

        if is_negative:
            try:
                return cls(x, y_neg)
            except ValueError:
                raise ValueError("INVALID point") from None
        else:
            try:
                return cls(x, y)
            except ValueError:
                raise ValueError("INVALID point") from None

    @classmethod  # modified
    def encode_to_curve_tai(cls, alpha_string: bytes | str, salt: bytes = b"") -> Self:
        """
        Encode a string to a curve point using try-and-increment method for ECVRF.

        Args:
            alpha: String to encode
            salt: Optional salt for the encoding

        Returns:
            TEAffinePoint: Resulting curve point
        """
        ctr = 0
        import hashlib

        H: Self | None = None
        front = b"\x01"
        back = b"\x00"
        alpha_string = alpha_string.encode() if isinstance(alpha_string, str) else alpha_string
        salt = salt.encode() if isinstance(salt, str) else salt
        suite_string = cls.curve.SUITE_STRING
        
        while True:
            ctr_string = ctr.to_bytes(1, "big")
            hash_input = suite_string + front + salt + alpha_string + ctr_string + back
            hash_output = hashlib.sha512(hash_input).digest()
            try:
                H = cls.string_to_point(hash_output[:33])
            except ValueError:
                ctr += 1
                continue
            
            # Check if H is valid (not raising ValueError)
            if cls.curve.COFACTOR > 1:
                # H is Self | None, but here it must be Self (point)
                if H is None: # Should not happen if string_to_point works
                     continue
                H = cast(Self, H * cls.curve.COFACTOR)  # type: ignore[operator]
            
            if H != cls.identity_point():
                return H
            ctr += 1


Bandersnatch_SW = CurveVariant(
    name="Bandersnatch_SW",
    curve=Bandersnatch_SW_SW_Curve,
    point=Bandersnatch_SW_Point,
)
