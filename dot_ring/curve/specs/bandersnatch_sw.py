from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Union
import hashlib

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant
from ..short_weierstrass.sw_curve import SWCurve
from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..point import CurvePoint

@dataclass(frozen=True)
class BandersnatchSWParams:
    SUITE_STRING = b"Bandersnatch_SW_SHA-512_TAI"
    DST = b"ECVRF_Bandersnatch_XMD:SHA-512_TAI_RO_Bandersnatch_SW_SHA-512_TAI"

    PRIME_FIELD: Final[
        int
    ] = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    ORDER: Final[
        int
    ] = 0x1CFB69D4CA675F520CCE760202687600FF8F87007419047174FD06B52876E7E1
    COFACTOR: Final[int] = 4

    WEIERSTRASS_A: Final[
        int
    ] = 10773120815616481058602537765553212789256758185246796157495669123169359657269
    WEIERSTRASS_B: Final[
        int
    ] = 29569587568322301171008055308580903175558631321415017492731745847794083609535

    GENERATOR_X: Final[
        int
    ] = 30900340493481298850216505686589334086208278925799850409469406976849338430199
    GENERATOR_Y: Final[
        int
    ] = 12663882780877899054958035777720958383845500985908634476792678820121468453298

    Z: Final[int] = -11
    M: Final[int] = 1
    L: Final[int] = 64
    K: Final[int] = 1
    S_in_bytes: Final[int] = 64
    H_A = hashlib.sha512
    ENDIAN = "little"
    BBx: Final[
        int
    ] = 43295201540795761503961631609120105078472641399392666499799525033203881929458
    BBy: Final[
        int
    ] = 47295792057744344182638225978402781315571475472700428341116949953237551542374

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
    curve: Final[SWCurve] = Bandersnatch_SW_SW_Curve
    
    @classmethod
    def identity_point(cls) -> None:
        return None

    @classmethod
    def _x_recover(cls, y: int) -> int:
        return SWAffinePoint._x_recover(cls, y)

    def point_to_string(self) -> bytes:
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
        if self.y <= (-self.y % p):
            flag = 0  # Y positive
        else:
            flag = 1 << 7  # Y negative

        # Serialize x-coordinate
        x_bytes = int(self.x).to_bytes((field_bit_len + 7) // 8, self.curve.ENDIAN)

        # Copy x_bytes into buffer of total length
        result = bytearray(output_byte_len)
        result[: len(x_bytes)] = x_bytes

        # Merge flag bits into last byte
        result[-1] |= flag

        return bytes(result)

    @classmethod
    def _y_recover(cls, x):
        p = cls.curve.PRIME_FIELD
        A = cls.curve.WeierstrassA
        B = cls.curve.WeierstrassB
        y_square = (pow(x, 3, p) + A * x + B) % p
        try:
            y = cls.curve.mod_sqrt(y_square)
        except ValueError:
            return None
        
        if not y:
            return None
        neg_y = -y % p
        if y < neg_y:
            return y, neg_y
        return neg_y, y

    @classmethod
    def string_to_point(cls, octet_string: Union[str, bytes]) -> "CurvePoint" | str:
        if isinstance(octet_string, str):
            octet_string = bytes.fromhex(octet_string)

        if len(octet_string) == 0:
            raise ValueError("Empty octet string")

        x_bytes = octet_string[:-1]
        x = int.from_bytes(x_bytes, cls.curve.ENDIAN)  # use big-endian
        y_candidates = cls._y_recover(x)
        if not y_candidates:
            return "INVALID"
        y, y_neg = y_candidates

        is_negative = (octet_string[-1] >> 7) & 1
        is_infinity = (octet_string[-1] >> 6) & 1

        if is_infinity:
            if is_negative:
                return "INVALID"
            return "INVALID"

        if is_negative:
            try:
                return cls(x, y_neg)
            except ValueError:
                return "INVALID"  # to support in the case of TAI
        else:
            try:
                return cls(x, y)
            except ValueError:
                return "INVALID"  # to support in the case of TAI

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

        H = "INVALID"
        front = b"\x01"
        back = b"\x00"
        alpha_string = (
            alpha_string.encode() if isinstance(alpha_string, str) else alpha_string
        )
        salt = salt.encode() if isinstance(salt, str) else salt
        suite_string = cls.curve.SUITE_STRING
        while H == "INVALID" or H == cls.identity_point():
            ctr_string = ctr.to_bytes(1, "big")
            hash_input = suite_string + front + salt + alpha_string + ctr_string + back
            hash_output = hashlib.sha512(hash_input).digest()
            H = cls.string_to_point(hash_output[:33])
            if H != "INVALID" and cls.curve.COFACTOR > 1:
                H = H * cls.curve.COFACTOR
            ctr += 1
        return H

Bandersnatch_SW = CurveVariant(
    name="Bandersnatch_SW",
    curve=Bandersnatch_SW_SW_Curve,
    point=Bandersnatch_SW_Point,
)