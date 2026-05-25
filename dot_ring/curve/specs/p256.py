from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from dot_ring.curve.curve import CurveVariant
from dot_ring.curve.e2c import E2C_Variant

from ..short_weierstrass.sw_affine_point import SWAffinePoint
from ..short_weierstrass.sw_curve import SWCurve


@dataclass(frozen=True)
class P256Params:
    """
    NIST P-256 (secp256r1) curve parameters.

    The P-256 curve is a NIST-standardized Short Weierstrass curve widely used
    in TLS, digital signatures, and other cryptographic applications.
    """

    SUITE_STRING = b"Secp256r1-SHA256-TAI-v1"
    SUITE_ID = b"Secp256r1-SHA256-TAI-v1"
    DST = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"  # Default DST is the same as SUITE_STRING

    # Curve parameters for y² = x³ - 3x + b
    PRIME_FIELD: Final[int] = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    ORDER: Final[int] = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    COFACTOR: Final[int] = 1

    # Generator point
    GENERATOR_X: Final[int] = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    GENERATOR_Y: Final[int] = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    # Short Weierstrass parameters: y² = x³ + ax + b
    WEIERSTRASS_A: Final[int] = -3  # a = -3
    WEIERSTRASS_B: Final[int] = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    # Z parameter for SSWU mapping (from RFC 9380 Section 8.1)
    Z: Final[int] = -10  # P-256 uses Z = -10 for SSWU mapping
    M: Final[int] = 1  # Field Extension Degree
    L: Final[int] = 48  # can define func as well
    K: Final[int] = 128  # Security level
    # expand_message: Final[str]="XMD"
    S_in_bytes: Final[int] = 64
    H_A = hashlib.sha256
    ENDIAN = "big"
    # Blinding Base For Pedersen VRF
    # These are arbitrary points on the curve for blinding
    BBx: Final[int] = 100063053743935619201936855760019111820847755970243670581468062459849338000
    BBy: Final[int] = 113675507039234898358330549589155441528265243038226986303017485279501143145422
    # Challenge length in bytes for VRF (from RFC 9381)
    CHALLENGE_LENGTH: Final[int] = 16  # 128 bits
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    UNCOMPRESSED = False
    POINT_LEN: Final[int] = 33
    TRANSCRIPT_HASH = "sha256"
    HASH_TO_CURVE = "tai"


class P256Curve(SWCurve):
    """
    NIST P-256 (secp256r1) curve implementation.

    A widely standardized curve used in many cryptographic protocols.
    Defined by the equation y² = x³ - 3x + b over the prime field.
    """

    def __init__(self, e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> None:
        """Initialize P-256 curve with its parameters."""
        # Default suite and dst
        SUITE_STRING = P256Params.SUITE_STRING
        DST = P256Params.DST
        # Replace RO with NU automatically if variant endswith "NU_"
        if e2c_variant.value.endswith("NU_"):
            SUITE_STRING = SUITE_STRING.replace(b"_RO_", b"_NU_")
            DST = DST.replace(b"_RO_", b"_NU_")
        elif e2c_variant.value == "TryAndIncrement":
            SUITE_STRING = P256Params.SUITE_ID
            DST = b""
        ENDIAN = "little" if e2c_variant == E2C_Variant.TAI else P256Params.ENDIAN

        super().__init__(
            PRIME_FIELD=P256Params.PRIME_FIELD,
            ORDER=P256Params.ORDER,
            GENERATOR_X=P256Params.GENERATOR_X,
            GENERATOR_Y=P256Params.GENERATOR_Y,
            COFACTOR=P256Params.COFACTOR,
            Z=P256Params.Z,
            WeierstrassA=P256Params.WEIERSTRASS_A,
            WeierstrassB=P256Params.WEIERSTRASS_B,
            SUITE_STRING=SUITE_STRING,
            DST=DST,
            E2C=e2c_variant,
            BBx=P256Params.BBx,
            BBy=P256Params.BBy,
            M=P256Params.M,
            K=P256Params.K,
            L=P256Params.L,
            S_in_bytes=P256Params.S_in_bytes,
            H_A=P256Params.H_A,
            Requires_Isogeny=P256Params.Requires_Isogeny,
            Isogeny_Coeffs=P256Params.Isogeny_Coeffs,
            UNCOMPRESSED=P256Params.UNCOMPRESSED,
            ENDIAN=ENDIAN,
            POINT_LEN=P256Params.POINT_LEN,
            CHALLENGE_LENGTH=P256Params.CHALLENGE_LENGTH,
            SUITE_ID=P256Params.SUITE_ID if e2c_variant == E2C_Variant.TAI else None,
            TRANSCRIPT_HASH=P256Params.TRANSCRIPT_HASH,
            HASH_TO_CURVE=P256Params.HASH_TO_CURVE if e2c_variant == E2C_Variant.TAI else None,
        )


def nu_variant(e2c_variant: E2C_Variant = E2C_Variant.SSWU) -> type[P256Point]:
    class P256PointVariant(P256Point):
        """Point on P256 with custom E2C variant"""

        curve: P256Curve = P256Curve(e2c_variant)

    return P256PointVariant


class P256Point(SWAffinePoint):
    """
    Point on the NIST P-256 curve.

    Implements point operations specific to the P-256 curve.
    """

    @classmethod
    def identity_point(cls) -> None:
        """
        Get the identity point (0, 1) of the curve.
        Returns:
            Ed25519Point: Identity point
        """
        # The identity point
        return None

    def point_to_string(self, compressed: bool = True) -> bytes:
        if getattr(self.curve, "HASH_TO_CURVE", None) != "tai":
            return super().point_to_string(compressed)

        if self.x is None and self.y is None:
            return bytes([0] * 32 + [0x40])

        p = self.curve.PRIME_FIELD
        x_bytes = int(self.x).to_bytes(32, "little")
        flag = 0x80 if int(self.y) > (-int(self.y) % p) else 0x00
        return x_bytes + bytes([flag])

    @classmethod
    def string_to_point(cls, data: str | bytes):
        if isinstance(data, str):
            data = bytes.fromhex(data)

        if getattr(cls.curve, "HASH_TO_CURVE", None) != "tai":
            return super().string_to_point(data)
        elif len(data) == 33 and data[0] in (0x02, 0x03):
            # Canonical SW encodings put flags in the final byte, so external
            # vectors can coincidentally start with SEC1 marker bytes.
            try:
                return cls._string_to_canonical_point(data)
            except ValueError:
                return super().string_to_point(data)

        if len(data) != 33:
            raise ValueError(f"Invalid compressed point length: expected 33, got {len(data)}")
        return cls._string_to_canonical_point(data)

    @classmethod
    def _string_to_canonical_point(cls, data: bytes):
        flag = data[-1]
        is_negative = (flag >> 7) & 1
        is_infinity = (flag >> 6) & 1
        if flag & 0x3F:
            raise ValueError("Invalid canonical point flags")
        if is_infinity:
            if is_negative or any(data[:-1]):
                raise ValueError("Invalid infinity encoding")
            return cls.identity()

        x = int.from_bytes(data[:-1], "little")
        if x >= cls.curve.PRIME_FIELD:
            raise ValueError("x-coordinate is not in field")
        y_candidates = cls._y_recover(x)
        if y_candidates is None:
            raise ValueError("Invalid point")
        y, y_neg = y_candidates
        return cls(x, y_neg if is_negative else y)

    @classmethod
    def _y_recover(cls, x: int) -> tuple[int, int] | None:
        p = cls.curve.PRIME_FIELD
        y_square = (pow(x, 3, p) + cls.curve.WeierstrassA * x + cls.curve.WeierstrassB) % p
        try:
            y = cls.curve.mod_sqrt(y_square)
        except ValueError:
            return None
        neg_y = -y % p
        return (y, neg_y) if y <= neg_y else (neg_y, y)


P256_RO = CurveVariant(
    name="P256_RO",
    curve=P256Curve(e2c_variant=E2C_Variant.SSWU),
    point=nu_variant(e2c_variant=E2C_Variant.SSWU),
)

P256_NU = CurveVariant(
    name="P256_TAI",
    curve=P256Curve(e2c_variant=E2C_Variant.TAI),
    point=nu_variant(e2c_variant=E2C_Variant.TAI),
)
