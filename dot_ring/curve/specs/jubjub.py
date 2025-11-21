from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self

from dot_ring.curve.e2c import E2C_Variant

from ..glv import DisabledGLV, GLVSpecs
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class JubJubParams:
    """
    JubJub curve parameters.

    Specification of the JubJub curve in Twisted Edwards form.
    """

    SUITE_STRING = b"JubJub_SHA-512_TAI"  # "Jubjub_XMD:SHA-512_ELL2_RO_"
    DST = b""
    # f_len=q_len=32
    # Curve parameters
    PRIME_FIELD: Final[
        int
    ] = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    ORDER: Final[
        int
    ] = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
    COFACTOR: Final[int] = 8

    # Generator point
    GENERATOR_X: Final[
        int
    ] = 8076246640662884909881801758704306714034609987455869804520522091855516602923
    GENERATOR_Y: Final[
        int
    ] = 13262374693698910701929044844600465831413122818447359594527400194675274060458

    # Edwards curve parameters
    EDWARDS_A: Final[int] = -1
    EDWARDS_D: Final[
        int
    ] = 19257038036680949359750312669786877991949435402254120286184196891950884077233

    # GLV parameters
    GLV_LAMBDA: Final[
        int
    ] = 0x13B4F3DC4A39A493EDF849562B38C72BCFC49DB970A5056ED13D21408783DF05
    GLV_B: Final[
        int
    ] = 0x52C9F28B828426A561F00D3A63511A882EA712770D9AF4D6EE0F014D172510B4
    GLV_C: Final[
        int
    ] = 0x6CC624CF865457C3A97C6EFD6C17D1078456ABCFFF36F4E9515C806CDF650B3D

    # Z
    Z: Final[int] = 5
    M: Final[int] = 1
    K: Final[int] = 128
    L: Final[int] = 48  # can define func as well
    S_in_bytes: Final[
        int
    ] = 48  # can be taken as hsh_fn.block_size #not sure as its supposed to be 128 for sha512
    H_A: Final[str] = "SHA-512"
    ENDIAN = "little"
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    CHALLENGE_LENGTH: Final[int] = 32

    # Blinding Base For Pedersen
    BBx: Final[
        int
    ] = 42257337814662035284373945156525735092765968053982822992704750832078779438788
    BBy: Final[
        int
    ] = 47476395315228831116309413527962830333178159651930104661512857647213254194102
    UNCOMPRESSED = False


class JubJubCurve(TECurve):
    """
    Bandersnatch curve implementation.

    A high-performance curve designed for zero-knowledge proofs and VRFs,
    offering both efficiency and security.
    """

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for JubJub VRF."""
        return JubJubParams.CHALLENGE_LENGTH  # 256-bit security level

    def __init__(self) -> None:
        """Initialize Bandersnatch curve with its parameters."""
        super().__init__(
            PRIME_FIELD=JubJubParams.PRIME_FIELD,
            ORDER=JubJubParams.ORDER,
            GENERATOR_X=JubJubParams.GENERATOR_X,
            GENERATOR_Y=JubJubParams.GENERATOR_Y,
            COFACTOR=JubJubParams.COFACTOR,
            glv=DisabledGLV,
            Z=JubJubParams.Z,
            EdwardsA=JubJubParams.EDWARDS_A,
            EdwardsD=JubJubParams.EDWARDS_D,
            SUITE_STRING=JubJubParams.SUITE_STRING,
            DST=JubJubParams.DST,
            E2C=E2C_Variant.TAI,
            BBx=JubJubParams.BBx,
            BBy=JubJubParams.BBy,
            M=JubJubParams.M,
            K=JubJubParams.K,
            L=JubJubParams.L,
            S_in_bytes=JubJubParams.S_in_bytes,
            H_A=JubJubParams.H_A,
            Requires_Isogeny=JubJubParams.Requires_Isogeny,
            Isogeny_Coeffs=JubJubParams.Isogeny_Coeffs,
            UNCOMPRESSED=JubJubParams.UNCOMPRESSED,
            ENDIAN=JubJubParams.ENDIAN,
        )


# Singleton instance
JubJub_TE_Curve: Final[JubJubCurve] = JubJubCurve()


@dataclass(frozen=True)
class JubJubPoint(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """

    curve: Final[JubJubCurve] = JubJub_TE_Curve

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
        return cls(JubJubParams.GENERATOR_X, JubJubParams.GENERATOR_Y)

    @classmethod
    def identity_point(cls) -> "JubJubPoint":
        """
        Get the identity point (0, 1) of the curve.

        Returns:
            JubJubPoint: Identity point
        """
        # The identity point in Twisted Edwards coordinates is (0, 1)
        return cls(0, 1)
