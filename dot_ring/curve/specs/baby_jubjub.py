from __future__ import annotations
from dataclasses import dataclass
from typing import Final, Self
from dot_ring.curve.e2c import E2C_Variant
from ..twisted_edwards.te_curve import TECurve
from ..twisted_edwards.te_affine_point import TEAffinePoint


@dataclass(frozen=True)
class BabyJubJubParams:
    """
    Baby JubJub curve parameters.

    Specification of the Baby JubJub curve in Twisted Edwards form.
    """

    SUITE_STRING = b"Baby-JubJub_SHA-512_TAI"  # "Babyjubjub_XMD:SHA-512_ELL2_RO_"
    DST = b""

    # Curve parameters
    PRIME_FIELD: Final[
        int
    ] = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    ORDER: Final[
        int
    ] = 2736030358979909402780800718157159386076813972158567259200215660948447373041
    COFACTOR: Final[int] = 8

    # Generator point
    GENERATOR_X: Final[
        int
    ] = 19698561148652590122159747500897617769866003486955115824547446575314762165298
    GENERATOR_Y: Final[
        int
    ] = 19298250018296453272277890825869354524455968081175474282777126169995084727839
    # Edwards curve parameters
    EDWARDS_A: Final[int] = 1
    EDWARDS_D: Final[
        int
    ] = 9706598848417545097372247223557719406784115219466060233080913168975159366771

    # Z
    Z: Final[int] = 5
    M: Final[int] = 1
    K: Final[int] = 128
    L: Final[int] = 32  # can define func as well
    S_in_bytes: Final[
        int
    ] = 128  # can be taken as hsh_fn.block_size #not sure as its supposed to be 128 for sha512
    H_A: Final[str] = "SHA-512"
    ENDIAN = "little"
    Requires_Isogeny: Final[bool] = False
    Isogeny_Coeffs = None
    # Challenge length in bytes for VRF (aligned with 128-bit security level)
    CHALLENGE_LENGTH: Final[int] = 32  # 128 bits

    # Blinding Base For Pedersen
    BBx: Final[
        int
    ] = 8170247200255741810297410022472365370979789984587637609570347196251706043122
    BBy: Final[
        int
    ] = 16313972569917201570489077828713531620741538540099917729994937953803219324220
    UNCOMPRESSED = False



class BabyJubJubCurve(TECurve):
    """
    Bandersnatch curve implementation.

    A high-performance curve designed for zero-knowledge proofs and VRFs,
    offering both efficiency and security.
    """

    @property
    def CHALLENGE_LENGTH(self) -> int:
        """Return the challenge length in bytes for BabyJubJub VRF."""
        return BabyJubJubParams.CHALLENGE_LENGTH

    def __init__(self) -> None:
        """Initialize Bandersnatch curve with its parameters."""
        super().__init__(
            PRIME_FIELD=BabyJubJubParams.PRIME_FIELD,
            ORDER=BabyJubJubParams.ORDER,
            GENERATOR_X=BabyJubJubParams.GENERATOR_X,
            GENERATOR_Y=BabyJubJubParams.GENERATOR_Y,
            COFACTOR=BabyJubJubParams.COFACTOR,
            Z=BabyJubJubParams.Z,
            EdwardsA=BabyJubJubParams.EDWARDS_A,
            EdwardsD=BabyJubJubParams.EDWARDS_D,
            SUITE_STRING=BabyJubJubParams.SUITE_STRING,
            DST=BabyJubJubParams.DST,
            E2C=E2C_Variant.TAI,
            BBx=BabyJubJubParams.BBx,
            BBy=BabyJubJubParams.BBy,
            M=BabyJubJubParams.M,
            K=BabyJubJubParams.K,
            L=BabyJubJubParams.L,
            S_in_bytes=BabyJubJubParams.S_in_bytes,
            H_A=BabyJubJubParams.H_A,
            Requires_Isogeny=BabyJubJubParams.Requires_Isogeny,
            Isogeny_Coeffs=BabyJubJubParams.Isogeny_Coeffs,
            UNCOMPRESSED=BabyJubJubParams.UNCOMPRESSED,
            ENDIAN=BabyJubJubParams.ENDIAN,
        )


# Singleton instance
BabyJubJub_TE_Curve: Final[BabyJubJubCurve] = BabyJubJubCurve()


@dataclass(frozen=True)
class BabyJubJubPoint(TEAffinePoint):
    """
    Point on the Bandersnatch curve.

    Implements optimized point operations specific to the Bandersnatch curve,
    including GLV scalar multiplication.
    """

    curve: Final[BabyJubJubCurve] = BabyJubJub_TE_Curve

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
        return cls(BabyJubJubParams.GENERATOR_X, BabyJubJubParams.GENERATOR_Y)

    @classmethod
    def identity_point(cls) -> Self:
        return cls(0, 1)
