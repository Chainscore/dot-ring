from enum import Enum


class E2C_Variant(Enum):
    """Encode to Curve (E2C) variants.

    Args:
        Enum (str): Base class for string enums
    """

    TAI = "TryAndIncrement"
    # TE Curves
    ELL2 = "Hash2Suite_Elligator2_RO_"  # RO (Random Oracle) variant for Elligator2
    ELL2_NU = "Hash2Suite_Elligator2_NU_"  # NU (Non-Uniform) variant for Elligator2
    # SW Curves
    SSWU = "Simple_SWU_RO_"  # RO (Random Oracle) variant for SSWU
    SSWU_NU = "Simple_SWU_NU_"  # NU (Non-Uniform) variant for SSWU
