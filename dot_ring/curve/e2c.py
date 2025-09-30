from enum import Enum

class E2C_Variant(Enum):
    TAI = "TryAndIncrement"
    ELL2= "Hash2Suite_Elligator2_RO_"  # RO (Random Oracle) variant for Elligator2
    SSWU= "Simple_SWU_RO_"  # RO (Random Oracle) variant for SSWU
    ELL2_NU="Hash2Suite_Elligator2_NU_"  # NU (Non-Uniform) variant for Elligator2
    SSWU_NU="Simple_SWU_NU_"  # NU (Non-Uniform) variant for SSWU