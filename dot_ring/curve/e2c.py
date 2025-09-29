
from enum import Enum

class E2C_Variant(Enum):
    TAI = "TryAndIncrement"
    ELL2= "Hash2Suite_Elligator2_RO_" #Replace with NU for NU way of hash 2 curve
    SSWU= "Simple_SWU_RO_" #Replace with NU for NU way of hash 2 curve
    ELL2_NU="Hash2Suite_Elligator2_NU_"
    SSWU_NU="Simple_SWU_NU_"