from __future__ import annotations

from dot_ring.curve.specs.bandersnatch import BandersnatchParams

S_PRIME: int = BandersnatchParams.PRIME_FIELD  # Finite‑field modulus p
S_ORDER: int = BandersnatchParams.ORDER  # Prime subgroup order r

# Base point for the prover’s blinding factor when masking linkability tags
Blinding_Base: tuple[int, int] = (BandersnatchParams.BBx, BandersnatchParams.BBy)

# Initial seed generator for hashing ring items → curve points (old)
# SeedPoint: tuple[int, int] = (
# 3955725774225903122339172568337849452553276548604445833196164961773358506589,
# 29870564530691725960104983716673293929719207405660860235233811770612192692323,
# )
#

# new  seed point
SeedPoint: tuple[int, int] = (
    37805570861274048643170021838972902516980894313648523898085159469000338764576,
    14738305321141000190236674389841754997202271418876976886494444739226156422510,
)


# old
# # Padding generator so we can commit to short rings without leaking |R|
# PaddingPoint: tuple[int, int] = (23942223917106120326220291257397678561637131227432899006603244452561725937075,
#            1605027200774560580022502723165578671697794116420567297367317898913080293877)

# new padding point
PaddingPoint: tuple[int, int] = (
    26287722405578650394504321825321286533153045350760430979437739593351290020913,
    19058981610000167534379068105702216971787064146691007947119244515951752366738,
)


S_A: int = 10773120815616481058602537765553212789256758185246796157495669123169359657269
S_B: int = 29569587568322301171008055308580903175558631321415017492731745847794083609535

DEFAULT_SIZE: int = 512

OMEGA_2048: int = 49307615728544765012166121802278658070711169839041683575071795236746050763237
OMEGA_1024 = pow(OMEGA_2048, 2048 // 1024, S_PRIME)
OMEGA_512: int = pow(OMEGA_2048, 2048 // 512, S_PRIME)

# Pre‑compute the entire evaluation domain for fast access.
D_512: list[int] = [pow(OMEGA_512, i, S_PRIME) for i in range(512)]
D_1024: list[int] = [pow(OMEGA_1024, i, S_PRIME) for i in range(1024)]
D_2048: list[int] = [pow(OMEGA_2048, i, S_PRIME) for i in range(2048)]

OMEGAS = {
    512: OMEGA_512,
    1024: OMEGA_1024,
    2048: OMEGA_2048,
}

EVAL_DOMAINS = {
    512: D_512,
    1024: D_1024,
    2048: D_2048,
}

MAX_RING_SIZE: int = 255  # Upper bound enforced by the constraint system


__all__ = [
    "S_PRIME",
    "S_ORDER",
    "SeedPoint",
    "PaddingPoint",
    "Blinding_Base",
    "S_A",
    "S_B",
    "OMEGA_2048",
    "OMEGA_USED",
    "OMEGA",
    "SIZE",
    "D_512",
    "D_2048",
    "MAX_RING_SIZE",
]
