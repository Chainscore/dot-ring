from __future__ import annotations

from enum import IntEnum


class DomSep(IntEnum):
    TINY_VRF = 0x00
    THIN_VRF = 0x01
    PEDERSEN_VRF = 0x02
    NONCE_EXPAND = 0x10
    NONCE = 0x11
    PEDERSEN_BLINDING = 0x12
    POINT_TO_HASH = 0x20
    DELINEARIZE = 0x30
    CHALLENGE = 0x40
    BATCH_VERIFY = 0x50
    HASH_TO_CURVE = 0x60
