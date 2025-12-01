from hashlib import shake_256


def shake256(data: bytes, len_in_bytes: int = 64) -> bytes:
    """SHA512 hash function"""
    if not isinstance(data, bytes):
        data = bytes(data)
    shake = shake_256()
    shake.update(data)
    return shake.digest(len_in_bytes)
