from hashlib import sha256, sha512, shake_256, sha384


def sha512(data: bytes) -> bytes:
    """SHA512 hash function"""
    if not isinstance(data, bytes):
        data = bytes(data)
    return sha512(data).digest()

def sha256(data: bytes) -> bytes:
    """SHA512 hash function"""
    if not isinstance(data, bytes):
        data = bytes(data)
    return sha256(data).digest()

def sha384(data: bytes) -> bytes:
    """SHA512 hash function"""
    if not isinstance(data, bytes):
        data = bytes(data)
    return sha384(data).digest()

def shake256(data: bytes, len_in_bytes: int = 64) -> bytes:
    """SHA512 hash function"""
    if not isinstance(data, bytes):
        data = bytes(data)
    shake = shake_256()
    shake.update(data)
    return shake.digest(len_in_bytes)
