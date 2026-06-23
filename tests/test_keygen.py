import pytest

from dot_ring import Bandersnatch


@pytest.mark.parametrize(
    "seed, expected_pk, expected_sk",
    [
        (
            0,
            "dff68d8158281c3ee65e678d75c7f5c007de51d0c3a800675208b7c61d2e6f98",
            "cc1a43aef9a710b8def623da1eae8f35d7992f46302c08242e0a2bb823ccac08",
        ),
        (
            100,
            "84c569f6371c182164b6ca1b94097274c7071d3a005050df39c14275f60b01cf",
            "0d28a81b0a4b8d197c7c10d60472d9ab9c5b7743803c4b68dc1a274d34009104",
        ),
    ],
)
def test_secret_from_seed_vectors(seed: int, expected_pk: str, expected_sk: str) -> None:
    pk, sk = Bandersnatch.secret_from_seed(seed.to_bytes(32, "little"))
    assert pk.hex() == expected_pk
    assert sk.hex() == expected_sk


def test_secret_from_seed_public_key_roundtrip() -> None:
    seed = (2**32 - 1).to_bytes(32, "little")
    pk, sk = Bandersnatch.secret_from_seed(seed)
    assert pk == Bandersnatch.public_key_from_secret(sk)


def test_secret_from_seed_type_errors() -> None:
    with pytest.raises(TypeError):
        Bandersnatch.secret_from_seed("not-bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Bandersnatch.public_key_from_secret("not-bytes")  # type: ignore[arg-type]
