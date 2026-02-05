import pytest

from dot_ring import Bandersnatch, secret_from_seed
from dot_ring.vrf.ietf.ietf import IETF_VRF


@pytest.mark.parametrize(
    "seed, expected_pk, expected_sk",
    [
        (
            0,
            "5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d",
            "51c1537c18eea5c5969cb2ae45c1224cc245de5c5b8e6e25f48fb99f2786ee05",
        ),
        (
            100,
            "caf7eb70d84e27511179c83ac352f8d3e9b9661371520c54c9ad56781f374a32",
            "ad20931d3f8cee57206bc1c3e5dad50677afb9fb712217c6a980867d3a56451c",
        ),
    ],
)
def test_secret_from_seed_vectors(seed: int, expected_pk: str, expected_sk: str) -> None:
    pk, sk = secret_from_seed(seed.to_bytes(32, "little"), Bandersnatch)
    assert pk.hex() == expected_pk
    assert sk.hex() == expected_sk


def test_secret_from_seed_public_key_roundtrip() -> None:
    seed = (2**32 - 1).to_bytes(32, "little")
    pk, sk = secret_from_seed(seed, Bandersnatch)
    assert pk == IETF_VRF[Bandersnatch].get_public_key(sk)


def test_secret_from_seed_type_errors() -> None:
    with pytest.raises(TypeError):
        secret_from_seed("not-bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        secret_from_seed(b"\x00" * 32, "not-a-curve")  # type: ignore[arg-type]
