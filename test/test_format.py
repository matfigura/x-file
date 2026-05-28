import pytest

from xfile.crypto import encrypt_file_data, decrypt_file_data
from xfile.format import serialize, deserialize, FormatError


def test_format_roundtrip():
    password = "tajne-haslo"
    aad = b"xfile-v1"
    plaintext = b"Hello encrypted file!"

    artifacts = encrypt_file_data(plaintext, password, aad)
    encoded = serialize(artifacts)
    decoded = deserialize(encoded)

    recovered = decrypt_file_data(decoded, password, aad)

    assert recovered == plaintext


def test_invalid_magic_raises():
    password = "tajne-haslo"
    aad = b"xfile-v1"
    plaintext = b"Hello encrypted file!"

    artifacts = encrypt_file_data(plaintext, password, aad)
    encoded = bytearray(serialize(artifacts))

    encoded[0] = 0x00

    with pytest.raises(FormatError):
        deserialize(bytes(encoded))