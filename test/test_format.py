import pytest

from xfile.crypto import (
    EncryptionArtifacts,
    KDFParams,
    SALT_SIZE,
    NONCE_SIZE,
    WRAPPED_DEK_SIZE,
)

from xfile.format import (
    HEADER_STRUCT,
    VERSION,
    FormatError,
    serialize,
    deserialize,
)


@pytest.fixture
def sample_artifacts() -> EncryptionArtifacts:
    return EncryptionArtifacts(
        kdf_params=KDFParams(
            salt=b"s" * SALT_SIZE,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        ),
        wrapped_dek=b"w" * WRAPPED_DEK_SIZE,
        wrap_nonce=b"n" * NONCE_SIZE,
        data_nonce=b"d" * NONCE_SIZE,
        ciphertext=b"encrypted file content",
    )


def test_serialize_and_deserialize_roundtrip(sample_artifacts):
    serialized = serialize(sample_artifacts)
    deserialized = deserialize(serialized)

    assert deserialized == sample_artifacts


def test_serialize_adds_header_before_ciphertext(sample_artifacts):
    serialized = serialize(sample_artifacts)

    assert len(serialized) == HEADER_STRUCT.size + len(sample_artifacts.ciphertext)
    assert serialized.endswith(sample_artifacts.ciphertext)


def test_deserialize_too_short_data_raises_format_error():
    with pytest.raises(FormatError, match="File too short"):
        deserialize(b"too short")


def test_deserialize_invalid_magic_raises_format_error(sample_artifacts):
    serialized = bytearray(serialize(sample_artifacts))

    serialized[0:5] = b"BAD!!"

    with pytest.raises(FormatError, match="Invalid file magic"):
        deserialize(bytes(serialized))


def test_deserialize_unsupported_version_raises_format_error(sample_artifacts):
    serialized = bytearray(serialize(sample_artifacts))

    version_index = 5
    serialized[version_index] = VERSION + 1

    with pytest.raises(FormatError, match="Unsupported version"):
        deserialize(bytes(serialized))


def test_deserialize_allows_empty_ciphertext():
    artifacts = EncryptionArtifacts(
        kdf_params=KDFParams(
            salt=b"s" * SALT_SIZE,
            time_cost=1,
            memory_kib=8192,
            parallelism=1,
        ),
        wrapped_dek=b"w" * WRAPPED_DEK_SIZE,
        wrap_nonce=b"n" * NONCE_SIZE,
        data_nonce=b"d" * NONCE_SIZE,
        ciphertext=b"",
    )

    serialized = serialize(artifacts)
    deserialized = deserialize(serialized)

    assert deserialized.ciphertext == b""
    assert deserialized == artifacts