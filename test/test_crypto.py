import pytest

from xfile import crypto
from xfile.crypto import (
    KDFParams,
    KEK_SIZE,
    DEK_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    WRAPPED_DEK_SIZE,
    DecryptionError,
    derive_kek,
    generate_dek,
    wrap_dek,
    unwrap_dek,
    encrypt_data,
    decrypt_data,
)


@pytest.fixture
def fast_kdf_params() -> KDFParams:
    """
    Szybsze parametry Argon2id do testów.

    W normalnym kodzie używamy mocniejszych parametrów,
    ale w testach nie chcemy czekać zbyt długo.
    """
    return KDFParams(
        salt=b"\x01" * SALT_SIZE,
        time_cost=1,
        memory_kib=8192,
        parallelism=1,
    )


def test_derive_kek_is_deterministic_for_same_password_and_params(fast_kdf_params):
    password = "test-password"

    kek_1 = derive_kek(password, fast_kdf_params)
    kek_2 = derive_kek(password, fast_kdf_params)

    assert len(kek_1) == KEK_SIZE
    assert kek_1 == kek_2


def test_generate_dek_returns_32_random_bytes():
    dek_1 = generate_dek()
    dek_2 = generate_dek()

    assert len(dek_1) == DEK_SIZE
    assert len(dek_2) == DEK_SIZE
    assert dek_1 != dek_2


def test_wrap_and_unwrap_dek_roundtrip():
    dek = b"a" * DEK_SIZE
    kek = b"b" * KEK_SIZE

    wrapped_dek, wrap_nonce = wrap_dek(dek, kek)
    unwrapped_dek = unwrap_dek(wrapped_dek, wrap_nonce, kek)

    assert len(wrap_nonce) == NONCE_SIZE
    assert len(wrapped_dek) == WRAPPED_DEK_SIZE
    assert unwrapped_dek == dek


def test_wrap_dek_rejects_invalid_dek_size():
    invalid_dek = b"short"
    kek = b"b" * KEK_SIZE

    with pytest.raises(ValueError):
        wrap_dek(invalid_dek, kek)


def test_wrap_dek_rejects_invalid_kek_size():
    dek = b"a" * DEK_SIZE
    invalid_kek = b"short"

    with pytest.raises(ValueError):
        wrap_dek(dek, invalid_kek)


def test_unwrap_dek_with_wrong_kek_raises_decryption_error():
    dek = b"a" * DEK_SIZE
    correct_kek = b"b" * KEK_SIZE
    wrong_kek = b"c" * KEK_SIZE

    wrapped_dek, wrap_nonce = wrap_dek(dek, correct_kek)

    with pytest.raises(DecryptionError):
        unwrap_dek(wrapped_dek, wrap_nonce, wrong_kek)


def test_encrypt_and_decrypt_data_roundtrip():
    plaintext = b"Very secret test message"
    dek = b"a" * DEK_SIZE
    data_nonce = b"n" * NONCE_SIZE
    aad = b"test-header"

    ciphertext = encrypt_data(plaintext, dek, data_nonce, aad)
    decrypted = decrypt_data(ciphertext, dek, data_nonce, aad)

    assert ciphertext != plaintext
    assert decrypted == plaintext


def test_decrypt_data_with_wrong_aad_raises_decryption_error():
    plaintext = b"Very secret test message"
    dek = b"a" * DEK_SIZE
    data_nonce = b"n" * NONCE_SIZE

    ciphertext = encrypt_data(
        plaintext=plaintext,
        dek=dek,
        data_nonce=data_nonce,
        aad=b"correct-aad",
    )

    with pytest.raises(DecryptionError):
        decrypt_data(
            ciphertext=ciphertext,
            dek=dek,
            data_nonce=data_nonce,
            aad=b"wrong-aad",
        )


def test_decrypt_data_with_tampered_ciphertext_raises_decryption_error():
    plaintext = b"Very secret test message"
    dek = b"a" * DEK_SIZE
    data_nonce = b"n" * NONCE_SIZE
    aad = b"test-header"

    ciphertext = encrypt_data(plaintext, dek, data_nonce, aad)

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 1

    with pytest.raises(DecryptionError):
        decrypt_data(bytes(tampered_ciphertext), dek, data_nonce, aad)


def test_encrypt_file_data_and_decrypt_file_data_roundtrip(monkeypatch, fast_kdf_params):
    monkeypatch.setattr(crypto, "new_kdf_params", lambda: fast_kdf_params)

    plaintext = b"Example file content"
    password = "correct-password"
    aad = b"example.txt"

    artifacts = crypto.encrypt_file_data(plaintext, password, aad)
    decrypted = crypto.decrypt_file_data(artifacts, password, aad)

    assert decrypted == plaintext


def test_decrypt_file_data_with_wrong_password_raises_decryption_error(
    monkeypatch,
    fast_kdf_params,
):
    monkeypatch.setattr(crypto, "new_kdf_params", lambda: fast_kdf_params)

    plaintext = b"Example file content"
    aad = b"example.txt"

    artifacts = crypto.encrypt_file_data(
        plaintext=plaintext,
        password="correct-password",
        aad=aad,
    )

    with pytest.raises(DecryptionError):
        crypto.decrypt_file_data(
            artifacts=artifacts,
            password="wrong-password",
            aad=aad,
        )


def test_decrypt_file_data_with_wrong_aad_raises_decryption_error(
    monkeypatch,
    fast_kdf_params,
):
    monkeypatch.setattr(crypto, "new_kdf_params", lambda: fast_kdf_params)

    plaintext = b"Example file content"

    artifacts = crypto.encrypt_file_data(
        plaintext=plaintext,
        password="correct-password",
        aad=b"original-file-name.txt",
    )

    with pytest.raises(DecryptionError):
        crypto.decrypt_file_data(
            artifacts=artifacts,
            password="correct-password",
            aad=b"different-file-name.txt",
        )