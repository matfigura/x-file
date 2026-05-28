"""
Tests for filelock.crypto
 
Test philosophy:
  - Test behaviour, not implementation
  - Every public function has a happy-path test
  - Every security property has a dedicated negative test
  - "If I change one byte, decryption MUST fail" is tested explicitly
  - Tests are documentation: names explain the invariant being verified
 
Run with:
    pip install -e ".[dev]"
    pytest tests/ -v --tb=short
"""
 
import os
import secrets
 
import pytest
 
from xfile.crypto import (
    NONCE_SIZE,
    SALT_SIZE,
    DEK_SIZE,
    KEK_SIZE,
    WRAPPED_DEK_SIZE,
    DecryptionError,
    KDFParams,
    EncryptionArtifacts,
    derive_kek,
    new_kdf_params,
    generate_dek,
    wrap_dek,
    unwrap_dek,
    encrypt_data,
    decrypt_data,
    encrypt_file_data,
    decrypt_file_data,
)
 
 
# ---------------------------------------------------------------------------
# Fixtures — reusable test data
# ---------------------------------------------------------------------------
 
@pytest.fixture
def password() -> str:
    return "correct-horse-battery-staple"
 
@pytest.fixture
def kdf_params() -> KDFParams:
    return new_kdf_params()
 
@pytest.fixture
def kek(password, kdf_params) -> bytes:
    return derive_kek(password, kdf_params)
 
@pytest.fixture
def dek() -> bytes:
    return generate_dek()
 
@pytest.fixture
def data_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)
 
@pytest.fixture
def sample_plaintext() -> bytes:
    return b"The quick brown fox jumps over the lazy dog"
 
@pytest.fixture
def sample_aad() -> bytes:
    # Simulates what format.py will produce: serialized header metadata
    return b"\x01\x00filelock" + secrets.token_bytes(16)
 
 
# ---------------------------------------------------------------------------
# KDF tests
# ---------------------------------------------------------------------------
 
class TestDeriveKek:
    def test_produces_correct_length(self, password, kdf_params):
        kek = derive_kek(password, kdf_params)
        assert len(kek) == KEK_SIZE, f"KEK must be {KEK_SIZE} bytes"
 
    def test_deterministic_same_inputs(self, password, kdf_params):
        """Same password + same params MUST produce same KEK (needed for decryption)."""
        kek1 = derive_kek(password, kdf_params)
        kek2 = derive_kek(password, kdf_params)
        assert kek1 == kek2
 
    def test_different_passwords_produce_different_keks(self, kdf_params):
        kek1 = derive_kek("password-one", kdf_params)
        kek2 = derive_kek("password-two", kdf_params)
        assert kek1 != kek2
 
    def test_different_salts_produce_different_keks(self, password):
        """Same password, different salt → different KEK. This is the point of the salt."""
        params1 = new_kdf_params()
        params2 = new_kdf_params()
        # Extremely unlikely to collide, but check anyway
        assert params1.salt != params2.salt
        kek1 = derive_kek(password, params1)
        kek2 = derive_kek(password, params2)
        assert kek1 != kek2
 
    def test_accepts_bytes_password(self, kdf_params):
        """derive_kek must accept bytes as well as str."""
        kek = derive_kek(b"bytes-password", kdf_params)
        assert len(kek) == KEK_SIZE
 
    def test_str_and_utf8_bytes_equivalent(self, kdf_params):
        """str password must produce same result as its UTF-8 encoding."""
        password_str = "héllo"  # non-ASCII to catch encoding bugs
        password_bytes = password_str.encode("utf-8")
        kek_str = derive_kek(password_str, kdf_params)
        kek_bytes = derive_kek(password_bytes, kdf_params)
        assert kek_str == kek_bytes
 
    def test_output_looks_random(self, password, kdf_params):
        """Basic sanity check: KEK should not be all zeros or trivially weak."""
        kek = derive_kek(password, kdf_params)
        assert kek != b"\x00" * KEK_SIZE
        assert len(set(kek)) > 4  # at least 5 distinct byte values
 
 
class TestNewKdfParams:
    def test_salt_length(self):
        params = new_kdf_params()
        assert len(params.salt) == SALT_SIZE
 
    def test_salts_are_unique(self):
        """Each call MUST produce a unique salt."""
        salts = {new_kdf_params().salt for _ in range(20)}
        assert len(salts) == 20, "Salt collision — CSPRNG failure or salt too short"
 
    def test_default_params_are_set(self):
        params = new_kdf_params()
        # These are the minimums — if someone weakens them, this test catches it
        assert params.time_cost >= 2
        assert params.memory_kib >= 19456  # OWASP minimum: 19 MiB
        assert params.parallelism >= 1
 
 
# ---------------------------------------------------------------------------
# DEK tests
# ---------------------------------------------------------------------------
 
class TestGenerateDek:
    def test_correct_length(self):
        assert len(generate_dek()) == DEK_SIZE
 
    def test_uniqueness(self):
        deks = {generate_dek() for _ in range(50)}
        assert len(deks) == 50, "DEK collision — should never happen with CSPRNG"
 
 
# ---------------------------------------------------------------------------
# Key wrapping tests
# ---------------------------------------------------------------------------
 
class TestWrapUnwrapDek:
    def test_roundtrip(self, dek, kek):
        wrapped, nonce = wrap_dek(dek, kek)
        recovered = unwrap_dek(wrapped, nonce, kek)
        assert recovered == dek
 
    def test_wrapped_dek_correct_size(self, dek, kek):
        wrapped, nonce = wrap_dek(dek, kek)
        assert len(wrapped) == WRAPPED_DEK_SIZE
        assert len(nonce) == NONCE_SIZE
 
    def test_wrong_kek_raises_decryption_error(self, dek, kek):
        wrapped, nonce = wrap_dek(dek, kek)
        wrong_kek = secrets.token_bytes(KEK_SIZE)
        with pytest.raises(DecryptionError):
            unwrap_dek(wrapped, nonce, wrong_kek)
 
    def test_wrong_nonce_raises_decryption_error(self, dek, kek):
        wrapped, _ = wrap_dek(dek, kek)
        wrong_nonce = os.urandom(NONCE_SIZE)
        with pytest.raises(DecryptionError):
            unwrap_dek(wrapped, wrong_nonce, kek)
 
    def test_bit_flip_in_wrapped_dek_raises_decryption_error(self, dek, kek):
        """
        This is a CRITICAL security test.
        Modifying even one byte of the wrapped DEK must cause authentication failure.
        If this test fails, the authentication layer is broken.
        """
        wrapped, nonce = wrap_dek(dek, kek)
 
        # Flip one bit in the middle of the wrapped DEK
        pos = len(wrapped) // 2
        corrupted = bytearray(wrapped)
        corrupted[pos] ^= 0x01  # XOR with 1 = flip lowest bit
 
        with pytest.raises(DecryptionError):
            unwrap_dek(bytes(corrupted), nonce, kek)
 
    def test_truncated_wrapped_dek_raises(self, dek, kek):
        wrapped, nonce = wrap_dek(dek, kek)
        with pytest.raises((DecryptionError, Exception)):
            unwrap_dek(wrapped[:-1], nonce, kek)  # truncated by 1 byte
 
    def test_wrap_dek_wrong_dek_size_raises(self, kek):
        with pytest.raises(ValueError):
            wrap_dek(b"too-short", kek)
 
    def test_wrap_dek_wrong_kek_size_raises(self, dek):
        with pytest.raises(ValueError):
            wrap_dek(dek, b"too-short")
 
 
# ---------------------------------------------------------------------------
# Data encryption tests
# ---------------------------------------------------------------------------
 
class TestEncryptDecryptData:
    def test_roundtrip(self, dek, data_nonce, sample_plaintext, sample_aad):
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        pt = decrypt_data(ct, dek, data_nonce, sample_aad)
        assert pt == sample_plaintext
 
    def test_ciphertext_differs_from_plaintext(self, dek, data_nonce, sample_plaintext, sample_aad):
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        assert ct != sample_plaintext
 
    def test_ciphertext_longer_than_plaintext_by_tag_size(self, dek, data_nonce, sample_plaintext, sample_aad):
        """Poly1305 tag is always exactly 16 bytes."""
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        assert len(ct) == len(sample_plaintext) + 16
 
    def test_same_inputs_same_ciphertext(self, dek, data_nonce, sample_plaintext, sample_aad):
        """XChaCha20-Poly1305 is deterministic given the same inputs. Nonce reuse is the bug, not this."""
        ct1 = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        ct2 = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        assert ct1 == ct2
 
    def test_different_nonces_produce_different_ciphertext(self, dek, sample_plaintext, sample_aad):
        """Different nonces → different ciphertext (even same plaintext + same DEK)."""
        nonce1 = os.urandom(NONCE_SIZE)
        nonce2 = os.urandom(NONCE_SIZE)
        ct1 = encrypt_data(sample_plaintext, dek, nonce1, sample_aad)
        ct2 = encrypt_data(sample_plaintext, dek, nonce2, sample_aad)
        assert ct1 != ct2
 
    def test_wrong_dek_raises_decryption_error(self, dek, data_nonce, sample_plaintext, sample_aad):
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        wrong_dek = secrets.token_bytes(DEK_SIZE)
        with pytest.raises(DecryptionError):
            decrypt_data(ct, wrong_dek, data_nonce, sample_aad)
 
    def test_wrong_nonce_raises_decryption_error(self, dek, data_nonce, sample_plaintext, sample_aad):
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        wrong_nonce = os.urandom(NONCE_SIZE)
        with pytest.raises(DecryptionError):
            decrypt_data(ct, dek, wrong_nonce, sample_aad)
 
    def test_modified_aad_raises_decryption_error(self, dek, data_nonce, sample_plaintext, sample_aad):
        """
        CRITICAL: AAD is authenticated. Changing even one byte of AAD must break decryption.
        This is the entire point of AAD — it binds ciphertext to its metadata.
        """
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        tampered_aad = bytearray(sample_aad)
        tampered_aad[0] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt_data(ct, dek, data_nonce, bytes(tampered_aad))
 
    def test_empty_aad_works(self, dek, data_nonce, sample_plaintext):
        """Empty AAD is valid (though we don't recommend it in production)."""
        ct = encrypt_data(sample_plaintext, dek, data_nonce, b"")
        pt = decrypt_data(ct, dek, data_nonce, b"")
        assert pt == sample_plaintext
 
    def test_empty_plaintext_works(self, dek, data_nonce, sample_aad):
        """Empty file should encrypt/decrypt correctly."""
        ct = encrypt_data(b"", dek, data_nonce, sample_aad)
        pt = decrypt_data(ct, dek, data_nonce, sample_aad)
        assert pt == b""
 
    def test_single_bit_flip_in_ciphertext_raises(self, dek, data_nonce, sample_plaintext, sample_aad):
        """
        CRITICAL SECURITY TEST.
        This verifies the AEAD authentication property:
        any modification to the ciphertext MUST be detected.
 
        If this test passes silently (no exception), the authentication is broken
        and the cipher is not providing integrity guarantees.
        """
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
 
        for flip_pos in [0, len(ct) // 2, len(ct) - 1]:
            corrupted = bytearray(ct)
            corrupted[flip_pos] ^= 0x01
            with pytest.raises(DecryptionError, match="corrupted"):
                decrypt_data(bytes(corrupted), dek, data_nonce, sample_aad)
 
    def test_truncated_ciphertext_raises(self, dek, data_nonce, sample_plaintext, sample_aad):
        ct = encrypt_data(sample_plaintext, dek, data_nonce, sample_aad)
        with pytest.raises((DecryptionError, Exception)):
            decrypt_data(ct[:-1], dek, data_nonce, sample_aad)
 
    def test_large_file(self, dek, data_nonce, sample_aad):
        """Sanity check for larger payloads — not a streaming test, just correctness."""
        large_plaintext = secrets.token_bytes(1024 * 1024)  # 1 MiB
        ct = encrypt_data(large_plaintext, dek, data_nonce, sample_aad)
        pt = decrypt_data(ct, dek, data_nonce, sample_aad)
        assert pt == large_plaintext
 
 
# ---------------------------------------------------------------------------
# Full pipeline tests (encrypt_file_data / decrypt_file_data)
# ---------------------------------------------------------------------------
 
class TestFullPipeline:
    def test_roundtrip(self, password, sample_plaintext, sample_aad):
        artifacts = encrypt_file_data(sample_plaintext, password, sample_aad)
        plaintext = decrypt_file_data(artifacts, password, sample_aad)
        assert plaintext == sample_plaintext
 
    def test_wrong_password_raises_decryption_error(self, password, sample_plaintext, sample_aad):
        artifacts = encrypt_file_data(sample_plaintext, password, sample_aad)
        with pytest.raises(DecryptionError):
            decrypt_file_data(artifacts, "wrong-password", sample_aad)
 
    def test_tampered_aad_raises_decryption_error(self, password, sample_plaintext, sample_aad):
        artifacts = encrypt_file_data(sample_plaintext, password, sample_aad)
        tampered_aad = sample_aad[:-1] + bytes([sample_aad[-1] ^ 0x01])
        with pytest.raises(DecryptionError):
            decrypt_file_data(artifacts, password, tampered_aad)
 
    def test_tampered_ciphertext_raises_decryption_error(self, password, sample_plaintext, sample_aad):
        artifacts = encrypt_file_data(sample_plaintext, password, sample_aad)
        corrupted = bytearray(artifacts.ciphertext)
        corrupted[0] ^= 0xFF
        bad_artifacts = EncryptionArtifacts(
            kdf_params=artifacts.kdf_params,
            wrapped_dek=artifacts.wrapped_dek,
            wrap_nonce=artifacts.wrap_nonce,
            data_nonce=artifacts.data_nonce,
            ciphertext=bytes(corrupted),
        )
        with pytest.raises(DecryptionError):
            decrypt_file_data(bad_artifacts, password, sample_aad)
 
    def test_tampered_wrapped_dek_raises_decryption_error(self, password, sample_plaintext, sample_aad):
        artifacts = encrypt_file_data(sample_plaintext, password, sample_aad)
        corrupted_wrapped_dek = bytearray(artifacts.wrapped_dek)
        corrupted_wrapped_dek[0] ^= 0xFF
        bad_artifacts = EncryptionArtifacts(
            kdf_params=artifacts.kdf_params,
            wrapped_dek=bytes(corrupted_wrapped_dek),
            wrap_nonce=artifacts.wrap_nonce,
            data_nonce=artifacts.data_nonce,
            ciphertext=artifacts.ciphertext,
        )
        with pytest.raises(DecryptionError):
            decrypt_file_data(bad_artifacts, password, sample_aad)
 
    def test_each_encryption_produces_different_ciphertext(self, password, sample_plaintext, sample_aad):
        """
        Two encryptions of the same plaintext with same password MUST produce different output.
        This verifies that salt and nonces are truly randomized each time.
        If this fails, nonce/salt generation is broken — catastrophic security bug.
        """
        art1 = encrypt_file_data(sample_plaintext, password, sample_aad)
        art2 = encrypt_file_data(sample_plaintext, password, sample_aad)
        assert art1.kdf_params.salt != art2.kdf_params.salt
        assert art1.data_nonce != art2.data_nonce
        assert art1.ciphertext != art2.ciphertext
 
    def test_empty_password_works(self, sample_plaintext, sample_aad):
        """Empty string is a valid (if terrible) password. Don't crash — just work."""
        artifacts = encrypt_file_data(sample_plaintext, "", sample_aad)
        pt = decrypt_file_data(artifacts, "", sample_aad)
        assert pt == sample_plaintext
 
    def test_unicode_password(self, sample_plaintext, sample_aad):
        """Non-ASCII passwords must work correctly."""
        password = "żółć_gęśl🔑"
        artifacts = encrypt_file_data(sample_plaintext, password, sample_aad)
        pt = decrypt_file_data(artifacts, password, sample_aad)
        assert pt == sample_plaintext
 
    def test_artifacts_contain_no_plaintext_dek(self, password, sample_plaintext, sample_aad):
        """
        Sanity check: the raw DEK must NOT appear anywhere in the artifacts.
        This would indicate a serious key management bug.
        """
        artifacts = encrypt_file_data(sample_plaintext, password, sample_aad)
        # We can't easily extract the DEK without decrypting, but we can verify
        # the wrapped_dek is different from a raw 32-byte key (it should be 48 bytes)
        assert len(artifacts.wrapped_dek) == 48  # DEK_SIZE + 16-byte tag