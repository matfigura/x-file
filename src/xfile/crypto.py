"""
filelock.crypto — cryptographic primitives for filelock.

Design constraints (do NOT relax without updating format-spec.md):
  - All randomness via os.urandom() / secrets — never random.random()
  - No custom crypto primitives — only PyCA/cryptography
  - Functions are pure bytes→bytes; no file I/O here
  - Every public function has explicit type annotations

Cipher choice note:
  Original design called for XChaCha20-Poly1305 (192-bit nonce). PyCA removed
  this in v42+ because OpenSSL's backend doesn't implement it natively.
  We use AES-256-GCM instead — equally secure, universally supported.

  AES-256-GCM nonce is 96 bits (12 bytes). With *random* nonce generation,
  the birthday-paradox collision probability becomes meaningful after ~2^48
  encryptions with the *same key*. Since we generate a fresh random DEK per
  file, each key is used for exactly ONE nonce — no collision risk whatsoever.

Threat model (Model A):
  - Protects against passive eavesdroppers on the transport channel
  - Does NOT authenticate the sender — recipient cannot verify who encrypted the file
  - Key is derived from password; weak passwords = weak security (document this!)
  - No forward secrecy — compromise of password compromises all past files
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


# ---------------------------------------------------------------------------
# Constants — changing these is a BREAKING CHANGE to the format
# ---------------------------------------------------------------------------

KEK_SIZE = 32    # Key Encryption Key: 256 bits
DEK_SIZE = 32    # Data Encryption Key: 256 bits (AES-256 requires exactly 32 bytes)
NONCE_SIZE = 12  # AES-GCM nonce: 96 bits (NIST SP 800-38D standard size)
SALT_SIZE = 16   # Argon2id salt: 128 bits (NIST SP 800-132 minimum)

# Argon2id parameters. Stored in file header, so old files remain decryptable
# if you raise these in a future version. NEVER lower them.
ARGON2_TIME_COST = 3        # passes over memory
ARGON2_MEMORY_KIB = 65536  # 64 MiB — GPU-resistant, ~0.5s on modern hardware
ARGON2_PARALLELISM = 1

# AES-GCM appends a 16-byte authentication tag unconditionally.
WRAPPED_DEK_SIZE = DEK_SIZE + 16  # 48 bytes


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DecryptionError(Exception):
    """
    Raised when decryption fails for ANY reason.

    Deliberately vague: we do NOT distinguish between wrong password,
    corrupted ciphertext, or tampered AAD. This prevents oracle attacks.
    Intentional security design.
    """


# ---------------------------------------------------------------------------
# KDF: password → KEK
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KDFParams:
    """Argon2id parameters stored in the file header."""
    salt: bytes
    time_cost: int
    memory_kib: int
    parallelism: int


def derive_kek(password: str | bytes, params: KDFParams) -> bytes:
    """
    Derive a Key Encryption Key from a password using Argon2id.

    Returns 32-byte KEK. Do NOT log, store, or serialize this value.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    kdf = Argon2id(
        salt=params.salt,
        length=KEK_SIZE,
        iterations=params.time_cost,
        lanes=params.parallelism,
        memory_cost=params.memory_kib,
    )
    return kdf.derive(password_bytes)


def new_kdf_params() -> KDFParams:
    """Generate fresh KDF parameters with a random salt for a new file."""
    return KDFParams(
        salt=os.urandom(SALT_SIZE),
        time_cost=ARGON2_TIME_COST,
        memory_kib=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
    )


# ---------------------------------------------------------------------------
# DEK management: generate, wrap, unwrap
# ---------------------------------------------------------------------------

def generate_dek() -> bytes:
    """Generate a random 256-bit Data Encryption Key. Never reuse across files."""
    return secrets.token_bytes(DEK_SIZE)


def wrap_dek(dek: bytes, kek: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt a DEK under a KEK using AES-256-GCM (key wrapping).

    Returns (wrapped_dek, wrap_nonce). Both must be stored in the file header.
    wrap_nonce is independent from the data nonce — generated separately.
    """
    if len(dek) != DEK_SIZE:
        raise ValueError(f"DEK must be {DEK_SIZE} bytes, got {len(dek)}")
    if len(kek) != KEK_SIZE:
        raise ValueError(f"KEK must be {KEK_SIZE} bytes, got {len(kek)}")

    wrap_nonce = os.urandom(NONCE_SIZE)
    cipher = AESGCM(kek)
    wrapped = cipher.encrypt(wrap_nonce, dek, associated_data=None)
    return wrapped, wrap_nonce


def unwrap_dek(wrapped_dek: bytes, wrap_nonce: bytes, kek: bytes) -> bytes:
    """
    Decrypt and authenticate a wrapped DEK.

    Raises DecryptionError if KEK is wrong or wrapped_dek was modified.
    """
    if len(wrap_nonce) != NONCE_SIZE:
        raise ValueError(f"wrap_nonce must be {NONCE_SIZE} bytes, got {len(wrap_nonce)}")

    cipher = AESGCM(kek)
    try:
        return cipher.decrypt(wrap_nonce, wrapped_dek, associated_data=None)
    except InvalidTag as exc:
        raise DecryptionError("DEK unwrap failed: wrong password or corrupted header") from exc


# ---------------------------------------------------------------------------
# Data encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_data(plaintext: bytes, dek: bytes, data_nonce: bytes, aad: bytes) -> bytes:
    """
    Encrypt plaintext bytes using AES-256-GCM.

    aad is authenticated but NOT encrypted — changes to AAD break decryption.
    Use aad to bind the ciphertext to its header metadata.

    Returns ciphertext || 16-byte GCM tag.

    Known limitation: loads entire file into memory. Streaming support deferred.
    """
    if len(dek) != DEK_SIZE:
        raise ValueError(f"DEK must be {DEK_SIZE} bytes, got {len(dek)}")
    if len(data_nonce) != NONCE_SIZE:
        raise ValueError(f"data_nonce must be {NONCE_SIZE} bytes, got {len(data_nonce)}")

    return AESGCM(dek).encrypt(data_nonce, plaintext, associated_data=aad)


def decrypt_data(ciphertext: bytes, dek: bytes, data_nonce: bytes, aad: bytes) -> bytes:
    """
    Decrypt and authenticate ciphertext using AES-256-GCM.

    AAD must EXACTLY match what was used during encryption.
    Raises DecryptionError on any authentication failure.
    """
    if len(dek) != DEK_SIZE:
        raise ValueError(f"DEK must be {DEK_SIZE} bytes, got {len(dek)}")
    if len(data_nonce) != NONCE_SIZE:
        raise ValueError(f"data_nonce must be {NONCE_SIZE} bytes, got {len(data_nonce)}")

    try:
        return AESGCM(dek).decrypt(data_nonce, ciphertext, associated_data=aad)
    except InvalidTag as exc:
        raise DecryptionError("Data decryption failed: corrupted ciphertext or wrong key") from exc


# ---------------------------------------------------------------------------
# High-level pipeline
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EncryptionArtifacts:
    """
    Everything produced by a single encrypt_file_data() call.
    All fields must be stored in the .enc file — nothing is ephemeral.
    """
    kdf_params: KDFParams
    wrapped_dek: bytes
    wrap_nonce: bytes
    data_nonce: bytes
    ciphertext: bytes


def encrypt_file_data(plaintext: bytes, password: str, aad: bytes) -> EncryptionArtifacts:
    """
    Full encryption pipeline: plaintext + password → EncryptionArtifacts.

    Step-by-step:
      1. Generate fresh Argon2id salt and parameters
      2. Derive KEK from password (slow — intentional)
      3. Generate random DEK for this file
      4. Wrap DEK under KEK (key envelope)
      5. Generate random data nonce
      6. Encrypt file data with DEK
    """
    kdf_params = new_kdf_params()
    kek = derive_kek(password, kdf_params)
    dek = generate_dek()
    wrapped_dek, wrap_nonce = wrap_dek(dek, kek)
    data_nonce = os.urandom(NONCE_SIZE)
    ciphertext = encrypt_data(plaintext, dek, data_nonce, aad)

    # DEK and KEK no longer needed.
    # NOTE: Python doesn't guarantee memory zeroing — known limitation.
    del dek, kek

    return EncryptionArtifacts(
        kdf_params=kdf_params,
        wrapped_dek=wrapped_dek,
        wrap_nonce=wrap_nonce,
        data_nonce=data_nonce,
        ciphertext=ciphertext,
    )


def decrypt_file_data(artifacts: EncryptionArtifacts, password: str, aad: bytes) -> bytes:
    """
    Full decryption pipeline: EncryptionArtifacts + password → plaintext.

    Raises DecryptionError if password is wrong, file is corrupted,
    or AAD doesn't match. All three are indistinguishable. Intentional.
    """
    kek = derive_kek(password, artifacts.kdf_params)
    dek = unwrap_dek(artifacts.wrapped_dek, artifacts.wrap_nonce, kek)
    plaintext = decrypt_data(artifacts.ciphertext, dek, artifacts.data_nonce, aad)
    del dek, kek
    return plaintext
