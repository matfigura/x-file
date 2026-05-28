from __future__ import annotations

import struct

from xfile.crypto import (
    EncryptionArtifacts,
    KDFParams,
    SALT_SIZE,
    NONCE_SIZE,
    WRAPPED_DEK_SIZE,
)

MAGIC = b"XFILE"
VERSION = 1

HEADER_STRUCT = struct.Struct(">5sBIII16s12s12s48s")
# magic, version, time_cost, memory_kib, parallelism,
# salt, wrap_nonce, data_nonce, wrapped_dek


class FormatError(Exception):
    """Raised when .enc file format is invalid."""


def serialize(artifacts: EncryptionArtifacts) -> bytes:
    header = HEADER_STRUCT.pack(
        MAGIC,
        VERSION,
        artifacts.kdf_params.time_cost,
        artifacts.kdf_params.memory_kib,
        artifacts.kdf_params.parallelism,
        artifacts.kdf_params.salt,
        artifacts.wrap_nonce,
        artifacts.data_nonce,
        artifacts.wrapped_dek,
    )

    return header + artifacts.ciphertext


def deserialize(data: bytes) -> EncryptionArtifacts:
    if len(data) < HEADER_STRUCT.size:
        raise FormatError("File too short")

    header = data[:HEADER_STRUCT.size]
    ciphertext = data[HEADER_STRUCT.size:]

    (
        magic,
        version,
        time_cost,
        memory_kib,
        parallelism,
        salt,
        wrap_nonce,
        data_nonce,
        wrapped_dek,
    ) = HEADER_STRUCT.unpack(header)

    if magic != MAGIC:
        raise FormatError("Invalid file magic")

    if version != VERSION:
        raise FormatError(f"Unsupported version: {version}")

    if len(salt) != SALT_SIZE:
        raise FormatError("Invalid salt size")

    if len(wrap_nonce) != NONCE_SIZE:
        raise FormatError("Invalid wrap nonce size")

    if len(data_nonce) != NONCE_SIZE:
        raise FormatError("Invalid data nonce size")

    if len(wrapped_dek) != WRAPPED_DEK_SIZE:
        raise FormatError("Invalid wrapped DEK size")

    return EncryptionArtifacts(
        kdf_params=KDFParams(
            salt=salt,
            time_cost=time_cost,
            memory_kib=memory_kib,
            parallelism=parallelism,
        ),
        wrapped_dek=wrapped_dek,
        wrap_nonce=wrap_nonce,
        data_nonce=data_nonce,
        ciphertext=ciphertext,
    )