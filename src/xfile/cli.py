from __future__ import annotations

import argparse
from getpass import getpass
from pathlib import Path

from xfile.crypto import encrypt_file_data, decrypt_file_data, DecryptionError
from xfile.format import serialize, deserialize, FormatError

AAD = b"xfile-v1"


def encrypt_command(input_path: Path, output_path: Path) -> None:
    password = getpass("Password: ")

    plaintext = input_path.read_bytes()
    artifacts = encrypt_file_data(plaintext, password, AAD)
    encrypted = serialize(artifacts)

    output_path.write_bytes(encrypted)

    print(f"Encrypted: {input_path} -> {output_path}")


def decrypt_command(input_path: Path, output_path: Path) -> None:
    password = getpass("Password: ")

    encrypted = input_path.read_bytes()
    artifacts = deserialize(encrypted)
    plaintext = decrypt_file_data(artifacts, password, AAD)

    output_path.write_bytes(plaintext)

    print(f"Decrypted: {input_path} -> {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="xfile")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt")
    encrypt_parser.add_argument("input", type=Path)
    encrypt_parser.add_argument("output", type=Path)

    decrypt_parser = subparsers.add_parser("decrypt")
    decrypt_parser.add_argument("input", type=Path)
    decrypt_parser.add_argument("output", type=Path)

    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            encrypt_command(args.input, args.output)
        elif args.command == "decrypt":
            decrypt_command(args.input, args.output)
    except DecryptionError:
        print("Decryption failed: wrong password or corrupted file")
    except FormatError as exc:
        print(f"Invalid file format: {exc}")


if __name__ == "__main__":
    main()