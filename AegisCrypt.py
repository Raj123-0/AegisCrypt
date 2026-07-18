import argparse
import base64
import os
import sys
from pathlib import Path
from textwrap import dedent

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"CX"
VERSION = 2
LEGACY_MAGIC = b"CX2"
NONCE_LEN = 12
SALT_LEN = 16
DEFAULT_ITERATIONS = 200_000
KEY_LEN = 32


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def print_banner() -> None:
    print("\n" + "=" * 78)
    print(" CipherX — runtime-only authenticated encryption")
    print(" Key stays out of source and is only requested at runtime.")
    print("=" * 78)


def prompt_secret(prompt: str = "Secret key: ") -> str:
    print(prompt, end="", flush=True)
    return input()


def resolve_key(key: str | None, key_file: str | None, key_env: str | None = None) -> str:
    provided_sources = [key is not None, key_file is not None, key_env is not None]
    if sum(provided_sources) > 1:
        raise ValueError("Provide only one of: key, --key-file, or --key-env.")

    if key_file:
        path = Path(key_file)
        if not path.exists():
            raise ValueError(f"Key file does not exist: {key_file}")
        return path.read_text(encoding="utf-8").strip()

    if key_env:
        if key_env not in os.environ:
            raise ValueError(f"Environment variable is not set: {key_env}")
        return os.environ[key_env]

    if key is None:
        return prompt_secret("Enter secret key: ")

    return key


def _parse_blob(blob: bytes):
    if blob.startswith(MAGIC):
        if len(blob) < 2 + 1 + 4 + SALT_LEN + NONCE_LEN + 16:
            raise ValueError("Ciphertext is too short.")

        version = blob[2]
        if version != VERSION:
            raise ValueError(f"Unsupported CipherX version: {version}")

        iterations = int.from_bytes(blob[3:7], "big")
        salt = blob[7:7 + SALT_LEN]
        nonce = blob[7 + SALT_LEN:7 + SALT_LEN + NONCE_LEN]
        ciphertext = blob[7 + SALT_LEN + NONCE_LEN:]
        return iterations, salt, nonce, ciphertext

    if blob.startswith(LEGACY_MAGIC):
        if len(blob) < len(LEGACY_MAGIC) + SALT_LEN + NONCE_LEN + 16:
            raise ValueError("Ciphertext is too short.")

        salt = blob[len(LEGACY_MAGIC):len(LEGACY_MAGIC) + SALT_LEN]
        nonce = blob[len(LEGACY_MAGIC) + SALT_LEN:len(LEGACY_MAGIC) + SALT_LEN + NONCE_LEN]
        ciphertext = blob[len(LEGACY_MAGIC) + SALT_LEN + NONCE_LEN:]
        return DEFAULT_ITERATIONS, salt, nonce, ciphertext

    raise ValueError("Ciphertext is not a valid CipherX blob.")


def encrypt(message: str, key: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    if iterations < 1000:
        raise ValueError("Iterations must be at least 1000 for a secure KDF.")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    aes_key = derive_key(key, salt, iterations)
    aesgcm = AESGCM(aes_key)

    plaintext = message.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    blob = MAGIC + bytes([VERSION]) + iterations.to_bytes(4, "big") + salt + nonce + ciphertext
    return base64.b64encode(blob).decode("ascii")


def decrypt(ciphertext_b64: str, key: str) -> str:
    try:
        blob = base64.b64decode(ciphertext_b64)
    except Exception as exc:
        raise ValueError("Ciphertext is not valid - check you copied it correctly.") from exc

    iterations, salt, nonce, ciphertext = _parse_blob(blob)
    aes_key = derive_key(key, salt, iterations)
    aesgcm = AESGCM(aes_key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Incorrect key or corrupted ciphertext.") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Incorrect key - decrypted data is not valid text.") from exc


# ---------- Interactive menu (loops so you can process many messages) ----------
def interactive_menu():
    print_banner()
    while True:
        print("\n[1] Encode a message")
        print("[2] Decode a message")
        print("[3] Exit")
        choice = input("Select an option: ").strip()

        if choice == '1':
            msg = input("Message to encode: ")
            key = prompt_secret("Secret key: ")
            print(f"\nEncoded output:\n{encrypt(msg, key)}")

        elif choice == '2':
            ct = input("Ciphertext to decode: ").strip()
            key = prompt_secret("Secret key: ")
            try:
                print(f"\nDecoded output:\n{decrypt(ct, key)}")
            except ValueError as e:
                print(f"\nDecode failed: {e}")

        elif choice == '3':
            print("\nGoodbye.")
            break

        else:
            print("Invalid option — choose 1, 2, or 3.")


# ---------- Command-line interface ----------
def main():
    parser = argparse.ArgumentParser(
        description=dedent(
            """
            CipherX — a cryptographically strong symmetric cipher.

            Recommended usage:
              - pass a key directly only for one-off testing
              - prefer --key-file or --key-env for runtime secret isolation
              - use the menu mode for a cleaner interactive session
            """
        ).strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode")

    encode_parser = subparsers.add_parser(
        "encode",
        help="Encode a message with a runtime-only secret key",
    )
    encode_parser.add_argument("message", help="The plaintext message to encode")
    encode_parser.add_argument("key", nargs="?", help="The key to encode with")
    encode_parser.add_argument("--key-file", help="Path to a file containing the key")
    encode_parser.add_argument(
        "--key-env",
        default=None,
        help="Name of the environment variable containing the key",
    )
    encode_parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iteration count (default: {DEFAULT_ITERATIONS})",
    )

    decode_parser = subparsers.add_parser(
        "decode",
        help="Decode a ciphertext with a runtime-only secret key",
    )
    decode_parser.add_argument("ciphertext", help="The ciphertext (base64) to decode")
    decode_parser.add_argument("key", nargs="?", help="The key to decode with")
    decode_parser.add_argument("--key-file", help="Path to a file containing the key")
    decode_parser.add_argument(
        "--key-env",
        default=None,
        help="Name of the environment variable containing the key",
    )

    args = parser.parse_args()

    if args.mode == "encode":
        try:
            key_value = resolve_key(args.key, args.key_file, args.key_env)
            print(encrypt(args.message, key_value, iterations=args.iterations))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.mode == "decode":
        try:
            key_value = resolve_key(args.key, args.key_file, args.key_env)
            print(decrypt(args.ciphertext, key_value))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        interactive_menu()


if __name__ == "__main__":
    main()
