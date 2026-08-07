"""At-rest encryption for sensitive database columns.

Group message payloads and group private keys are encrypted before they touch
SQLite, using the AES-256-CBC + HMAC token construct that ships with RNS. This
protects a stolen database file or backup; it cannot protect a live host, since
the daemon necessarily holds the key while it runs.

Message hashes are computed over plaintext payloads, so deduplication, Merkle
roots and federation are unaffected by the choice of at-rest mode, and hubs do
not need to share an at-rest key.
"""

from __future__ import annotations

import os
from typing import Protocol

import RNS
from RNS.Cryptography import HKDF, Token

KEY_LENGTH = 64
KEY_ENV_VAR = "LXMF_HUB_DB_KEY"
HKDF_CONTEXT = b"lxmf_hub/at-rest/v1"

MODE_NONE = "none"
MODE_KEYFILE = "keyfile"
MODE_PASSPHRASE = "passphrase"


class Cipher(Protocol):
    def encrypt(self, plaintext: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes) -> bytes: ...


class TokenCipher:
    def __init__(self, key: bytes):
        if len(key) != KEY_LENGTH:
            raise ValueError(f"At-rest key must be {KEY_LENGTH} bytes")
        self._token = Token(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._token.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = self._token.decrypt(ciphertext)
        if plaintext is None:
            raise ValueError("At-rest decryption failed")
        return plaintext


def load_keyfile(path: str) -> bytes:
    """Read the at-rest key, generating it on first use."""
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.isfile(path):
        with open(path, "rb") as key_file:
            key = key_file.read()
        if len(key) != KEY_LENGTH:
            raise ValueError(f"At-rest keyfile {path} does not hold a {KEY_LENGTH}-byte key")
        return key

    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = Token.generate_key()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as key_file:
        key_file.write(key)
    RNS.log(f"Generated at-rest encryption key at {path}", RNS.LOG_NOTICE)
    return key


def key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    return HKDF.hkdf(
        length=KEY_LENGTH,
        derive_from=passphrase.encode("utf-8"),
        salt=salt,
        context=HKDF_CONTEXT,
    )


def build_cipher(mode: str, keyfile_path: str, salt: bytes) -> Cipher | None:
    """Construct the cipher for a configured at-rest mode."""
    if mode == MODE_NONE:
        return None
    if mode == MODE_KEYFILE:
        return TokenCipher(load_keyfile(keyfile_path))
    if mode == MODE_PASSPHRASE:
        passphrase = os.environ.get(KEY_ENV_VAR)
        if not passphrase:
            raise ValueError(
                f"At-rest mode 'passphrase' requires the {KEY_ENV_VAR} environment variable"
            )
        return TokenCipher(key_from_passphrase(passphrase, salt))
    raise ValueError(f"Unknown at-rest mode: {mode}")
