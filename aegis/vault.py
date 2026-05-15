"""Token vault — symmetric encryption for VCS tokens / webhook secrets.

Plaintext lives only in memory of a short-lived context; the DB stores ciphertext
only. Key from AEGIS_VAULT_KEY (env/KMS), validated fail-fast at startup (config.py).
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from aegis.config import get_settings
from aegis.errors import VaultError


def _cipher() -> Fernet:
    return Fernet(get_settings().vault_key.encode())


def encrypt(plaintext: str) -> str:
    if plaintext == "":
        raise VaultError("refusing to encrypt empty secret")
    return _cipher().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    try:
        return _cipher().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError) as exc:
        raise VaultError("cannot decrypt secret (wrong key or corrupt ciphertext)") from exc
