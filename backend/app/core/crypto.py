"""Symmetric encryption helper for connector secrets.

We Fernet-encrypt sensitive blobs at the application layer before persisting
to JSON columns so that a DB dump cannot trivially leak SIEM/EDR credentials.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

_fernet = Fernet(settings.fernet_key.encode("utf-8"))


def encrypt(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    try:
        return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("invalid or tampered ciphertext") from exc


__all__ = ["encrypt", "decrypt"]
