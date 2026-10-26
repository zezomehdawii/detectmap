"""Password hashing + JWT token issuance and verification.

Two distinct signing keys are used:
  - JWT_TENANT_SECRET     — for MSSP staff & customer users
  - JWT_SUPERADMIN_SECRET — for Product Super Admins

This isolates blast radius. A compromise of one secret cannot mint tokens
authorized by the other code path.
"""
from __future__ import annotations

import enum
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
from jose import JWTError, jwt

from app.config import settings


# -- Password hashing -------------------------------------------------------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# -- JWT --------------------------------------------------------------------
class TokenAudience(str, enum.Enum):
    TENANT = "detectmap:tenant"
    SUPERADMIN = "detectmap:superadmin"


def _secret_for(aud: TokenAudience) -> str:
    if aud is TokenAudience.TENANT:
        return settings.jwt_tenant_secret
    if aud is TokenAudience.SUPERADMIN:
        return settings.jwt_superadmin_secret
    raise ValueError(f"unknown audience: {aud}")


def create_access_token(
    *,
    subject: str,
    audience: TokenAudience,
    claims: Optional[dict[str, Any]] = None,
    ttl_minutes: Optional[int] = None,
) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl_minutes or settings.jwt_access_ttl_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "aud": audience.value,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "typ": "access",
    }
    if claims:
        payload.update(claims)
    return jwt.encode(payload, _secret_for(audience), algorithm=settings.jwt_algorithm)


def decode_token(token: str, audience: TokenAudience) -> dict[str, Any]:
    """Decode and verify a JWT. Raises JWTError on failure.

    Critically, audience is *enforced* — a tenant token decoded against the
    super-admin key will fail signature verification AND audience check.
    """
    return jwt.decode(
        token,
        _secret_for(audience),
        algorithms=[settings.jwt_algorithm],
        audience=audience.value,
    )


__all__ = [
    "TokenAudience",
    "create_access_token",
    "decode_token",
    "hash_password",
    "verify_password",
    "JWTError",
]
