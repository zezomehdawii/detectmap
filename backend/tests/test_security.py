"""Unit tests for security-critical primitives.

These don't require a live database. Run with:
    docker compose exec backend pytest -q
"""
from __future__ import annotations

import os

import pytest

# Ensure required env vars exist before importing app.config.
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("DATABASE_URL_SYNC", "postgresql+psycopg2://x:x@localhost/x")
os.environ.setdefault("JWT_TENANT_SECRET", "a" * 64)
os.environ.setdefault("JWT_SUPERADMIN_SECRET", "b" * 64)
os.environ.setdefault("FERNET_KEY", "GnZ3JmKuV2hWvWVH3kqW8x8K8aE-1cWj9F2K6XmpA0o=")
os.environ.setdefault("INTERNAL_API_KEY", "test-internal")

from app.core.rbac import Permission, role_has  # noqa: E402
from app.core.security import (  # noqa: E402
    JWTError,
    TokenAudience,
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.tenant import schema_for  # noqa: E402
from app.models.public import Role  # noqa: E402


# ---- tenant schema name validation ---------------------------------------
class TestSchemaFor:
    def test_valid_codename(self) -> None:
        assert schema_for("acme") == "cust_acme"
        assert schema_for("foo_bar_2") == "cust_foo_bar_2"

    @pytest.mark.parametrize("bad", [
        "Acme",            # uppercase
        "2acme",           # leading digit
        "acme-co",         # hyphen
        "acme;DROP",       # injection attempt
        "",                # empty
        "a" * 40,          # too long
        "acme.thing",      # dot
    ])
    def test_rejects_invalid(self, bad: str) -> None:
        with pytest.raises(ValueError):
            schema_for(bad)


# ---- password hashing ----------------------------------------------------
class TestPasswords:
    def test_round_trip(self) -> None:
        h = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", h)
        assert not verify_password("wrong", h)

    def test_unique_salts(self) -> None:
        a = hash_password("x")
        b = hash_password("x")
        assert a != b  # bcrypt randomizes salts


# ---- JWT audience isolation ----------------------------------------------
class TestJWTAudienceSeparation:
    """The two-secret design must reject cross-audience tokens."""

    def test_tenant_token_decodes_with_tenant_secret(self) -> None:
        token = create_access_token(
            subject="user-id", audience=TokenAudience.TENANT,
        )
        payload = decode_token(token, TokenAudience.TENANT)
        assert payload["sub"] == "user-id"
        assert payload["aud"] == TokenAudience.TENANT.value

    def test_tenant_token_rejected_by_superadmin_audience(self) -> None:
        token = create_access_token(
            subject="user-id", audience=TokenAudience.TENANT,
        )
        with pytest.raises(JWTError):
            decode_token(token, TokenAudience.SUPERADMIN)

    def test_superadmin_token_rejected_by_tenant_audience(self) -> None:
        token = create_access_token(
            subject="admin-id", audience=TokenAudience.SUPERADMIN,
        )
        with pytest.raises(JWTError):
            decode_token(token, TokenAudience.TENANT)


# ---- RBAC matrix ---------------------------------------------------------
class TestRBAC:
    def test_super_admin_cannot_edit_detections(self) -> None:
        # Super admin manages the product, not customer data.
        assert not role_has(Role.PRODUCT_SUPER_ADMIN, Permission.DETECTION_WRITE)

    def test_mssp_readonly_cannot_write(self) -> None:
        assert role_has(Role.MSSP_READONLY, Permission.DETECTION_READ)
        assert not role_has(Role.MSSP_READONLY, Permission.DETECTION_WRITE)
        assert not role_has(Role.MSSP_READONLY, Permission.DETECTION_DELETE)

    def test_customer_user_cannot_see_portfolio(self) -> None:
        assert not role_has(Role.CUSTOMER_USER, Permission.CUSTOMER_PORTFOLIO)

    def test_mssp_analyst_can_write_but_not_delete(self) -> None:
        assert role_has(Role.MSSP_ANALYST, Permission.DETECTION_WRITE)
        assert not role_has(Role.MSSP_ANALYST, Permission.DETECTION_DELETE)

    def test_customer_user_locked_out_of_mssp_surface(self) -> None:
        """The /portal experience relies on customer_user being denied every
        MSSP/super-admin permission. Lock that contract in tests so a future
        grant change doesn't accidentally widen what the portal exposes."""
        denied = {
            Permission.CUSTOMER_READ,
            Permission.CUSTOMER_PROVISION,
            Permission.CUSTOMER_PORTFOLIO,
            Permission.CONNECTOR_WRITE,
            Permission.USER_MANAGE,
            Permission.AUDIT_READ,
            Permission.CATALOG_MANAGE,
            Permission.MSSP_MANAGE,
        }
        for perm in denied:
            assert not role_has(Role.CUSTOMER_USER, perm), (
                f"customer_user must not have {perm.value}"
            )

    def test_customer_user_owns_their_data_perms(self) -> None:
        """Conversely, the portal does need these. Pin them so a future
        narrowing doesn't silently break the customer-facing flow."""
        required = {
            Permission.DETECTION_READ,
            Permission.DETECTION_WRITE,
            Permission.DETECTION_DELETE,
            Permission.COVERAGE_READ,
            Permission.REPORT_EXPORT,
            Permission.CONNECTOR_READ,
        }
        for perm in required:
            assert role_has(Role.CUSTOMER_USER, perm), (
                f"customer_user needs {perm.value} for the portal"
            )
