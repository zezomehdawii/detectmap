"""FastAPI dependencies: auth + tenant resolution + permission gates.

This module is the security perimeter for the API. Every protected endpoint
depends on one of:
  - current_tenant_user()  -> authenticated MSSP/customer user + tenant set
  - current_super_admin()  -> authenticated super admin (separate JWT secret)
  - require_perm(perm)     -> permission gate built on current_tenant_user

Tenant resolution rules:
  - CUSTOMER_USER: customer_id in JWT; X-Customer header is IGNORED. The
                   token IS the authority. Mismatched X-Customer => 403.
  - MSSP_*:        X-Customer header selects the active customer; the user's
                   mssp_org_id must own that customer. Absence is allowed for
                   MSSP-level endpoints (portfolio, customer list) but the
                   tenant context will be unset.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.rbac import Permission, role_has
from app.core.security import JWTError, TokenAudience, decode_token
from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant
from app.models.public import Customer, Role, SuperAdmin, User

_bearer = HTTPBearer(auto_error=False)


@dataclass
class TenantPrincipal:
    """The authenticated tenant user + active customer (if any)."""
    user: User
    customer: Optional[Customer]  # None for MSSP users with no X-Customer set


# ---- low-level helpers ----------------------------------------------------
async def _public_session() -> AsyncSession:
    """Yield a session pinned to 'public' for auth lookups (no tenant context)."""
    session = AsyncSessionLocal()
    return session


def _credentials_exception(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---- super admin ----------------------------------------------------------
async def current_super_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> SuperAdmin:
    if creds is None:
        raise _credentials_exception("Missing bearer token")
    try:
        payload = decode_token(creds.credentials, TokenAudience.SUPERADMIN)
    except JWTError:
        # The super-admin decode failed. Before flagging as 401 (which
        # logs the user out in the SPA), check if the bearer is actually
        # a valid TENANT token — i.e., the caller is signed in but as an
        # MSSP user trying to reach a super-admin-only endpoint. That's
        # a permission problem (403), not an authentication problem,
        # and the UI degrades gracefully on 403 instead of bouncing the
        # session.
        try:
            decode_token(creds.credentials, TokenAudience.TENANT)
        except JWTError as exc:
            raise _credentials_exception(f"Invalid token: {exc}") from exc
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="super-admin role required for this endpoint",
        )

    sub = payload.get("sub")
    if not sub:
        raise _credentials_exception("Malformed token")

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(SuperAdmin).where(SuperAdmin.id == uuid.UUID(sub))
        )
        admin = result.scalar_one_or_none()
        if admin is None or not admin.is_active:
            raise _credentials_exception("Super admin not found or inactive")
        return admin


# ---- tenant principal -----------------------------------------------------
async def current_tenant_user(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    x_customer: Optional[str] = Header(default=None, alias="X-Customer"),
) -> TenantPrincipal:
    """Resolve the calling user + active customer, set tenant context.

    Side effect: calls set_tenant(<codename>) so downstream tenant_session()
    scopes search_path correctly. Cleared in main.py middleware on response.
    """
    if creds is None:
        raise _credentials_exception("Missing bearer token")
    try:
        payload = decode_token(creds.credentials, TokenAudience.TENANT)
    except JWTError as exc:
        raise _credentials_exception(f"Invalid token: {exc}") from exc

    user_id = payload.get("sub")
    if not user_id:
        raise _credentials_exception("Malformed token")

    async with AsyncSessionLocal() as session:
        user = (
            await session.execute(select(User).where(User.id == uuid.UUID(user_id)))
        ).scalar_one_or_none()
        if user is None or not user.is_active:
            raise _credentials_exception("User not found or inactive")

        active_customer: Optional[Customer] = None

        if user.role == Role.CUSTOMER_USER:
            # Customer users are HARD-PINNED to their own customer. The token
            # carries the customer_id claim; we trust the token, not the header.
            if user.customer_id is None:
                raise HTTPException(403, "Customer user not bound to a customer")
            active_customer = (
                await session.execute(
                    select(Customer).where(Customer.id == user.customer_id)
                )
            ).scalar_one_or_none()
            if active_customer is None:
                raise HTTPException(403, "Customer not found")
            # If the client sent X-Customer and it disagrees with the token,
            # that's a tampering signal — refuse.
            if x_customer and x_customer != active_customer.codename:
                raise HTTPException(403, "X-Customer mismatch for customer user")
        else:
            # MSSP roles. X-Customer is optional (some endpoints work without).
            if x_customer:
                active_customer = (
                    await session.execute(
                        select(Customer).where(
                            Customer.codename == x_customer,
                            Customer.mssp_org_id == user.mssp_org_id,
                        )
                    )
                ).scalar_one_or_none()
                if active_customer is None:
                    raise HTTPException(403, "Customer not visible to this user")

        # Set tenant context for the request. Cleared in main.py.
        set_tenant(active_customer.codename if active_customer else None)
        # Stash on request.state for logging / observability.
        request.state.user_id = str(user.id)
        request.state.customer_id = (
            str(active_customer.id) if active_customer else None
        )

        return TenantPrincipal(user=user, customer=active_customer)


# ---- permission gates -----------------------------------------------------
def require_perm(perm: Permission):
    """Build a dependency that enforces a permission on the calling user.

    Resolution: if the user has `custom_role_id`, the custom role's
    permission list is authoritative. Otherwise the built-in grants for
    `users.role` apply. The custom-role check is one extra DB hit; for
    users on built-in roles we short-circuit and stay synchronous.
    """
    async def _check(
        principal: TenantPrincipal = Depends(current_tenant_user),
    ) -> TenantPrincipal:
        from app.services.roles import user_has_permission

        if principal.user.custom_role_id is None:
            if not role_has(principal.user.role, perm):
                raise HTTPException(403, f"Missing permission: {perm.value}")
            return principal
        if not await user_has_permission(principal.user, perm):
            raise HTTPException(403, f"Missing permission: {perm.value}")
        return principal
    return _check


def require_active_customer():
    """Dependency that requires an active customer context (X-Customer set)."""
    async def _check(
        principal: TenantPrincipal = Depends(current_tenant_user),
    ) -> TenantPrincipal:
        if principal.customer is None:
            raise HTTPException(
                400,
                "X-Customer header required to scope this operation",
            )
        return principal
    return _check


def require_feature(key: str, *, optional_customer: bool = False):
    """Enforce a per-customer feature toggle.

    Returns 403 when the active customer has `key` disabled. By default
    requires an active customer (customer_user is pinned via the token;
    MSSP staff supply X-Customer). Pass `optional_customer=True` for
    cross-tenant endpoints (e.g. shared GRC catalog edits) — the gate
    then no-ops when the request has no customer context, and enforces
    only when one is set.
    """
    async def _check(
        principal: TenantPrincipal = Depends(current_tenant_user),
    ) -> TenantPrincipal:
        from app.services import customer_features

        if principal.customer is None:
            if optional_customer:
                return principal
            raise HTTPException(
                400,
                "X-Customer header required to scope this feature",
            )
        if not customer_features.is_enabled(principal.customer.features, key):
            raise HTTPException(
                403,
                f"Feature '{key}' is disabled for this customer",
            )
        return principal
    return _check


# ---- internal API key (bootstrap endpoints) -------------------------------
async def require_internal_key(
    x_internal_key: Optional[str] = Header(default=None, alias="X-Internal-Key"),
) -> None:
    if x_internal_key != settings.internal_api_key:
        raise HTTPException(401, "Invalid or missing internal key")
