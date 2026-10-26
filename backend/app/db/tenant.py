"""Per-request tenant context + schema-scoped session.

Flow per request:
  1. Auth middleware resolves the active customer (see api/deps.py):
       - Customer User: pinned to their own customer_id (JWT claim).
       - MSSP User:     reads X-Customer header; if absent, no tenant context.
       - Super Admin:   no tenant context unless explicitly impersonating.
  2. tenant_ctx.set(schema_name) is called.
  3. tenant_session() yields an AsyncSession with SET LOCAL search_path =
     "<schema>, public". search_path is reset when the connection returns to
     the pool because it was LOCAL to the transaction.

Cross-tenant access is impossible because customer-scoped models have no
schema qualifier — they resolve against whichever schema is active in
search_path. If no tenant is set, queries against customer tables will
hit 'public' and fail (no such table), which we treat as 403 at the API edge.
"""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import AsyncIterator, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import AsyncSessionLocal

# Context var that holds the active customer schema for this request/task.
# None means "no tenant context" — only public-schema queries are allowed.
_tenant_schema: ContextVar[Optional[str]] = ContextVar(
    "detectmap_tenant_schema", default=None
)

# Customer codenames must match this strict pattern. We interpolate the
# schema name into SQL because parameter binding doesn't apply to identifiers,
# so we *must* validate strictly.
_CODENAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,30}$")


def schema_for(codename: str) -> str:
    """Return the Postgres schema name for a customer codename."""
    if not _CODENAME_RE.match(codename):
        raise ValueError(f"invalid customer codename: {codename!r}")
    return f"cust_{codename}"


def set_tenant(codename: Optional[str]) -> None:
    """Set the active tenant for the current context. Pass None to clear."""
    if codename is None:
        _tenant_schema.set(None)
    else:
        _tenant_schema.set(schema_for(codename))


def current_tenant_schema() -> Optional[str]:
    """Return the active tenant schema, or None if no tenant context."""
    return _tenant_schema.get()


def require_tenant() -> str:
    schema = current_tenant_schema()
    if schema is None:
        # API layer should have caught this and returned 403 already.
        raise PermissionError("no tenant context set for this operation")
    return schema


@asynccontextmanager
async def tenant_session(*, require: bool = True) -> AsyncIterator[AsyncSession]:
    """Yield an AsyncSession with search_path scoped to the active tenant.

    If require=True (default), raises PermissionError when no tenant is set.
    If require=False, yields a session pinned to the 'public' schema only —
    useful for MSSP-level operations (listing customers, etc.).
    """
    schema = current_tenant_schema()
    if schema is None and require:
        raise PermissionError("tenant context required but not set")

    async with AsyncSessionLocal() as session:
        # SET LOCAL only affects the current transaction. SQLAlchemy starts a
        # transaction on first use; we open one explicitly so the SET sticks
        # for the duration of this session.
        async with session.begin():
            if schema is not None:
                # Validated against _CODENAME_RE in schema_for(); safe to inline.
                await session.execute(
                    text(f'SET LOCAL search_path TO "{schema}", public')
                )
            else:
                await session.execute(text('SET LOCAL search_path TO public'))
            yield session
        # On exit the transaction commits (or rolls back on exception);
        # search_path resets because it was LOCAL.
