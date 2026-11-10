"""Create initial administrators only for a genuinely empty deployment.

    python -m app.scripts.initialize_admins \
        --admin-email admin@detectmap.local --super-email super@detectmap.local

Existing accounts, organizations, customers, and customer schemas are never
modified. Passwords are generated inside this process and printed only after
the database transaction commits. No password command arguments are accepted.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
import json
import logging
import re
import secrets
import sys
import uuid

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.security import hash_password
from app.db.base import AsyncSessionLocal, engine
from app.models.public import AppSettings, Customer, MSSPOrg, Role, SuperAdmin, User

# Avoid emitting INSERT parameters (including password hashes) in the setup
# terminal when the installation otherwise enables SQLAlchemy debug output.
engine.sync_engine.echo = False
logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)

DEFAULT_ADMIN_EMAIL = "admin@detectmap.local"
DEFAULT_SUPER_EMAIL = "super@detectmap.local"
DEFAULT_MSSP_NAME = "Detect Map"
INITIALIZATION_LOCK = 741225031


@dataclass(frozen=True)
class InitializationResult:
    empty: bool
    created: bool = False
    admin_email: str | None = None
    admin_password: str | None = field(default=None, repr=False)
    super_email: str | None = None
    super_password: str | None = field(default=None, repr=False)


def _email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 255 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("Administrator identities must be valid email addresses up to 255 characters")
    return value


async def _deployment_empty(session) -> bool:
    # Reference catalogs may already exist; they do not establish ownership.
    # Even an orphaned organization/customer/schema prevents automatic init.
    for model in (User, SuperAdmin, MSSPOrg, Customer):
        count = (await session.execute(select(func.count()).select_from(model))).scalar_one()
        if count:
            return False
    has_customer_schema = (await session.execute(text(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE left(nspname, 5) = 'cust_')"
    ))).scalar_one()
    return not has_customer_schema


async def initialize_admins(
    *, admin_email: str = DEFAULT_ADMIN_EMAIL,
    super_email: str = DEFAULT_SUPER_EMAIL,
    status_only: bool = False,
) -> InitializationResult:
    admin_email, super_email = _email(admin_email), _email(super_email)
    result = InitializationResult(empty=False)
    async with AsyncSessionLocal() as session:
        async with session.begin():
            # Serialize simultaneous invocations from setup without retaining
            # a lock after commit/rollback or introducing persistent state.
            await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": INITIALIZATION_LOCK})
            empty = await _deployment_empty(session)
            if not empty or status_only:
                result = InitializationResult(empty=empty)
            else:
                admin_password = secrets.token_urlsafe(24)
                super_password = secrets.token_urlsafe(24)
                org = MSSPOrg(id=uuid.uuid4(), name=DEFAULT_MSSP_NAME)
                session.add(org)
                await session.flush()
                session.add(User(
                    id=uuid.uuid4(), email=admin_email,
                    hashed_password=hash_password(admin_password),
                    role=Role.MSSP_ADMIN, auth_source="local",
                    full_name="Initial administrator", is_active=True,
                    mssp_org_id=org.id, customer_id=None, must_change_password=True,
                ))
                session.add(SuperAdmin(
                    id=uuid.uuid4(), email=super_email,
                    hashed_password=hash_password(super_password),
                    full_name="Initial super admin", is_active=True,
                    must_change_password=True,
                ))
                await session.flush()
                # The configured demo login hint is unrelated to these newly
                # generated credentials. Disable that hint atomically while
                # preserving every other setting on an existing singleton.
                await session.execute(
                    pg_insert(AppSettings).values(singleton=True, show_login_hint=False)
                    .on_conflict_do_update(
                        index_elements=[AppSettings.singleton],
                        set_={"show_login_hint": False},
                    )
                )
                result = InitializationResult(
                    empty=True, created=True,
                    admin_email=admin_email, admin_password=admin_password,
                    super_email=super_email, super_password=super_password,
                )
    # Returning credentials only after the transaction and session exit means
    # a failed commit cannot produce apparently usable initial credentials.
    return result


def print_result(result: InitializationResult, *, status_only: bool = False) -> None:
    if status_only:
        print(json.dumps({"empty": result.empty}))
    elif not result.created:
        print("Existing deployment detected; administrator accounts unchanged.")
    else:
        print("Initial administrators created. Save these generated credentials now:")
        print(f"  MSSP administrator: {result.admin_email}")
        print(f"  Temporary password: {result.admin_password}")
        print(f"  Product super admin: {result.super_email}")
        print(f"  Temporary password: {result.super_password}")
        print("Both accounts must change their password on first sign-in.")
        print("Passwords will not be printed again by a subsequent setup run.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-email", default=DEFAULT_ADMIN_EMAIL)
    parser.add_argument("--super-email", default=DEFAULT_SUPER_EMAIL)
    parser.add_argument("--status-only", action="store_true", help="Report whether initialization is possible without changing records")
    args = parser.parse_args()
    try:
        result = asyncio.run(initialize_admins(
            admin_email=args.admin_email, super_email=args.super_email,
            status_only=args.status_only,
        ))
    except ValueError as exc:
        parser.error(str(exc))
    except Exception:
        # SQL exceptions can contain credentials or hashes as query parameters.
        print("Administrator initialization failed; no credentials were printed. Check database/service health.", file=sys.stderr)
        raise SystemExit(1) from None
    print_result(result, status_only=args.status_only)


if __name__ == "__main__":
    main()
