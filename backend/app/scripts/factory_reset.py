"""Factory-reset the deployment: clean slate with a single admin.

WHAT IT DOES
============

DROPS (per-tenant + per-org state):
  - every `cust_*` schema (all customer-tenant data: detections,
    coverage snapshots, connectors, saved views, etc.)
  - every row in public.user_preferences, custom_roles, users,
    customers, mssp_orgs, super_admins
  - audit_log + scheduled_job_runs
  - app_settings (recreated on next API call with defaults)

PRESERVES (reference data the operator paid to ingest):
  - ATT&CK catalog: techniques, mitigations, groups, software, all
    `attack_*` mapping tables, attack_catalog_versions
  - GRC frameworks + controls + technique/mitigation mappings
  - sector profiles
  - SigmaHQ default detections + ingest run history
  - D3FEND ontology + mappings

SEEDS (the only login that exists after the reset):
  - one MSSP org named "Default MSSP"
  - one MSSP admin with a generated random password
  - one super admin with a generated random password
  - both flagged `must_change_password=True`

OUTPUT
======
Prints the generated credentials ONCE on stdout. Save them — they are
not recoverable. Pass `--admin-email` / `--super-email` to set the
addresses; otherwise defaults are `admin@detectmap.local` and
`super@detectmap.local`. Pass `--admin-password` / `--super-password`
to override the generated passwords (useful for unattended setup).

SAFETY
======
This is destructive. Requires `--yes` to proceed without an interactive
confirmation. The setup script passes `--yes` after collecting the
operator's confirmation.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import secrets
import sys
import uuid
from typing import Optional

# Silence engine echo — this is a CLI, not the server.
logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)

from sqlalchemy import delete, select, text  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.db.base import AsyncSessionLocal, engine  # noqa: E402

engine.sync_engine.echo = False  # belt-and-braces with the log level above

from app.models.public import (  # noqa: E402
    AppSettings,
    AuditLog,
    CustomRole,
    Customer,
    MSSPOrg,
    Role,
    ScheduledJobRun,
    SuperAdmin,
    User,
    UserPreferences,
)

# Default identities for the seed admin + super admin.
DEFAULT_MSSP_NAME = "Default MSSP"
DEFAULT_ADMIN_EMAIL = "admin@detectmap.local"
DEFAULT_SUPER_EMAIL = "super@detectmap.local"
GENERATED_PASSWORD_BYTES = 18  # ~24 chars after urlsafe encoding


# ---- pretty printing -----------------------------------------------------

def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if sys.stdout.isatty() else s


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if sys.stdout.isatty() else s


def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m" if sys.stdout.isatty() else s


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if sys.stdout.isatty() else s


def _dim(s: str) -> str:
    return f"\033[2m{s}\033[0m" if sys.stdout.isatty() else s


# ---- destruction ---------------------------------------------------------

async def _drop_customer_schemas() -> list[str]:
    """Drop every `cust_*` schema. Returns the list of dropped schemas."""
    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name LIKE 'cust\\_%' ESCAPE '\\'"
            )
        )
        schemas = [row[0] for row in result.fetchall()]
        for schema in schemas:
            # Sanity check the name before interpolating — we only ever
            # drop schemas that match our codename pattern.
            if not schema.startswith("cust_") or not schema.replace("_", "").isalnum():
                raise RuntimeError(
                    f"refusing to drop suspicious schema name: {schema!r}"
                )
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    return schemas


async def _wipe_public_tenant_state() -> None:
    """Clear every public-schema table that holds per-org / per-user state.

    Order matters — child tables before parents, even with CASCADE FKs, so
    we don't fight ourselves on dependent rows.
    """
    async with AsyncSessionLocal() as session:
        async with session.begin():
            # Order: child tables first.
            await session.execute(delete(UserPreferences))
            await session.execute(delete(CustomRole))
            await session.execute(delete(User))
            await session.execute(delete(SuperAdmin))
            await session.execute(delete(Customer))
            await session.execute(delete(MSSPOrg))
            await session.execute(delete(AuditLog))
            await session.execute(delete(ScheduledJobRun))
            # app_settings is a singleton — wiping the row lets the next
            # /settings/catalog read recreate it with defaults.
            await session.execute(delete(AppSettings))


# ---- seeding -------------------------------------------------------------

def _gen_password() -> str:
    return secrets.token_urlsafe(GENERATED_PASSWORD_BYTES)


async def _seed_admin(
    *,
    mssp_name: str,
    admin_email: str,
    admin_password: str,
    super_email: str,
    super_password: str,
) -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = MSSPOrg(id=uuid.uuid4(), name=mssp_name)
            session.add(org)
            await session.flush()
            session.add(
                User(
                    id=uuid.uuid4(),
                    email=admin_email.lower(),
                    hashed_password=hash_password(admin_password),
                    auth_source="local",
                    full_name="Initial administrator",
                    role=Role.MSSP_ADMIN,
                    is_active=True,
                    mssp_org_id=org.id,
                    customer_id=None,
                    must_change_password=True,
                )
            )
            session.add(
                SuperAdmin(
                    id=uuid.uuid4(),
                    email=super_email.lower(),
                    hashed_password=hash_password(super_password),
                    full_name="Initial super admin",
                    is_active=True,
                    must_change_password=True,
                )
            )


# ---- summary -------------------------------------------------------------

async def _summarise_preserved() -> dict:
    """Read-only counts of preserved reference data — surfaced after the
    reset so the operator can sanity-check that ingest wasn't lost."""
    from app.models.public import (
        AttackGroup,
        AttackMitigation,
        AttackTechnique,
        D3FENDTechnique,
        DefaultDetection,
        GRCControl,
        GRCFramework,
        SectorProfile,
    )

    async with AsyncSessionLocal() as session:
        async def _count(model):
            r = await session.execute(select(model))
            return len(r.scalars().all())

        return {
            "ATT&CK techniques": await _count(AttackTechnique),
            "ATT&CK mitigations": await _count(AttackMitigation),
            "ATT&CK groups (APTs)": await _count(AttackGroup),
            "GRC frameworks": await _count(GRCFramework),
            "GRC controls": await _count(GRCControl),
            "Sector profiles": await _count(SectorProfile),
            "SigmaHQ default detections": await _count(DefaultDetection),
            "D3FEND techniques": await _count(D3FENDTechnique),
        }


# ---- entrypoint ----------------------------------------------------------

async def _amain(args: argparse.Namespace) -> int:
    admin_password = args.admin_password or _gen_password()
    super_password = args.super_password or _gen_password()

    print()
    print(_bold("Factory reset — clearing per-tenant state"))
    print(_dim("This destroys every customer schema, every user, and every"))
    print(_dim("MSSP org. Reference data (ATT&CK, GRC, SigmaHQ, D3FEND,"))
    print(_dim("sector profiles) is preserved."))
    print()

    if not args.yes:
        try:
            ans = input(f"Type {_bold('RESET')} to proceed: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 130
        if ans != "RESET":
            print(_yellow("aborted"))
            return 1

    print(_dim("→ dropping customer schemas..."))
    schemas = await _drop_customer_schemas()
    print(_dim(f"  dropped {len(schemas)} schema(s): {', '.join(schemas) or '(none)'}"))

    print(_dim("→ wiping per-org / per-user tables..."))
    await _wipe_public_tenant_state()

    print(_dim("→ seeding initial admin + super admin..."))
    await _seed_admin(
        mssp_name=args.mssp_name,
        admin_email=args.admin_email,
        admin_password=admin_password,
        super_email=args.super_email,
        super_password=super_password,
    )

    counts = await _summarise_preserved()

    print()
    print(_green(_bold("✓ factory reset complete")))
    print()
    print(_bold("Preserved reference data:"))
    for k, v in counts.items():
        print(f"  {k:<32} {v}")

    print()
    print(_bold("Initial credentials — save these now, they are not recoverable:"))
    print()
    print(_yellow("  MSSP administrator"))
    print(f"    email     {admin_email_display(args.admin_email)}")
    print(f"    password  {_bold(admin_password)}")
    print()
    print(_yellow("  Product super admin"))
    print(f"    email     {admin_email_display(args.super_email)}")
    print(f"    password  {_bold(super_password)}")
    print()
    print(_dim("Both accounts will be required to change their password on first"))
    print(_dim("login."))
    print()
    return 0


def admin_email_display(email: str) -> str:
    return email.lower()


def main() -> None:
    p = argparse.ArgumentParser(prog="factory-reset", description=__doc__)
    p.add_argument(
        "--mssp-name",
        default=DEFAULT_MSSP_NAME,
        help=f"Display name for the seed MSSP org (default: {DEFAULT_MSSP_NAME!r})",
    )
    p.add_argument(
        "--admin-email",
        default=DEFAULT_ADMIN_EMAIL,
        help=f"Email for the seed MSSP admin (default: {DEFAULT_ADMIN_EMAIL!r})",
    )
    p.add_argument(
        "--admin-password",
        default=None,
        help="Password for the seed MSSP admin (default: generated, ~24 chars)",
    )
    p.add_argument(
        "--super-email",
        default=DEFAULT_SUPER_EMAIL,
        help=f"Email for the seed super admin (default: {DEFAULT_SUPER_EMAIL!r})",
    )
    p.add_argument(
        "--super-password",
        default=None,
        help="Password for the seed super admin (default: generated, ~24 chars)",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the typed RESET confirmation (use for unattended setup)",
    )
    args = p.parse_args()

    try:
        rc = asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print()
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
