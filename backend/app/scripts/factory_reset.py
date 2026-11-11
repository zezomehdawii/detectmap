"""Factory-reset the deployment: clean slate with a single admin.

WHAT IT DOES
============

DROPS (per-tenant + per-org state):
  - every `cust_*` schema (all customer-tenant data: detections,
    coverage snapshots, connectors, saved views, etc.)
  - every row in public.user_preferences, custom_roles, users,
    customers, mssp_orgs, super_admins
  - audit_log + scheduled_job_runs
  - app_settings (recreated with the selected sign-in hint setting)

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

With --use-login-defaults, the dashboard administrator instead uses the
configured login-card credentials, has no forced password change, and the
card is enabled. The super admin remains separate with a temporary password.

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
from typing import Literal

# Silence engine echo — this is a CLI, not the server.
logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)

from sqlalchemy import delete, select, text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402
from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.db.base import AsyncSessionLocal, engine  # noqa: E402
from app.scripts.initialize_admins import (  # noqa: E402
    INITIALIZATION_LOCK,
    configured_login_credentials,
    normalize_admin_email,
)
from app.services.deployment import configure  # noqa: E402

engine.sync_engine.echo = False  # belt-and-braces with the log level above

from app.models.public import (  # noqa: E402
    AppSettings,
    AuditLog,
    CustomRole,
    Customer,
    DeploymentMode,
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

async def _drop_customer_schemas(session: AsyncSession) -> list[str]:
    """Drop every customer schema within the reset transaction."""
    result = await session.execute(
        text("SELECT nspname FROM pg_namespace WHERE left(nspname, 5) = 'cust_'")
    )
    schemas = list(result.scalars())
    for schema in schemas:
        if not schema.startswith("cust_") or not schema.replace("_", "").isalnum():
            raise RuntimeError(f"refusing to drop suspicious schema name: {schema!r}")
        await session.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    return schemas


async def _wipe_public_tenant_state(session: AsyncSession) -> None:
    """Clear public tenant state, child rows before parents."""
    for model in (UserPreferences, CustomRole, User, SuperAdmin, Customer, MSSPOrg, AuditLog, ScheduledJobRun, AppSettings):
        await session.execute(delete(model))


# ---- seeding -------------------------------------------------------------

def _gen_password() -> str:
    return secrets.token_urlsafe(GENERATED_PASSWORD_BYTES)


async def _seed_admin(
    session: AsyncSession,
    *,
    mssp_name: str,
    admin_email: str,
    admin_password: str,
    super_email: str,
    super_password: str,
    use_login_defaults: bool = False,
    deployment_mode: DeploymentMode = "multi_tenant",
    sample_data: Literal["sample", "fresh"] = "fresh",
) -> None:
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
            must_change_password=not use_login_defaults,
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
    # A random password does not match the configured login card.
    await session.execute(
        pg_insert(AppSettings).values(singleton=True, show_login_hint=use_login_defaults)
        .on_conflict_do_update(
            index_elements=[AppSettings.singleton],
            set_={"show_login_hint": use_login_defaults},
        )
    )
    if deployment_mode != "multi_tenant" or sample_data == "sample":
        await configure(
            session, org, mode=deployment_mode, sample_data_enabled=sample_data == "sample",
            initializing=True,
        )


async def _reset_deployment(**admin_options) -> list[str]:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": INITIALIZATION_LOCK})
            schemas = await _drop_customer_schemas(session)
            await _wipe_public_tenant_state(session)
            await _seed_admin(session, **admin_options)
    return schemas


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
    use_login_defaults = getattr(args, "use_login_defaults", False)
    if use_login_defaults:
        # Fail before confirmation or any destructive call when the hint and
        # seeded account would disagree. Use the configured dashboard password.
        if args.admin_password is not None:
            raise ValueError("--admin-password cannot be combined with --use-login-defaults")
        admin_email, admin_password = configured_login_credentials(args.admin_email)
        super_email = normalize_admin_email(args.super_email)
    else:
        admin_email = args.admin_email or DEFAULT_ADMIN_EMAIL
        admin_password = args.admin_password or _gen_password()
        super_email = args.super_email
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

    counts = await _summarise_preserved()
    print(_dim("→ replacing customer schemas and accounts..."))
    schemas = await _reset_deployment(
        mssp_name=args.mssp_name,
        admin_email=admin_email,
        admin_password=admin_password,
        super_email=super_email,
        super_password=super_password,
        use_login_defaults=use_login_defaults,
        deployment_mode=args.deployment_mode,
        sample_data=args.sample_data,
    )
    print(_dim(f"  dropped {len(schemas)} schema(s): {', '.join(schemas) or '(none)'}"))

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
    print(f"    email     {admin_email_display(admin_email)}")
    print(f"    password  {_bold(admin_password)}")
    print()
    print(_yellow("  Product super admin"))
    print(f"    email     {admin_email_display(super_email)}")
    print(f"    password  {_bold(super_password)}")
    print()
    if use_login_defaults:
        print(_dim("Dashboard credentials are shown on the login page; hide the card"))
        print(_dim("under Settings -> Branding when it is no longer needed."))
        print(_dim("The product super admin must change its password on first login."))
    else:
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
        default=None,
        help=f"Seed MSSP admin email (default: {DEFAULT_ADMIN_EMAIL!r}; DEFAULT_LOGIN_EMAIL with --use-login-defaults)",
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
        "--use-login-defaults",
        action="store_true",
        help="Seed the dashboard account from DEFAULT_LOGIN_EMAIL/PASSWORD and enable the login-page card",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the typed RESET confirmation (use for unattended setup)",
    )
    p.add_argument("--deployment-mode", choices=("single", "multi_tenant"), default="multi_tenant")
    p.add_argument("--sample-data", choices=("sample", "fresh"), default="fresh")
    args = p.parse_args()

    try:
        rc = asyncio.run(_amain(args))
    except ValueError as exc:
        p.error(str(exc))
    except KeyboardInterrupt:
        print()
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
