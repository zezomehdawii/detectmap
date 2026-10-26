"""Interactive admin password reset utility.

Run inside the backend container:

    docker compose exec backend pass-reset

Lists MSSP users + super admins, lets the operator pick one by number
(or `s<n>` for a super admin), prompts for a new password twice (hidden),
and rehashes it directly in the database. No HTTP, no token — meant for
break-glass use when the admin has lost their password.

Flags (optional, all skip the menu / prompts when supplied):

    --email someone@example.com   pick the account by email
    --password 'new-secret'       set password without prompting (NOT echoed
                                  on the menu; useful for scripted resets)
    --kind user|superadmin        disambiguate when the same email is in
                                  both tables (rare)
    --yes                         skip the final "really?" confirmation

The utility is intentionally pickier than the HTTP /settings/users PATCH:
- Requires a password ≥ 8 chars.
- For users, refuses to flip an LDAP-only account back to local without
  the explicit `--force-local` flag.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from typing import Optional

from sqlalchemy import select

from app.core.security import hash_password
from app.db.base import AsyncSessionLocal, engine
from app.models.public import SuperAdmin, User

# Silence SQLAlchemy engine echo for this CLI — when the API server runs
# in debug mode the global engine has `echo=True`, which would spam every
# prompt with query traces. Toggling `engine.echo` flips the per-instance
# logger level installed by `create_async_engine`.
engine.sync_engine.echo = False
logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)

MIN_LEN = 8


# ---- pretty printing ----------------------------------------------------

def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if sys.stdout.isatty() else s


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if sys.stdout.isatty() else s


def _dim(s: str) -> str:
    return f"\033[2m{s}\033[0m" if sys.stdout.isatty() else s


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if sys.stdout.isatty() else s


# ---- prompts ------------------------------------------------------------

def _prompt_password() -> str:
    while True:
        pw = getpass.getpass("New password: ")
        if len(pw) < MIN_LEN:
            print(_red(f"  password must be at least {MIN_LEN} characters"))
            continue
        confirm = getpass.getpass("Confirm password: ")
        if pw != confirm:
            print(_red("  passwords don't match — try again"))
            continue
        return pw


def _confirm(prompt: str) -> bool:
    try:
        ans = input(f"{prompt} [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


# ---- menu ---------------------------------------------------------------

async def _load_candidates() -> tuple[list[User], list[SuperAdmin]]:
    async with AsyncSessionLocal() as session:
        users = (
            await session.execute(
                select(User)
                .where(User.role.in_(("mssp_admin", "mssp_analyst", "mssp_readonly", "customer_user")))
                .order_by(User.role.asc(), User.email.asc())
            )
        ).scalars().all()
        supers = (
            await session.execute(select(SuperAdmin).order_by(SuperAdmin.email.asc()))
        ).scalars().all()
        return list(users), list(supers)


def _print_menu(users: list[User], supers: list[SuperAdmin]) -> None:
    print()
    print(_bold("Tenant users (MSSP staff + customer users)"))
    if not users:
        print(_dim("  (none)"))
    else:
        for i, u in enumerate(users, start=1):
            active = "" if u.is_active else _red(" [inactive]")
            auth = "" if u.auth_source == "local" else _dim(f" [{u.auth_source}]")
            print(f"  {i:>3}. {u.email:<40} {u.role.value}{auth}{active}")
    print()
    print(_bold("Super admins"))
    if not supers:
        print(_dim("  (none)"))
    else:
        for i, sa in enumerate(supers, start=1):
            active = "" if sa.is_active else _red(" [inactive]")
            print(f"  s{i:<2}. {sa.email}{active}")
    print()
    print(_dim("Pick by number (e.g. 1, s2) or type the full email. Ctrl-C to quit."))


def _pick(users: list[User], supers: list[SuperAdmin]):
    """Returns (kind, row) where kind ∈ {'user','superadmin'}."""
    while True:
        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not choice:
            continue
        # super admin shortcut
        if choice.lower().startswith("s") and choice[1:].isdigit():
            idx = int(choice[1:]) - 1
            if 0 <= idx < len(supers):
                return "superadmin", supers[idx]
            print(_red("  out of range"))
            continue
        # plain user index
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(users):
                return "user", users[idx]
            print(_red("  out of range"))
            continue
        # email lookup
        e = choice.lower()
        for sa in supers:
            if sa.email.lower() == e:
                return "superadmin", sa
        for u in users:
            if u.email.lower() == e:
                return "user", u
        print(_red("  no match — try again"))


# ---- reset --------------------------------------------------------------

async def _reset_user_password(user_id, new_hash: str, allow_local_flip: bool) -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            u = (
                await session.execute(select(User).where(User.id == user_id))
            ).scalar_one()
            if u.auth_source != "local" and not allow_local_flip:
                raise SystemExit(
                    _red(
                        f"  {u.email} is currently an {u.auth_source} account. "
                        "Re-run with --force-local to switch it back to local auth."
                    )
                )
            u.hashed_password = new_hash
            u.auth_source = "local"


async def _reset_super_password(super_id, new_hash: str) -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            sa = (
                await session.execute(
                    select(SuperAdmin).where(SuperAdmin.id == super_id)
                )
            ).scalar_one()
            sa.hashed_password = new_hash


# ---- lookup-by-email path (non-interactive selection) -------------------

async def _resolve_by_email(
    email: str, kind: Optional[str]
) -> tuple[str, object]:
    e = email.lower()
    async with AsyncSessionLocal() as session:
        u = (
            await session.execute(select(User).where(User.email == e))
        ).scalar_one_or_none()
        sa = (
            await session.execute(select(SuperAdmin).where(SuperAdmin.email == e))
        ).scalar_one_or_none()
    if kind == "user":
        if u is None:
            raise SystemExit(_red(f"  no tenant user with email {email}"))
        return "user", u
    if kind == "superadmin":
        if sa is None:
            raise SystemExit(_red(f"  no super admin with email {email}"))
        return "superadmin", sa
    if u is not None and sa is not None:
        raise SystemExit(
            _red(
                f"  email {email} matches both a tenant user and a super admin — "
                "pass --kind user or --kind superadmin"
            )
        )
    if u is not None:
        return "user", u
    if sa is not None:
        return "superadmin", sa
    raise SystemExit(_red(f"  no account with email {email}"))


# ---- main ---------------------------------------------------------------

async def _amain(args: argparse.Namespace) -> None:
    # 1. pick the account
    if args.email:
        kind, row = await _resolve_by_email(args.email, args.kind)
    else:
        users, supers = await _load_candidates()
        if not users and not supers:
            raise SystemExit(_red("no accounts found — has the database been bootstrapped?"))
        _print_menu(users, supers)
        kind, row = _pick(users, supers)

    label = f"{kind}: {row.email}"
    print(_dim(f"selected → {label}"))

    # 2. pick the password
    if args.password:
        if len(args.password) < MIN_LEN:
            raise SystemExit(_red(f"  password must be at least {MIN_LEN} characters"))
        new_pw = args.password
    else:
        new_pw = _prompt_password()

    # 3. confirm + apply
    if not args.yes:
        if not _confirm(f"Reset password for {_bold(label)}?"):
            print(_dim("aborted"))
            return
    new_hash = hash_password(new_pw)
    if kind == "user":
        await _reset_user_password(row.id, new_hash, args.force_local)
    else:
        await _reset_super_password(row.id, new_hash)
    print(_green(f"  ✓ password updated for {label}"))


def main() -> None:
    p = argparse.ArgumentParser(prog="pass-reset", description=__doc__)
    p.add_argument("--email", help="pick the account by email instead of the menu")
    p.add_argument(
        "--kind",
        choices=("user", "superadmin"),
        help="disambiguate when the same email exists in both tables",
    )
    p.add_argument("--password", help="set the password without prompting")
    p.add_argument(
        "--force-local",
        action="store_true",
        help="allow flipping an LDAP/SSO user back to local auth",
    )
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = p.parse_args()
    try:
        asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()
