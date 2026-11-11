"""Explicit tenant-schema upgrades, without catalog seeding or data resets.

    python -m app.scripts.upgrade_tenants --customer lab01
    python -m app.scripts.upgrade_tenants --customer lab01 --customer lab02 --apply
    python -m app.scripts.upgrade_tenants --all --apply

Without --apply, lists the registered tenant/schema targets only.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from sqlalchemy import select, text

from app.db.base import AsyncSessionLocal
from app.db.tenant import schema_for
from app.models.public import Customer
from app.services.provisioning import _migrate_in_transaction


async def upgrade(customers: list[str] | None, *, apply: bool = False) -> list[dict]:
    targets = []
    # Validate the full target list before applying any migrations.
    async with AsyncSessionLocal() as session:
        registered = (await session.scalars(select(Customer.codename).order_by(Customer.codename))).all()
        names = dict.fromkeys(registered if customers is None else customers)
        for name in names:
            schema = schema_for(name)
            if customers is not None and registered.count(name) != 1:
                raise ValueError(f"customer codename must identify exactly one registered customer: {name}")
            exists = await session.scalar(text("SELECT to_regnamespace(:schema)"), {"schema": schema})
            if exists is None:
                if customers is None:
                    continue  # Failed or pending provisioning may have no schema yet.
                raise ValueError(f"missing schema: {schema}; provision the customer first")
            targets.append({"customer": name, "schema": schema, "applied": False})
    if apply:
        for target in targets:
            schema = target["schema"]
            async with AsyncSessionLocal.begin() as session:
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext('detectmap:tenant-migrations'), hashtext(:schema))"),
                    {"schema": schema},
                )
                connection = await session.connection()
                await connection.run_sync(_migrate_in_transaction, schema)
            target["applied"] = True
    return targets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--customer", action="append", help="Exact existing customer; repeat for multiple targets")
    targets.add_argument("--all", action="store_true", help="Every registered customer with an existing schema")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(upgrade(args.customer, apply=args.apply)), indent=2))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
