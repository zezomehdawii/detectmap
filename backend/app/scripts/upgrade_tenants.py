"""Explicit tenant-schema upgrades, without catalog seeding or data resets.

    python -m app.scripts.upgrade_tenants --customer lab01
    python -m app.scripts.upgrade_tenants --customer lab01 --customer lab02 --apply

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
from app.services.provisioning import _run_customer_migrations


async def upgrade(customers: list[str], *, apply: bool = False) -> list[dict]:
    names = list(dict.fromkeys(customers))
    targets = []
    # Validate the full target list before applying any migrations.
    async with AsyncSessionLocal() as session:
        for name in names:
            schema = schema_for(name)
            matches = (await session.execute(select(Customer).where(Customer.codename == name))).scalars().all()
            if len(matches) != 1:
                raise ValueError(f"customer codename must identify exactly one registered customer: {name}")
            exists = (await session.execute(text("SELECT to_regnamespace(:schema)"), {"schema": schema})).scalar_one_or_none()
            if exists is None:
                raise ValueError(f"missing schema: {schema}; provision the customer first")
            targets.append({"customer": name, "schema": schema, "applied": False})
    for target in targets:
        if apply:
            await _run_customer_migrations(target["schema"])
            target["applied"] = True
    return targets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--customer", action="append", required=True, help="Exact existing customer; repeat for multiple targets")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(upgrade(args.customer, apply=args.apply)), indent=2))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
