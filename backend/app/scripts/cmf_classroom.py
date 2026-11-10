"""Instructor-only starter seed/restore, explicitly scoped to one existing tenant.

    python -m app.scripts.cmf_classroom show --customer lab01
    python -m app.scripts.cmf_classroom seed --customer lab01 --apply
    python -m app.scripts.cmf_classroom reset --customer lab01 --apply --confirm lab01

Reset restores only deterministic marker-owned starter rows in place. It does
not wipe a tenant, delete student-added records, or alter users/catalogs.
"""
from __future__ import annotations

import argparse
import asyncio
import json

from sqlalchemy import select, text

from app.db.base import AsyncSessionLocal
from app.db.tenant import schema_for, set_tenant, tenant_session
from app.models.customer import Asset, AssetDataSource, CollectionPlanItem, CollectionRequirement
from app.models.public import Customer, CustomerStatus
from app.services.cmf_classroom_data import MARKER, owns_record, starter_records

MODELS = {"assets": Asset, "data_sources": AssetDataSource, "requirements": CollectionRequirement, "plan": CollectionPlanItem}


async def apply_starter(customer: str, *, reset: bool = False) -> dict:
    schema = schema_for(customer)
    async with AsyncSessionLocal() as public:
        matches = (await public.execute(select(Customer).where(Customer.codename == customer))).scalars().all()
        if len(matches) != 1:
            raise ValueError("customer codename must identify exactly one registered customer")
        registered = matches[0]
        if registered.status != CustomerStatus.ACTIVE:
            raise ValueError("customer must already exist and be active")
        exists = (await public.execute(text("SELECT to_regnamespace(:schema)"), {"schema": schema})).scalar_one_or_none()
        if exists is None:
            raise ValueError("tenant schema missing; provision/upgrade it first")
    records = starter_records(customer)
    counts = {"created": 0, "restored": 0, "unchanged": 0}
    set_tenant(customer)
    try:
        async with tenant_session() as session:
            # Serializes repeat seed/reset commands for this one dataset/tenant.
            await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"{schema}:{MARKER}"})
            # Preflight every ownership marker before mutating any row.
            existing = {}
            for kind, specs in records.items():
                for spec in specs:
                    row = await session.get(MODELS[kind], spec["id"])
                    if row is not None and not owns_record(kind, row, spec):
                        raise ValueError(f"refusing non-classroom record collision: {kind}/{spec['id']}")
                    if kind == "assets":
                        matches = (await session.execute(select(Asset.id).where(Asset.external_id == spec["external_id"]))).scalars().all()
                        if any(value != spec["id"] for value in matches):
                            raise ValueError(f"starter external_id already belongs to a different asset: {spec['external_id']}")
                    if kind == "data_sources" and row is None:
                        conflict = (await session.execute(select(AssetDataSource.id).where(
                            AssetDataSource.asset_id == spec["asset_id"], AssetDataSource.name == spec["name"],
                        ))).scalar_one_or_none()
                        if conflict is not None:
                            raise ValueError(f"refusing to replace non-starter collection source: {spec['name']}")
                    existing[(kind, spec["id"])] = row
            for kind, specs in records.items():
                for spec in specs:
                    row = existing[(kind, spec["id"])]
                    if row is None:
                        session.add(MODELS[kind](**spec))
                        counts["created"] += 1
                    elif reset:
                        # Set every editable column to the starter/default value,
                        # preserving record IDs and unrelated FK references.
                        editable = set(MODELS[kind].__table__.columns.keys()) - {"id", "created_at", "updated_at"}
                        defaults = {
                            "environment": "production", "criticality": "medium", "status": "active",
                            "tags": [], "compliance_scope": [], "attack_technique_ids": [],
                            "priority": "medium", "technique_count": 0, "enabled": True,
                        }
                        for field in editable:
                            setattr(row, field, spec.get(field, defaults.get(field)))
                        counts["restored"] += 1
                    else:
                        counts["unchanged"] += 1
                # Ensure FK parents exist before processing the next group.
                await session.flush()
    finally:
        set_tenant(None)
    return {"customer": customer, "dataset": MARKER, **counts}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["show", "seed", "reset"])
    parser.add_argument("--customer", required=True)
    parser.add_argument("--apply", action="store_true", help="Actually write the starter records")
    parser.add_argument("--confirm", help="For reset, repeat the exact customer codename")
    args = parser.parse_args()
    schema_for(args.customer)
    if args.action == "show" or not args.apply:
        print(json.dumps({"dry_run": True, "customer": args.customer, "dataset": starter_records(args.customer)}, default=str, indent=2))
        return
    if args.action == "reset" and args.confirm != args.customer:
        parser.error("reset requires --confirm matching --customer")
    try:
        print(json.dumps(asyncio.run(apply_starter(args.customer, reset=args.action == "reset")), indent=2))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
