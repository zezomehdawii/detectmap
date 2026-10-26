"""Custom denominator builder.

Lets analysts compose a denominator from multiple sources:
- sectors:    any technique used by at least one of the listed sectors
- apt_groups: direct TTPs ∪ software TTPs of each listed group
- platforms:  only techniques tagged for the listed platforms (filter)
- operator:   how to combine sources — "union" (default) or "intersection"

Result is the set of in-scope ATT&CK technique IDs, identical in shape to
the output of `compute_denominator` so the rest of the coverage pipeline
can consume it unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select

from app.db.base import AsyncSessionLocal
from app.models.public import (
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackSoftwareTechnique,
    AttackTechnique,
    SectorProfile,
)


@dataclass
class CustomDenominatorSpec:
    sectors: list[str] = field(default_factory=list)
    apt_groups: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    operator: str = "union"  # union | intersection


async def compute_custom_denominator(
    spec: CustomDenominatorSpec,
    *,
    domain: str = "enterprise",
) -> set[str]:
    sets: list[set[str]] = []

    async with AsyncSessionLocal() as session:
        if spec.sectors:
            sector_set: set[str] = set()
            rows = (
                await session.execute(
                    select(SectorProfile).where(
                        SectorProfile.sector.in_(spec.sectors),
                    )
                )
            ).scalars().all()
            for p in rows:
                sector_set.update(p.technique_ids or [])
            sets.append(sector_set)

        if spec.apt_groups:
            apt_set: set[str] = set()
            direct = (
                await session.execute(
                    select(AttackGroupTechnique.technique_id).where(
                        AttackGroupTechnique.domain == domain,
                        AttackGroupTechnique.group_id.in_(spec.apt_groups),
                    )
                )
            ).scalars().all()
            apt_set.update(direct)
            sw_ids = (
                await session.execute(
                    select(AttackGroupSoftware.software_id).where(
                        AttackGroupSoftware.domain == domain,
                        AttackGroupSoftware.group_id.in_(spec.apt_groups),
                    )
                )
            ).scalars().all()
            if sw_ids:
                indirect = (
                    await session.execute(
                        select(AttackSoftwareTechnique.technique_id).where(
                            AttackSoftwareTechnique.domain == domain,
                            AttackSoftwareTechnique.software_id.in_(sw_ids),
                        )
                    )
                ).scalars().all()
                apt_set.update(indirect)
            sets.append(apt_set)

        if not sets:
            # No primary source given → start from full enterprise universe,
            # then optionally narrow by platform.
            all_rows = (
                await session.execute(
                    select(
                        AttackTechnique.technique_id,
                        AttackTechnique.platforms,
                    ).where(
                        AttackTechnique.domain == domain,
                        AttackTechnique.deprecated.is_(False),
                        AttackTechnique.revoked.is_(False),
                    )
                )
            ).all()
            base = {r.technique_id for r in all_rows}
            platform_meta = {r.technique_id: r.platforms or [] for r in all_rows}
        else:
            if spec.operator == "intersection":
                base = set.intersection(*sets)
            else:
                base = set.union(*sets)

            if spec.platforms:
                # Need the platform metadata for filtering
                plat_rows = (
                    await session.execute(
                        select(
                            AttackTechnique.technique_id,
                            AttackTechnique.platforms,
                        ).where(
                            AttackTechnique.domain == domain,
                            AttackTechnique.technique_id.in_(base),
                        )
                    )
                ).all()
                platform_meta = {r.technique_id: r.platforms or [] for r in plat_rows}
            else:
                platform_meta = {}

        if spec.platforms:
            wanted = {p.lower() for p in spec.platforms}
            base = {
                tid
                for tid in base
                if any(
                    p.lower() in wanted for p in (platform_meta.get(tid) or [])
                )
            }

    return base


__all__ = ["CustomDenominatorSpec", "compute_custom_denominator"]
