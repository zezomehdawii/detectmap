"""Cross-domain global search powering the Cmd+K palette.

Searches ATT&CK techniques, mitigations, APT groups (public schema),
plus the tenant's detections, and (for MSSP users) the customer registry.
Each result type is queried independently and capped at a small limit so
the palette stays snappy and the response under a kilobyte.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import Text, cast, or_, select

from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import Detection
from app.models.public import (
    AttackGroup,
    AttackMitigation,
    AttackTechnique,
    Customer,
    D3FENDTechnique,
)
from app.services.deployment import DeploymentScope


@dataclass
class SearchHit:
    kind: str  # technique | mitigation | apt | detection | customer
    id: str  # the canonical id used to deep-link
    label: str  # short label
    sub: Optional[str] = None  # tagline / second line
    href: Optional[str] = None  # frontend route suggestion


@dataclass
class SearchResults:
    query: str
    hits: list[SearchHit] = field(default_factory=list)


async def global_search(
    query: str,
    *,
    has_tenant: bool,
    mssp_org_id: Optional[str] = None,
    deployment: DeploymentScope = DeploymentScope(),
    limit_per_kind: int = 6,
) -> SearchResults:
    q = query.strip()
    out: list[SearchHit] = []
    if len(q) < 2:
        return SearchResults(query=q, hits=out)

    like = f"%{q}%"
    async with AsyncSessionLocal() as session:
        # Techniques: exact-id prefix match wins, then name ILIKE.
        tech_rows = (
            await session.execute(
                select(AttackTechnique)
                .where(
                    AttackTechnique.domain == "enterprise",
                    AttackTechnique.deprecated.is_(False),
                    AttackTechnique.revoked.is_(False),
                    or_(
                        AttackTechnique.technique_id.ilike(like),
                        AttackTechnique.name.ilike(like),
                    ),
                )
                .order_by(AttackTechnique.technique_id)
                .limit(limit_per_kind)
            )
        ).scalars().all()
        for t in tech_rows:
            out.append(
                SearchHit(
                    kind="technique",
                    id=t.technique_id,
                    label=f"{t.technique_id} · {t.name}",
                    sub=", ".join(t.tactics or []),
                    href=f"/dashboard/coverage?focus={t.technique_id}",
                )
            )

        # Mitigations
        mit_rows = (
            await session.execute(
                select(AttackMitigation)
                .where(
                    AttackMitigation.domain == "enterprise",
                    AttackMitigation.deprecated.is_(False),
                    AttackMitigation.revoked.is_(False),
                    or_(
                        AttackMitigation.mitigation_id.ilike(like),
                        AttackMitigation.name.ilike(like),
                    ),
                )
                .order_by(AttackMitigation.mitigation_id)
                .limit(limit_per_kind)
            )
        ).scalars().all()
        for m in mit_rows:
            out.append(
                SearchHit(
                    kind="mitigation",
                    id=m.mitigation_id,
                    label=f"{m.mitigation_id} · {m.name}",
                )
            )

        # D3FEND defensive techniques
        d3_rows = (
            await session.execute(
                select(D3FENDTechnique)
                .where(
                    or_(
                        D3FENDTechnique.d3fend_id.ilike(like),
                        D3FENDTechnique.name.ilike(like),
                    )
                )
                .order_by(D3FENDTechnique.d3fend_id)
                .limit(limit_per_kind)
            )
        ).scalars().all()
        for d in d3_rows:
            out.append(
                SearchHit(
                    kind="d3fend",
                    id=d.d3fend_id,
                    label=f"{d.d3fend_id} · {d.name}",
                    sub="D3FEND defensive technique",
                    href=d.url,
                )
            )

        # APT groups — match id, name, or aliases
        grp_rows = (
            await session.execute(
                select(AttackGroup)
                .where(
                    AttackGroup.domain == "enterprise",
                    AttackGroup.deprecated.is_(False),
                    AttackGroup.revoked.is_(False),
                    or_(
                        AttackGroup.group_id.ilike(like),
                        AttackGroup.name.ilike(like),
                        cast(AttackGroup.aliases, Text).ilike(like),
                    ),
                )
                .order_by(AttackGroup.group_id)
                .limit(limit_per_kind)
            )
        ).scalars().all()
        for g in grp_rows:
            aliases = list(g.aliases or [])[:2]
            out.append(
                SearchHit(
                    kind="apt",
                    id=g.group_id,
                    label=f"{g.group_id} · {g.name}",
                    sub=", ".join(aliases) if aliases else None,
                    href=f"/dashboard/apt?group={g.group_id}",
                )
            )

        # Customers (MSSP only; scoped to the MSSP's customers)
        if mssp_org_id is not None:
            import uuid as _uuid

            try:
                org_uuid = _uuid.UUID(mssp_org_id)
            except (ValueError, TypeError):
                org_uuid = None
            if org_uuid is not None:
                cust_rows = (
                    await session.execute(
                        select(Customer)
                        .where(
                            Customer.mssp_org_id == org_uuid,
                            deployment.customer_filter(),
                            or_(
                                Customer.codename.ilike(like),
                                Customer.name.ilike(like),
                            ),
                        )
                        .order_by(Customer.name)
                        .limit(limit_per_kind)
                    )
                ).scalars().all()
                for c in cust_rows:
                    out.append(
                        SearchHit(
                            kind="customer",
                            id=c.codename,
                            label=c.name,
                            sub=f"{c.codename} · {c.sector or 'no sector'}",
                        )
                    )

    # Detections — only if we have a tenant context (X-Customer set).
    if has_tenant:
        async with tenant_session() as session:
            det_rows = (
                await session.execute(
                    select(Detection)
                    .where(
                        or_(
                            Detection.title.ilike(like),
                            Detection.sigma_id.ilike(like),
                        )
                    )
                    .order_by(Detection.title)
                    .limit(limit_per_kind)
                )
            ).scalars().all()
            for d in det_rows:
                out.append(
                    SearchHit(
                        kind="detection",
                        id=str(d.id),
                        label=d.title,
                        sub=f"{d.detection_status.value} · {d.source.value}",
                        href=f"/dashboard/detections?id={d.id}",
                    )
                )

    return SearchResults(query=q, hits=out)


__all__ = ["SearchHit", "SearchResults", "global_search"]
