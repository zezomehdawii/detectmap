"""Consolidated per-technique drawer payload.

The coverage-matrix drawer needs many things at once: the ATT&CK catalog
record, mitigations, APT groups that use the technique, the tenant's
mapped detections, and any analyst note. Fetching these in one shot keeps
the UI snappy and avoids N+1 round-trips from the client.

All public-schema reads go through AsyncSessionLocal; tenant reads go
through tenant_session.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select

from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import (
    Detection,
    DetectionTechnique,
    TechniqueNote,
)
from app.models.public import (
    AttackGroup,
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackMitigation,
    AttackSoftware,
    AttackSoftwareTechnique,
    AttackTechnique,
    AttackTechniqueD3FEND,
    AttackTechniqueMitigation,
    D3FENDTechnique,
)


@dataclass
class MitigationDetail:
    mitigation_id: str
    name: str
    description: Optional[str]
    url: Optional[str]


@dataclass
class APTUsage:
    group_id: str
    name: str
    via: list[str]  # "direct" and/or "software:<sid>:<sname>"


@dataclass
class DetectionDetail:
    id: str
    sigma_id: str
    title: str
    detection_status: str
    source: str
    score_breadth: int
    score_depth: int
    level: Optional[str]
    upstream_global_id: Optional[str]


@dataclass
class D3FENDDefense:
    d3fend_id: str
    name: str
    relation: Optional[str]  # d3f:detects, d3f:hardens, …
    url: Optional[str]


@dataclass
class TechniqueNoteOut:
    body: str
    author_email: Optional[str]
    updated_at: str


@dataclass
class TechniqueDetailOut:
    technique_id: str
    domain: str
    name: str
    description: Optional[str]
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    tactics: list[str]
    platforms: list[str]
    data_sources: list[str]
    deprecated: bool
    revoked: bool
    url: Optional[str]
    mitigations: list[MitigationDetail] = field(default_factory=list)
    apt_groups: list[APTUsage] = field(default_factory=list)
    detections: list[DetectionDetail] = field(default_factory=list)
    d3fend: list[D3FENDDefense] = field(default_factory=list)
    note: Optional[TechniqueNoteOut] = None


async def get_technique_detail(
    technique_id: str, domain: str = "enterprise"
) -> Optional[TechniqueDetailOut]:
    """Bundle catalog + mitigations + APT linkage + tenant detections + note."""
    # ---- public catalog reads --------------------------------------------
    async with AsyncSessionLocal() as session:
        tech = (
            await session.execute(
                select(AttackTechnique).where(
                    AttackTechnique.domain == domain,
                    AttackTechnique.technique_id == technique_id,
                )
            )
        ).scalar_one_or_none()
        if tech is None:
            return None

        mit_ids = (
            await session.execute(
                select(AttackTechniqueMitigation.mitigation_id).where(
                    AttackTechniqueMitigation.domain == domain,
                    AttackTechniqueMitigation.technique_id == technique_id,
                )
            )
        ).scalars().all()
        mitigations: list[MitigationDetail] = []
        if mit_ids:
            mrows = (
                await session.execute(
                    select(AttackMitigation).where(
                        AttackMitigation.domain == domain,
                        AttackMitigation.mitigation_id.in_(mit_ids),
                        AttackMitigation.deprecated.is_(False),
                        AttackMitigation.revoked.is_(False),
                    )
                )
            ).scalars().all()
            mitigations = [
                MitigationDetail(
                    mitigation_id=m.mitigation_id,
                    name=m.name,
                    description=m.description,
                    url=m.url,
                )
                for m in sorted(mrows, key=lambda m: m.mitigation_id)
            ]

        # Direct group→technique relationships.
        direct_groups = (
            await session.execute(
                select(AttackGroupTechnique.group_id).where(
                    AttackGroupTechnique.domain == domain,
                    AttackGroupTechnique.technique_id == technique_id,
                )
            )
        ).scalars().all()

        # Indirect: software uses this technique, and groups use that software.
        sw_ids = (
            await session.execute(
                select(AttackSoftwareTechnique.software_id).where(
                    AttackSoftwareTechnique.domain == domain,
                    AttackSoftwareTechnique.technique_id == technique_id,
                )
            )
        ).scalars().all()

        sw_groups: dict[str, list[tuple[str, str]]] = {}
        if sw_ids:
            sw_meta = (
                await session.execute(
                    select(AttackSoftware.software_id, AttackSoftware.name).where(
                        AttackSoftware.domain == domain,
                        AttackSoftware.software_id.in_(sw_ids),
                    )
                )
            ).all()
            sw_name_by_id = {sid: name for sid, name in sw_meta}
            gs_rows = (
                await session.execute(
                    select(
                        AttackGroupSoftware.group_id,
                        AttackGroupSoftware.software_id,
                    ).where(
                        AttackGroupSoftware.domain == domain,
                        AttackGroupSoftware.software_id.in_(sw_ids),
                    )
                )
            ).all()
            for gid, sid in gs_rows:
                sw_groups.setdefault(gid, []).append(
                    (sid, sw_name_by_id.get(sid, sid))
                )

        all_group_ids = sorted(set(direct_groups) | set(sw_groups.keys()))
        groups_by_id: dict[str, AttackGroup] = {}
        if all_group_ids:
            grows = (
                await session.execute(
                    select(AttackGroup).where(
                        AttackGroup.domain == domain,
                        AttackGroup.group_id.in_(all_group_ids),
                        AttackGroup.deprecated.is_(False),
                        AttackGroup.revoked.is_(False),
                    )
                )
            ).scalars().all()
            groups_by_id = {g.group_id: g for g in grows}

        # D3FEND defensive linkages.
        d3_links = (
            await session.execute(
                select(AttackTechniqueD3FEND).where(
                    AttackTechniqueD3FEND.domain == domain,
                    AttackTechniqueD3FEND.technique_id == technique_id,
                )
            )
        ).scalars().all()
        d3fend_defenses: list[D3FENDDefense] = []
        if d3_links:
            d3_ids = sorted({link.d3fend_id for link in d3_links})
            d3_rows = (
                await session.execute(
                    select(D3FENDTechnique).where(
                        D3FENDTechnique.d3fend_id.in_(d3_ids)
                    )
                )
            ).scalars().all()
            d3_by_id = {r.d3fend_id: r for r in d3_rows}
            # Dedupe across multiple relations to the same d3fend_id;
            # prefer the most specific relation if duplicates appear.
            seen: dict[tuple[str, Optional[str]], D3FENDDefense] = {}
            for link in d3_links:
                row = d3_by_id.get(link.d3fend_id)
                key = (link.d3fend_id, link.relation)
                if key in seen:
                    continue
                seen[key] = D3FENDDefense(
                    d3fend_id=link.d3fend_id,
                    name=(row.name if row else link.d3fend_id),
                    relation=link.relation,
                    url=(row.url if row else None),
                )
            d3fend_defenses = sorted(seen.values(), key=lambda d: d.d3fend_id)

        apt_groups: list[APTUsage] = []
        for gid in all_group_ids:
            grp = groups_by_id.get(gid)
            if grp is None:
                continue
            via: list[str] = []
            if gid in direct_groups:
                via.append("direct")
            for sid, sname in sw_groups.get(gid, []):
                via.append(f"software:{sid}:{sname}")
            apt_groups.append(APTUsage(group_id=gid, name=grp.name, via=via))
        # Sort by group_id (G0001, G0007, ...) for stable display.
        apt_groups.sort(key=lambda x: x.group_id)

    # ---- tenant reads ----------------------------------------------------
    detections: list[DetectionDetail] = []
    note: Optional[TechniqueNoteOut] = None
    async with tenant_session() as session:
        det_rows = (
            await session.execute(
                select(Detection)
                .join(
                    DetectionTechnique,
                    DetectionTechnique.detection_id == Detection.id,
                )
                .where(DetectionTechnique.technique_id == technique_id)
                .order_by(
                    Detection.score_depth.desc(),
                    Detection.title.asc(),
                )
            )
        ).scalars().all()
        detections = [
            DetectionDetail(
                id=str(d.id),
                sigma_id=d.sigma_id,
                title=d.title,
                detection_status=d.detection_status.value,
                source=d.source.value,
                score_breadth=d.score_breadth,
                score_depth=d.score_depth,
                level=d.level.value if d.level else None,
                upstream_global_id=d.upstream_global_id,
            )
            for d in det_rows
        ]

        note_row = (
            await session.execute(
                select(TechniqueNote).where(
                    TechniqueNote.domain == domain,
                    TechniqueNote.technique_id == technique_id,
                )
            )
        ).scalar_one_or_none()
        if note_row is not None:
            note = TechniqueNoteOut(
                body=note_row.body,
                author_email=note_row.author_email,
                updated_at=note_row.updated_at.isoformat()
                if note_row.updated_at
                else "",
            )

    return TechniqueDetailOut(
        technique_id=tech.technique_id,
        domain=tech.domain,
        name=tech.name,
        description=tech.description,
        is_subtechnique=tech.is_subtechnique,
        parent_technique_id=tech.parent_technique_id,
        tactics=list(tech.tactics or []),
        platforms=list(tech.platforms or []),
        data_sources=list(tech.data_sources or []),
        deprecated=tech.deprecated,
        revoked=tech.revoked,
        url=tech.url,
        mitigations=mitigations,
        apt_groups=apt_groups,
        detections=detections,
        d3fend=d3fend_defenses,
        note=note,
    )


# ---- notes CRUD -----------------------------------------------------------

async def upsert_note(
    technique_id: str,
    body: str,
    *,
    author_email: Optional[str] = None,
    domain: str = "enterprise",
) -> TechniqueNoteOut:
    """Insert or replace the single note for (technique_id, domain)."""
    async with tenant_session() as session:
        existing = (
            await session.execute(
                select(TechniqueNote).where(
                    TechniqueNote.domain == domain,
                    TechniqueNote.technique_id == technique_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            row = TechniqueNote(
                technique_id=technique_id,
                domain=domain,
                body=body,
                author_email=author_email,
            )
            session.add(row)
        else:
            existing.body = body
            existing.author_email = author_email
            row = existing
        await session.flush()
        await session.refresh(row)
        out = TechniqueNoteOut(
            body=row.body,
            author_email=row.author_email,
            updated_at=row.updated_at.isoformat() if row.updated_at else "",
        )
    return out


async def delete_note(
    technique_id: str, *, domain: str = "enterprise"
) -> bool:
    async with tenant_session() as session:
        existing = (
            await session.execute(
                select(TechniqueNote).where(
                    TechniqueNote.domain == domain,
                    TechniqueNote.technique_id == technique_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            return False
        await session.delete(existing)
    return True


__all__ = [
    "APTUsage",
    "DetectionDetail",
    "MitigationDetail",
    "TechniqueDetailOut",
    "TechniqueNoteOut",
    "delete_note",
    "get_technique_detail",
    "upsert_note",
]
