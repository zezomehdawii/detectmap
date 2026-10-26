"""ATT&CK STIX 2.1 catalog ingest.

Idempotent on `(domain, version)` — re-ingesting the same bundle is a no-op
unless `force=True`. Tests inject `fetch_fn` to bypass network round-trips.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Iterable, Optional

import httpx
from sqlalchemy import Table, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import settings
from app.db.base import AsyncSessionLocal
from app.models.public import (
    AttackCatalogVersion,
    AttackGroup,
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackMitigation,
    AttackSoftware,
    AttackSoftwareTechnique,
    AttackTechnique,
    AttackTechniqueMitigation,
)
from app.services.attack_diff import TechniqueSnapshot, compute_diff

log = logging.getLogger(__name__)

DOMAINS = ("enterprise", "ics", "mobile")

FetchFn = Callable[[str], Awaitable[dict]]


async def _http_fetch(domain: str) -> dict:
    url = f"{settings.attack_stix_base_url}/{domain}-attack/{domain}-attack.json"
    log.info("fetching ATT&CK bundle: %s", url)
    async with httpx.AsyncClient(timeout=settings.attack_stix_fetch_timeout) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


def _mitre_ref(obj: dict) -> Optional[dict]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref
    return None


def _bundle_version(bundle: dict) -> str:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            v = obj.get("x_mitre_version")
            if v:
                return str(v)
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern" and obj.get("x_mitre_version"):
            return str(obj["x_mitre_version"])
    return datetime.now(timezone.utc).strftime("%Y%m%d")


_SDO_TYPES_WITH_MITRE_REF = (
    "attack-pattern",
    "course-of-action",
    "intrusion-set",
    "malware",
    "tool",
)


def parse_bundle(domain: str, bundle: dict) -> dict[str, Any]:
    """Extract techniques + mitigations + groups + software + relationships."""
    stix_id_to_tid: dict[str, str] = {}
    stix_id_to_mid: dict[str, str] = {}
    stix_id_to_gid: dict[str, str] = {}
    stix_id_to_sid: dict[str, str] = {}
    # ATT&CK moved data sources out of the attack-pattern object (the
    # denormalised `x_mitre_data_sources` string list is gone). Two shapes
    # exist across versions, both resolved via `detects` relationships below:
    #   • legacy (≤ v16): data-component --detects--> technique, and the
    #     component carries `x_mitre_data_source_ref` → "Source: Component".
    #   • current (v17+): detection-strategy --detects--> technique; the
    #     strategy lists analytics, each analytic references data components
    #     via `x_mitre_log_source_references[].x_mitre_data_component_ref`.
    #     The DC→DS link was severed, so the data *component* name is the
    #     canonical telemetry unit ("Process Creation", "WMI Creation").
    data_source_names: dict[str, str] = {}   # x-mitre-data-source stix id → source name
    data_components: dict[str, dict] = {}     # x-mitre-data-component stix id → {name, source_ref}
    analytic_components: dict[str, set[str]] = {}   # analytic id → {data-component id}
    strategy_analytics: dict[str, list[str]] = {}   # detection-strategy id → [analytic id]
    techniques: list[dict] = []
    mitigations: list[dict] = []
    groups: list[dict] = []
    software: list[dict] = []

    for obj in bundle.get("objects", []):
        otype = obj.get("type")
        ref = _mitre_ref(obj) if otype in _SDO_TYPES_WITH_MITRE_REF else None
        if otype == "attack-pattern":
            tid = ref.get("external_id") if ref else None
            if not tid:
                continue
            stix_id_to_tid[obj["id"]] = tid
            tactics = [
                p.get("phase_name")
                for p in (obj.get("kill_chain_phases") or [])
                if p.get("phase_name")
            ]
            is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
            parent = tid.split(".")[0] if (is_sub and "." in tid) else None
            techniques.append(
                {
                    "domain": domain,
                    "technique_id": tid,
                    "parent_technique_id": parent,
                    "name": obj.get("name", "")[:300],
                    "description": obj.get("description"),
                    "tactics": tactics,
                    "platforms": obj.get("x_mitre_platforms") or [],
                    "data_sources": obj.get("x_mitre_data_sources") or [],
                    "is_subtechnique": is_sub,
                    "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                    "revoked": bool(obj.get("revoked", False)),
                    "url": ref.get("url") if ref else None,
                    "raw_stix": obj,
                }
            )
        elif otype == "course-of-action":
            mid = ref.get("external_id") if ref else None
            if not mid:
                continue
            stix_id_to_mid[obj["id"]] = mid
            mitigations.append(
                {
                    "domain": domain,
                    "mitigation_id": mid,
                    "name": obj.get("name", "")[:300],
                    "description": obj.get("description"),
                    "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                    "revoked": bool(obj.get("revoked", False)),
                    "url": ref.get("url") if ref else None,
                    "raw_stix": obj,
                }
            )
        elif otype == "intrusion-set":
            gid = ref.get("external_id") if ref else None
            if not gid:
                continue
            stix_id_to_gid[obj["id"]] = gid
            groups.append(
                {
                    "domain": domain,
                    "group_id": gid,
                    "name": obj.get("name", "")[:300],
                    "description": obj.get("description"),
                    "aliases": obj.get("aliases") or [],
                    "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                    "revoked": bool(obj.get("revoked", False)),
                    "url": ref.get("url") if ref else None,
                    "raw_stix": obj,
                }
            )
        elif otype in ("malware", "tool"):
            sid = ref.get("external_id") if ref else None
            if not sid:
                continue
            stix_id_to_sid[obj["id"]] = sid
            software.append(
                {
                    "domain": domain,
                    "software_id": sid,
                    "name": obj.get("name", "")[:300],
                    "kind": otype,
                    "description": obj.get("description"),
                    "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                    "revoked": bool(obj.get("revoked", False)),
                    "url": ref.get("url") if ref else None,
                    "raw_stix": obj,
                }
            )
        elif otype == "x-mitre-data-source":
            data_source_names[obj["id"]] = obj.get("name") or ""
        elif otype == "x-mitre-data-component":
            data_components[obj["id"]] = {
                "name": obj.get("name") or "",
                "source_ref": obj.get("x_mitre_data_source_ref"),
            }
        elif otype == "x-mitre-analytic":
            refs = {
                r.get("x_mitre_data_component_ref")
                for r in (obj.get("x_mitre_log_source_references") or [])
                if r.get("x_mitre_data_component_ref")
            }
            analytic_components[obj["id"]] = refs
        elif otype == "x-mitre-detection-strategy":
            strategy_analytics[obj["id"]] = list(obj.get("x_mitre_analytic_refs") or [])

    def _dc_label(dc_id: str) -> Optional[str]:
        dc = data_components.get(dc_id)
        if not dc:
            return None
        name = dc["name"]
        src = data_source_names.get(dc.get("source_ref") or "")
        return f"{src}: {name}" if (src and name) else (name or None)

    # technique_id → {data-source / component label, ...} from `detects`.
    tech_data_sources: dict[str, set[str]] = {}
    mitigates: list[dict] = []
    group_techs: list[dict] = []
    software_techs: list[dict] = []
    group_software: list[dict] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        rtype = obj.get("relationship_type")
        src_ref = obj.get("source_ref") or ""
        tgt_ref = obj.get("target_ref") or ""
        if rtype == "mitigates":
            mid = stix_id_to_mid.get(src_ref)
            tid = stix_id_to_tid.get(tgt_ref)
            if mid and tid:
                mitigates.append(
                    {"domain": domain, "technique_id": tid, "mitigation_id": mid}
                )
        elif rtype == "detects":
            tid = stix_id_to_tid.get(tgt_ref)
            if not tid:
                continue
            labels: set[str] = set()
            if src_ref in data_components:
                # legacy: data-component --detects--> technique
                lbl = _dc_label(src_ref)
                if lbl:
                    labels.add(lbl)
            elif src_ref in strategy_analytics:
                # current: detection-strategy --detects--> technique, expand
                # through its analytics to the underlying data components.
                for analytic_id in strategy_analytics[src_ref]:
                    for dc_id in analytic_components.get(analytic_id, set()):
                        lbl = _dc_label(dc_id)
                        if lbl:
                            labels.add(lbl)
            if labels:
                tech_data_sources.setdefault(tid, set()).update(labels)
        elif rtype == "uses":
            tid = stix_id_to_tid.get(tgt_ref)
            if not tid:
                # 'uses' can also point group -> software; capture that too.
                sid = stix_id_to_sid.get(tgt_ref)
                gid = stix_id_to_gid.get(src_ref)
                if gid and sid:
                    group_software.append(
                        {"domain": domain, "group_id": gid, "software_id": sid}
                    )
                continue
            gid = stix_id_to_gid.get(src_ref)
            sid = stix_id_to_sid.get(src_ref)
            if gid:
                group_techs.append(
                    {"domain": domain, "group_id": gid, "technique_id": tid}
                )
            elif sid:
                software_techs.append(
                    {"domain": domain, "software_id": sid, "technique_id": tid}
                )

    # Merge derived data sources into each technique, preserving any legacy
    # `x_mitre_data_sources` values (older bundles / test fixtures still carry
    # the denormalised field).
    for t in techniques:
        derived = tech_data_sources.get(t["technique_id"])
        if derived:
            t["data_sources"] = sorted(set(t["data_sources"]) | derived)

    return {
        "version": _bundle_version(bundle),
        "techniques": techniques,
        "mitigations": mitigations,
        "groups": groups,
        "software": software,
        "relationships": mitigates,
        "group_techniques": group_techs,
        "software_techniques": software_techs,
        "group_software": group_software,
    }


# asyncpg's binary protocol caps query parameters at 32767. Chunk well below
# that to stay safe with the widest model (techniques: 14 cols × N rows).
_CHUNK_ROWS = 1000


async def _upsert(
    session,
    table: Table,
    rows: Iterable[dict],
    *,
    constraint: str,
    update_cols: Iterable[str],
) -> None:
    """INSERT ... ON CONFLICT DO UPDATE for catalog rows.

    `id` defaults on the ORM model don't fire for Core inserts, so the caller
    can skip setting `id` and we fill it here.
    """
    rows = list(rows)
    if not rows:
        return
    for r in rows:
        r.setdefault("id", uuid.uuid4())
    for i in range(0, len(rows), _CHUNK_ROWS):
        chunk = rows[i : i + _CHUNK_ROWS]
        stmt = pg_insert(table).values(chunk)
        stmt = stmt.on_conflict_do_update(
            constraint=constraint,
            set_={c: stmt.excluded[c] for c in update_cols},
        )
        await session.execute(stmt)


_TECHNIQUE_UPDATE_COLS = (
    "parent_technique_id",
    "name",
    "description",
    "tactics",
    "platforms",
    "data_sources",
    "is_subtechnique",
    "deprecated",
    "revoked",
    "url",
    "raw_stix",
)

_MITIGATION_UPDATE_COLS = (
    "name",
    "description",
    "deprecated",
    "revoked",
    "url",
    "raw_stix",
)

_GROUP_UPDATE_COLS = (
    "name",
    "description",
    "aliases",
    "deprecated",
    "revoked",
    "url",
    "raw_stix",
)

_SOFTWARE_UPDATE_COLS = (
    "name",
    "kind",
    "description",
    "deprecated",
    "revoked",
    "url",
    "raw_stix",
)


async def _reset_rows(session, model, domain: str, rows: Iterable[dict]) -> None:
    """Replace all rows for a domain. Used for SRO join tables where the bundle
    is the source of truth and no per-row update semantics are needed."""
    await session.execute(delete(model).where(model.domain == domain))
    rows = list(rows)
    if not rows:
        return
    for r in rows:
        r.setdefault("id", uuid.uuid4())
    for i in range(0, len(rows), _CHUNK_ROWS):
        chunk = rows[i : i + _CHUNK_ROWS]
        await session.execute(pg_insert(model.__table__).values(chunk))


async def _previous_snapshots(session, domain: str) -> list[TechniqueSnapshot]:
    result = await session.execute(
        select(
            AttackTechnique.technique_id,
            AttackTechnique.name,
            AttackTechnique.deprecated,
            AttackTechnique.revoked,
        ).where(AttackTechnique.domain == domain)
    )
    return [
        {
            "technique_id": r.technique_id,
            "name": r.name,
            "deprecated": bool(r.deprecated),
            "revoked": bool(r.revoked),
        }
        for r in result.all()
    ]


def _new_snapshots(techniques: Iterable[dict]) -> list[TechniqueSnapshot]:
    return [
        {
            "technique_id": t["technique_id"],
            "name": t["name"],
            "deprecated": bool(t["deprecated"]),
            "revoked": bool(t["revoked"]),
        }
        for t in techniques
    ]


async def refresh_domain(
    domain: str,
    *,
    force: bool = False,
    fetch_fn: Optional[FetchFn] = None,
) -> dict:
    """Refresh one ATT&CK domain. Idempotent on `(domain, version)`."""
    if domain not in DOMAINS:
        raise ValueError(f"unknown domain: {domain!r}")

    fetcher = fetch_fn or _http_fetch
    bundle = await fetcher(domain)
    parsed = parse_bundle(domain, bundle)
    version = parsed["version"]

    async with AsyncSessionLocal() as session:
        async with session.begin():
            # FOR UPDATE so concurrent workers serialize on the version row
            # instead of racing the upsert + relationship reset.
            existing = (
                await session.execute(
                    select(AttackCatalogVersion)
                    .where(
                        AttackCatalogVersion.domain == domain,
                        AttackCatalogVersion.version == version,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if existing is not None and not force:
                log.info("ATT&CK %s already at version %s — no-op", domain, version)
                return {
                    "domain": domain,
                    "version": version,
                    "no_op": True,
                    "technique_count": len(parsed["techniques"]),
                    "mitigation_count": len(parsed["mitigations"]),
                    "relationship_count": len(parsed["relationships"]),
                    "group_count": len(parsed["groups"]),
                    "software_count": len(parsed["software"]),
                    "group_technique_count": len(parsed["group_techniques"]),
                    "software_technique_count": len(parsed["software_techniques"]),
                }

            prev_snapshots = await _previous_snapshots(session, domain)
            await _upsert(
                session,
                AttackTechnique.__table__,
                parsed["techniques"],
                constraint="uq_attack_domain_tid",
                update_cols=_TECHNIQUE_UPDATE_COLS,
            )
            await _upsert(
                session,
                AttackMitigation.__table__,
                parsed["mitigations"],
                constraint="uq_attack_domain_mid",
                update_cols=_MITIGATION_UPDATE_COLS,
            )
            await _upsert(
                session,
                AttackGroup.__table__,
                parsed["groups"],
                constraint="uq_attack_domain_gid",
                update_cols=_GROUP_UPDATE_COLS,
            )
            await _upsert(
                session,
                AttackSoftware.__table__,
                parsed["software"],
                constraint="uq_attack_domain_sid",
                update_cols=_SOFTWARE_UPDATE_COLS,
            )
            await _reset_rows(
                session, AttackTechniqueMitigation, domain, parsed["relationships"]
            )
            await _reset_rows(
                session, AttackGroupTechnique, domain, parsed["group_techniques"]
            )
            await _reset_rows(
                session, AttackSoftwareTechnique, domain, parsed["software_techniques"]
            )
            await _reset_rows(
                session, AttackGroupSoftware, domain, parsed["group_software"]
            )

            diff = compute_diff(prev_snapshots, _new_snapshots(parsed["techniques"]))
            summary = {
                "technique_count": len(parsed["techniques"]),
                "mitigation_count": len(parsed["mitigations"]),
                "relationship_count": len(parsed["relationships"]),
                "group_count": len(parsed["groups"]),
                "software_count": len(parsed["software"]),
                "group_technique_count": len(parsed["group_techniques"]),
                "software_technique_count": len(parsed["software_techniques"]),
                "diff": diff,
            }

            if existing is None:
                await session.execute(
                    update(AttackCatalogVersion)
                    .where(
                        AttackCatalogVersion.domain == domain,
                        AttackCatalogVersion.is_current.is_(True),
                    )
                    .values(is_current=False)
                )
                session.add(
                    AttackCatalogVersion(
                        id=uuid.uuid4(),
                        domain=domain,
                        version=version,
                        summary=summary,
                        is_current=True,
                    )
                )
            else:
                existing.summary = summary
                if not existing.is_current:
                    await session.execute(
                        update(AttackCatalogVersion)
                        .where(
                            AttackCatalogVersion.domain == domain,
                            AttackCatalogVersion.is_current.is_(True),
                        )
                        .values(is_current=False)
                    )
                    existing.is_current = True

            log.info(
                "ATT&CK %s ingested v=%s techniques=%d mitigations=%d rels=%d",
                domain,
                version,
                summary["technique_count"],
                summary["mitigation_count"],
                summary["relationship_count"],
            )

    return {"domain": domain, "version": version, "no_op": False, **summary}


async def refresh_all(
    domains: Optional[Iterable[str]] = None,
    *,
    force: bool = False,
    fetch_fn: Optional[FetchFn] = None,
) -> dict:
    """Refresh multiple ATT&CK domains in parallel; defaults to all three."""
    targets = tuple(domains) if domains else DOMAINS
    results = await asyncio.gather(
        *(refresh_domain(d, force=force, fetch_fn=fetch_fn) for d in targets)
    )
    return dict(zip(targets, results))


__all__ = [
    "DOMAINS",
    "FetchFn",
    "parse_bundle",
    "refresh_domain",
    "refresh_all",
]
