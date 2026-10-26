"""D3FEND defensive-technique catalog ingest.

Source: d3fend.mitre.org's inferred mappings CSV. Each row links an ATT&CK
offensive technique to a D3FEND defensive technique via a relation predicate
(`d3f:detects`, `d3f:hardens`, `d3f:isolates`, …).

Idempotent on full re-run. Tests inject `fetch_fn` so they never hit the
network. The first time D3FEND is wired up, the catalog table is filled
by scanning the mappings CSV — D3FEND technique definitions come from the
same rows (a richer per-node lookup is deferred to a future pass).
"""
from __future__ import annotations

import csv
import io
import logging
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

import httpx
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import settings
from app.db.base import AsyncSessionLocal
from app.models.public import (
    AttackTechniqueD3FEND,
    D3FENDIngestRun,
    D3FENDTechnique,
)  # noqa: F401  (D3FENDTechnique used in d3fend_for_techniques)

log = logging.getLogger(__name__)

FetchFn = Callable[[], Awaitable[str]]


async def _http_fetch() -> str:
    url = settings.d3fend_mappings_url
    log.info("fetching D3FEND mappings: %s", url)
    async with httpx.AsyncClient(timeout=settings.d3fend_fetch_timeout) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.text


def _last_segment(iri: str) -> str:
    """Strip a D3FEND IRI down to its short form.

    Inputs like 'http://d3fend.mitre.org/ontologies/d3fend.owl#NetworkTrafficAnalysis'
    or 'd3f:NetworkTrafficAnalysis' both become 'NetworkTrafficAnalysis'.
    """
    if not iri:
        return ""
    s = str(iri).strip()
    if "#" in s:
        s = s.rsplit("#", 1)[1]
    if ":" in s:
        s = s.split(":", 1)[1]
    return s


def parse_mappings_csv(csv_text: str) -> dict:
    """Parse the D3FEND mappings CSV.

    Returns {techniques: [{d3fend_id, name, ...}], mappings: [{technique_id, d3fend_id, relation}]}.
    Column names in the upstream CSV are stable but we tolerate small drifts
    by matching case-insensitively on a known set of column hints.
    """
    reader = csv.DictReader(io.StringIO(csv_text))
    if reader.fieldnames is None:
        return {"techniques": [], "mappings": []}

    # The D3FEND CSV has a number of variants. We accept any of these column
    # heads for the relevant fields, case-insensitively.
    headers = {h.lower(): h for h in reader.fieldnames}

    def pick(*candidates: str) -> Optional[str]:
        for c in candidates:
            h = headers.get(c.lower())
            if h:
                return h
        return None

    col_attack = pick("off_tech_id", "off_tech", "attack_id", "offensive_technique_id")
    col_d3fend = pick("def_tech_id", "def_tech", "d3fend_id", "defensive_technique_id", "def_artifact_label")
    col_d3name = pick("def_tech_label", "def_tech_name", "d3fend_label")
    # The D3FEND CSV's per-row predicate (hardens, detects, strengthens,
    # isolates, …) — exposed via the artifact relation column. Older
    # dataset releases used a flatter `def_tech_rel_label` / `rel_label`,
    # so we still accept those.
    col_rel = pick(
        "def_artifact_rel_label",
        "def_tech_rel_label",
        "rel_label",
        "relation",
    )

    techniques: dict[str, dict] = {}
    mappings: list[dict] = []

    for row in reader:
        attack_id = (row.get(col_attack) or "").strip() if col_attack else ""
        d3raw = (row.get(col_d3fend) or "").strip() if col_d3fend else ""
        if not attack_id or not d3raw:
            continue
        d3id = _last_segment(d3raw)
        if not d3id:
            continue
        d3name = (row.get(col_d3name) or "").strip() if col_d3name else ""
        rel = (row.get(col_rel) or "").strip() if col_rel else ""
        if d3id not in techniques:
            techniques[d3id] = {
                "d3fend_id": d3id,
                "name": d3name or d3id,
                "definition": None,
                "parent_d3fend_id": None,
                "kind": None,
                "url": f"https://d3fend.mitre.org/technique/d3f:{d3id}/",
            }
        mappings.append({
            "domain": "enterprise",
            "technique_id": attack_id,
            "d3fend_id": d3id,
            "relation": rel or None,
        })

    return {
        "techniques": list(techniques.values()),
        "mappings": mappings,
    }


async def refresh(
    *,
    force: bool = False,
    fetch_fn: Optional[FetchFn] = None,
) -> dict:
    """Re-pull the D3FEND mappings + upsert the catalog tables.

    Returns a summary dict suitable for storing on `d3fend_ingest_runs`.
    """
    text = await (fetch_fn or _http_fetch)()
    parsed = parse_mappings_csv(text)
    techniques = parsed["techniques"]
    mappings = parsed["mappings"]

    if not techniques and not mappings:
        # Nothing parseable — record the run but don't flip is_current.
        async with AsyncSessionLocal() as session:
            run = D3FENDIngestRun(
                id=uuid.uuid4(),
                source_url=settings.d3fend_mappings_url,
                summary={"error": "no rows parsed", "techniques": 0, "mappings": 0},
                is_current=False,
            )
            session.add(run)
            await session.commit()
        return {"techniques": 0, "mappings": 0, "error": "no rows parsed"}

    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as session:
        # Upsert techniques
        if techniques:
            tech_rows = [
                {
                    "id": uuid.uuid4(),
                    "d3fend_id": t["d3fend_id"],
                    "name": t["name"][:300],
                    "definition": t.get("definition"),
                    "parent_d3fend_id": t.get("parent_d3fend_id"),
                    "kind": t.get("kind"),
                    "url": t.get("url"),
                    "ingested_at": now,
                }
                for t in techniques
            ]
            stmt = pg_insert(D3FENDTechnique).values(tech_rows)
            stmt = stmt.on_conflict_do_update(
                index_elements=["d3fend_id"],
                set_={
                    "name": stmt.excluded.name,
                    "definition": stmt.excluded.definition,
                    "parent_d3fend_id": stmt.excluded.parent_d3fend_id,
                    "kind": stmt.excluded.kind,
                    "url": stmt.excluded.url,
                    "ingested_at": now,
                },
            )
            await session.execute(stmt)

        # Upsert mappings
        if mappings:
            map_rows = [
                {
                    "id": uuid.uuid4(),
                    "domain": m["domain"],
                    "technique_id": m["technique_id"],
                    "d3fend_id": m["d3fend_id"],
                    "relation": m["relation"],
                }
                for m in mappings
            ]
            # Batch in chunks so very large CSVs don't blow up the parameter cap.
            BATCH = 1000
            for i in range(0, len(map_rows), BATCH):
                chunk = map_rows[i:i + BATCH]
                stmt = pg_insert(AttackTechniqueD3FEND).values(chunk)
                stmt = stmt.on_conflict_do_nothing(
                    index_elements=["domain", "technique_id", "d3fend_id", "relation"],
                )
                await session.execute(stmt)

        # Mark prior runs not-current
        await session.execute(
            update(D3FENDIngestRun)
            .where(D3FENDIngestRun.is_current.is_(True))
            .values(is_current=False)
        )
        run = D3FENDIngestRun(
            id=uuid.uuid4(),
            source_url=settings.d3fend_mappings_url,
            summary={
                "techniques": len(techniques),
                "mappings": len(mappings),
            },
            is_current=True,
        )
        session.add(run)
        await session.commit()

    return {
        "techniques": len(techniques),
        "mappings": len(mappings),
        "ingested_at": now.isoformat(),
    }


async def d3fend_for_techniques(technique_ids: list[str]) -> dict:
    """Return D3FEND linkage for a set of ATT&CK technique IDs.

    Shape:
      {
        "by_technique": {tid: [d3fend_id, ...]},
        "defenses": {d3fend_id: {"name": str, "relations": [str],
                                  "techniques": [tid]}},
      }
    Empty structure if nothing maps. Used by report exporters.
    """
    out_by_tech: dict[str, list[str]] = {}
    defenses: dict[str, dict] = {}
    if not technique_ids:
        return {"by_technique": out_by_tech, "defenses": defenses}

    async with AsyncSessionLocal() as session:
        links = (
            await session.execute(
                select(
                    AttackTechniqueD3FEND.technique_id,
                    AttackTechniqueD3FEND.d3fend_id,
                    AttackTechniqueD3FEND.relation,
                ).where(AttackTechniqueD3FEND.technique_id.in_(technique_ids))
            )
        ).all()
        if not links:
            return {"by_technique": out_by_tech, "defenses": defenses}
        d3_ids = sorted({d3id for (_t, d3id, _r) in links})
        names = dict(
            (
                await session.execute(
                    select(D3FENDTechnique.d3fend_id, D3FENDTechnique.name).where(
                        D3FENDTechnique.d3fend_id.in_(d3_ids)
                    )
                )
            ).all()
        )

    for tid, d3id, rel in links:
        out_by_tech.setdefault(tid, [])
        if d3id not in out_by_tech[tid]:
            out_by_tech[tid].append(d3id)
        entry = defenses.setdefault(
            d3id,
            {"name": names.get(d3id, d3id), "relations": set(), "techniques": set()},
        )
        if rel:
            entry["relations"].add(rel)
        entry["techniques"].add(tid)

    # Freeze sets to sorted lists for JSON-friendliness.
    for d3id, e in defenses.items():
        e["relations"] = sorted(e["relations"])
        e["techniques"] = sorted(e["techniques"])
    for tid in out_by_tech:
        out_by_tech[tid].sort()

    return {"by_technique": out_by_tech, "defenses": defenses}


__all__ = ["refresh", "parse_mappings_csv", "d3fend_for_techniques"]
