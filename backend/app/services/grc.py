"""GRC service: control coverage rollup + evidence shaping.

A control "inherits" the best state across its mapped ATT&CK techniques.
That gives an analyst a one-line answer: "for control PR.PS-04, do we have
detection coverage of any of its mapped TTPs, and how deep is it?"
"""
from __future__ import annotations

import csv
import io
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from sqlalchemy import func, select

from app.db.base import AsyncSessionLocal
from app.db.tenant import tenant_session
from app.models.customer import DetectionStatus
from app.models.public import (
    AttackTechniqueD3FEND,
    D3FENDTechnique,
    GRCControl,
    GRCFramework,
    GRCMitigationMapping,
    GRCTechniqueMapping,
)
from app.services.coverage import (
    CoverageState,
    _cell_state,
    _fetch_tenant_coverage,
)

log = logging.getLogger(__name__)


class ControlCoverageState(str, Enum):
    """Per-control rollup state — what the GRC UI paints on each row."""
    UNMAPPED = "unmapped"       # no techniques mapped at all
    GAP = "gap"                 # mapped, but every technique is uncovered
    IDEA = "idea"               # only 'idea' detections cover any mapped TTP
    IN_PROGRESS = "in_progress" # at least one mapped TTP in dev/tuning
    PARTIAL = "partial"         # some mapped TTPs deployed, some not
    DEPLOYED = "deployed"       # every mapped TTP has a deployed detection


@dataclass
class ControlCoverage:
    id: str
    control_id: str
    parent_control_id: Optional[str]
    family: Optional[str]
    name: str
    description: Optional[str]
    sort_order: int
    technique_count: int
    mapped_techniques: list[str]
    seeded_count: int
    user_count: int
    state: ControlCoverageState
    deployed_count: int
    in_progress_count: int
    idea_count: int
    gap_count: int
    # Count of distinct D3FEND defensive techniques derived from this
    # control's mapped ATT&CK techniques (control → ATT&CK → D3FEND).
    d3fend_count: int = 0


@dataclass
class FrameworkCoverage:
    framework_key: str
    framework_label: str
    framework_version: Optional[str]
    controls: list[ControlCoverage] = field(default_factory=list)
    counts_by_state: dict[str, int] = field(default_factory=dict)


# ---- summaries -----------------------------------------------------------

async def framework_summary() -> list[dict]:
    """List frameworks with control + mapping counts (no tenant context needed)."""
    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(
                    GRCFramework.key,
                    GRCFramework.label,
                    GRCFramework.version,
                    GRCFramework.description,
                    func.count(GRCControl.id.distinct()).label("control_count"),
                )
                .outerjoin(GRCControl, GRCControl.framework_id == GRCFramework.id)
                .group_by(
                    GRCFramework.key,
                    GRCFramework.label,
                    GRCFramework.version,
                    GRCFramework.description,
                )
                .order_by(GRCFramework.label)
            )
        ).all()

        # Tally mappings per framework in a second pass to keep the SQL simple.
        tech_rows = (
            await session.execute(
                select(
                    GRCFramework.key,
                    func.count(GRCTechniqueMapping.id).label("n"),
                )
                .join(GRCControl, GRCControl.framework_id == GRCFramework.id)
                .join(
                    GRCTechniqueMapping,
                    GRCTechniqueMapping.control_id == GRCControl.id,
                )
                .group_by(GRCFramework.key)
            )
        ).all()
        techs_by_key = {r.key: int(r.n) for r in tech_rows}

        mit_rows = (
            await session.execute(
                select(
                    GRCFramework.key,
                    func.count(GRCMitigationMapping.id).label("n"),
                )
                .join(GRCControl, GRCControl.framework_id == GRCFramework.id)
                .join(
                    GRCMitigationMapping,
                    GRCMitigationMapping.control_id == GRCControl.id,
                )
                .group_by(GRCFramework.key)
            )
        ).all()
        mits_by_key = {r.key: int(r.n) for r in mit_rows}

        return [
            {
                "key": r.key,
                "label": r.label,
                "version": r.version,
                "description": r.description,
                "control_count": int(r.control_count),
                "technique_mapping_count": techs_by_key.get(r.key, 0),
                "mitigation_mapping_count": mits_by_key.get(r.key, 0),
            }
            for r in rows
        ]


# ---- control coverage rollup --------------------------------------------

def _rollup_state(statuses_per_technique: list[list[DetectionStatus]]) -> ControlCoverageState:
    """Reduce a control's technique-coverage list into a single state.

    Rules:
      - No mapped techniques at all → caller passes empty list → UNMAPPED
      - Every mapped technique has a deployed detection → DEPLOYED
      - Some but not all mapped techniques have deployed detections → PARTIAL
      - At least one mapped technique is in dev/tuning → IN_PROGRESS
      - All mapped techniques have only idea detections → IDEA
      - No technique covered → GAP
    """
    if not statuses_per_technique:
        return ControlCoverageState.UNMAPPED

    per_tech_states = [
        _cell_state(in_scope=True, statuses=s) for s in statuses_per_technique
    ]

    deployed = sum(1 for s in per_tech_states if s == CoverageState.DEPLOYED)
    in_progress = sum(1 for s in per_tech_states if s == CoverageState.IN_PROGRESS)
    idea = sum(1 for s in per_tech_states if s == CoverageState.IDEA)
    gap = sum(1 for s in per_tech_states if s in (CoverageState.GAP,))

    total = len(per_tech_states)
    if deployed == total:
        return ControlCoverageState.DEPLOYED
    if deployed > 0:
        return ControlCoverageState.PARTIAL
    if in_progress > 0:
        return ControlCoverageState.IN_PROGRESS
    if idea > 0:
        return ControlCoverageState.IDEA
    if gap == total:
        return ControlCoverageState.GAP
    # Mixed N/A-only cases fall back to gap.
    return ControlCoverageState.GAP


async def control_coverage(framework_key: str) -> Optional[FrameworkCoverage]:
    """Per-control rollup of detection state across mapped ATT&CK techniques."""
    async with AsyncSessionLocal() as session:
        fw = (
            await session.execute(
                select(GRCFramework).where(GRCFramework.key == framework_key)
            )
        ).scalar_one_or_none()
        if fw is None:
            return None

        controls = (
            await session.execute(
                select(GRCControl)
                .where(GRCControl.framework_id == fw.id)
                .order_by(GRCControl.sort_order, GRCControl.control_id)
            )
        ).scalars().all()

        mappings = (
            await session.execute(
                select(
                    GRCTechniqueMapping.control_id,
                    GRCTechniqueMapping.technique_id,
                    GRCTechniqueMapping.source,
                ).where(
                    GRCTechniqueMapping.control_id.in_([c.id for c in controls])
                )
            )
        ).all() if controls else []

    by_control: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for r in mappings:
        by_control[str(r.control_id)].append((r.technique_id, r.source))

    all_tids = sorted({tid for rows in by_control.values() for (tid, _) in rows})

    if all_tids:
        async with tenant_session() as session:
            tenant_cov = await _fetch_tenant_coverage(session, all_tids)
    else:
        tenant_cov = {}

    # Map each ATT&CK technique to its set of D3FEND defensive techniques so
    # we can roll a "defenses available" count up to each control.
    d3fend_by_tid: dict[str, set[str]] = defaultdict(set)
    if all_tids:
        async with AsyncSessionLocal() as session:
            d3_rows = (
                await session.execute(
                    select(
                        AttackTechniqueD3FEND.technique_id,
                        AttackTechniqueD3FEND.d3fend_id,
                    ).where(AttackTechniqueD3FEND.technique_id.in_(all_tids))
                )
            ).all()
        for tid, d3id in d3_rows:
            d3fend_by_tid[tid].add(d3id)

    result_controls: list[ControlCoverage] = []
    state_counts: dict[str, int] = defaultdict(int)

    for c in controls:
        rows = by_control.get(str(c.id), [])
        tids = sorted({tid for (tid, _) in rows})
        sources = [s for (_, s) in rows]
        seeded_count = sum(1 for s in sources if s == "seeded")
        user_count = sum(1 for s in sources if s == "user")

        statuses_per_tech = [tenant_cov.get(t, {}).get("statuses", []) for t in tids]
        state = _rollup_state(statuses_per_tech)

        deployed = sum(
            1
            for s in statuses_per_tech
            if _cell_state(in_scope=True, statuses=s) == CoverageState.DEPLOYED
        )
        in_progress = sum(
            1
            for s in statuses_per_tech
            if _cell_state(in_scope=True, statuses=s) == CoverageState.IN_PROGRESS
        )
        idea = sum(
            1
            for s in statuses_per_tech
            if _cell_state(in_scope=True, statuses=s) == CoverageState.IDEA
        )
        gap = sum(
            1
            for s in statuses_per_tech
            if _cell_state(in_scope=True, statuses=s) == CoverageState.GAP
        )

        d3fend_ids: set[str] = set()
        for t in tids:
            d3fend_ids |= d3fend_by_tid.get(t, set())

        result_controls.append(
            ControlCoverage(
                id=str(c.id),
                control_id=c.control_id,
                parent_control_id=c.parent_control_id,
                family=c.family,
                name=c.name,
                description=c.description,
                sort_order=c.sort_order,
                technique_count=len(tids),
                mapped_techniques=tids,
                seeded_count=seeded_count,
                user_count=user_count,
                state=state,
                deployed_count=deployed,
                in_progress_count=in_progress,
                idea_count=idea,
                gap_count=gap,
                d3fend_count=len(d3fend_ids),
            )
        )
        state_counts[state.value] += 1

    return FrameworkCoverage(
        framework_key=fw.key,
        framework_label=fw.label,
        framework_version=fw.version,
        controls=result_controls,
        counts_by_state={s.value: state_counts.get(s.value, 0) for s in ControlCoverageState},
    )


# ---- evidence export ----------------------------------------------------

async def evidence_payload(framework_key: str) -> Optional[dict]:
    """Compact JSON-shaped evidence for compliance reporting."""
    coverage = await control_coverage(framework_key)
    if coverage is None:
        return None
    return {
        "framework": {
            "key": coverage.framework_key,
            "label": coverage.framework_label,
            "version": coverage.framework_version,
        },
        "counts_by_state": coverage.counts_by_state,
        "controls": [
            {
                "control_id": c.control_id,
                "parent_control_id": c.parent_control_id,
                "name": c.name,
                "family": c.family,
                "state": c.state.value,
                "mapped_techniques": c.mapped_techniques,
                "deployed_count": c.deployed_count,
                "in_progress_count": c.in_progress_count,
                "idea_count": c.idea_count,
                "gap_count": c.gap_count,
                "mappings_total": c.technique_count,
                "user_mappings": c.user_count,
            }
            for c in coverage.controls
        ],
    }


def evidence_csv(payload: dict) -> bytes:
    """CSV-shaped evidence — one row per control."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "framework",
            "control_id",
            "name",
            "family",
            "state",
            "deployed_count",
            "in_progress_count",
            "idea_count",
            "gap_count",
            "mappings_total",
            "user_mappings",
            "mapped_techniques",
        ]
    )
    fk = payload["framework"]["key"]
    for c in payload["controls"]:
        w.writerow(
            [
                fk,
                c["control_id"],
                c["name"],
                c["family"] or "",
                c["state"],
                c["deployed_count"],
                c["in_progress_count"],
                c["idea_count"],
                c["gap_count"],
                c["mappings_total"],
                c["user_mappings"],
                ";".join(c["mapped_techniques"]),
            ]
        )
    return buf.getvalue().encode("utf-8")


def evidence_json(payload: dict) -> bytes:
    return json.dumps(payload, indent=2).encode("utf-8")


# ---- scorecard (per-framework rollup) ------------------------------------

async def scorecard() -> list[dict]:
    """Per-framework compliance scorecard for the active tenant.

    `addressed_pct` = controls with any coverage (not unmapped/gap) / total.
    `deployed_pct`  = fully-deployed controls / total. Weighted score gives
    partial credit so the headline number tracks real progress.
    """
    frameworks = await framework_summary()
    out: list[dict] = []
    for fw in frameworks:
        cov = await control_coverage(fw["key"])
        if cov is None:
            continue
        counts = cov.counts_by_state
        total = sum(counts.values()) or 0
        deployed = counts.get("deployed", 0)
        partial = counts.get("partial", 0)
        in_prog = counts.get("in_progress", 0)
        idea = counts.get("idea", 0)
        gap = counts.get("gap", 0)
        unmapped = counts.get("unmapped", 0)
        addressed = total - gap - unmapped
        weighted = deployed * 1.0 + partial * 0.6 + in_prog * 0.3 + idea * 0.1
        out.append(
            {
                "key": fw["key"],
                "label": fw["label"],
                "version": fw["version"],
                "total_controls": total,
                "counts_by_state": counts,
                "deployed_pct": round(100.0 * deployed / total, 1) if total else 0.0,
                "addressed_pct": round(100.0 * addressed / total, 1) if total else 0.0,
                "weighted_pct": round(100.0 * weighted / total, 1) if total else 0.0,
            }
        )
    return out


def evidence_pdf(payload: dict) -> bytes:
    """Per-framework compliance evidence pack — hierarchical by family/domain.

    Layout:
      1. Cover header — customer + framework + version, NCA badge for NCA.*.
      2. Summary table — one row per control-coverage state with counts/pct.
      3. One section per `family` (i.e. ECC domain / ISO clause family /
         NCA family). Each section starts on a new page and lists the
         section's controls, indenting sub-controls under their parent.

    Designed so a non-technical reader (auditor, CISO board pack) can navigate
    by section without scrolling through one giant table.
    """
    from collections import defaultdict
    from datetime import datetime, timezone

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    INDIGO = colors.HexColor("#4f46e5")  # matches the UI theme
    NCA_GREEN = colors.HexColor("#0f766e")  # NCA cluster cue
    GREY_BORDER = colors.HexColor("#d1d5db")
    GREY_BG = colors.HexColor("#f3f4f6")

    # Per-state row tint for the per-section tables — quick visual scan.
    STATE_TINT: dict[str, colors.Color] = {
        "deployed": colors.HexColor("#dcfce7"),
        "partial": colors.HexColor("#fef3c7"),
        "in_progress": colors.HexColor("#fef3c7"),
        "idea": colors.HexColor("#e0e7ff"),
        "gap": colors.HexColor("#fee2e2"),
        "unmapped": colors.HexColor("#f3f4f6"),
    }

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, topMargin=16 * mm, bottomMargin=16 * mm,
        leftMargin=14 * mm, rightMargin=14 * mm,
    )
    styles = getSampleStyleSheet()
    fw = payload["framework"]
    counts = payload.get("counts_by_state", {}) or {}
    tenant = payload.get("tenant") or {}
    is_nca = (fw.get("key") or "").startswith("nca_")
    accent = NCA_GREEN if is_nca else INDIGO

    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        textColor=accent,
        spaceBefore=4,
        spaceAfter=4,
    )
    subtle_style = ParagraphStyle(
        "Subtle",
        parent=styles["Normal"],
        textColor=colors.HexColor("#6b7280"),
        fontSize=9,
    )

    # ---- 1) Cover header ----------------------------------------------------
    elements: list = []
    elements.append(
        Paragraph(
            f"Compliance evidence — {fw['label']}"
            + (f" v{fw['version']}" if fw.get("version") else ""),
            styles["Title"],
        )
    )
    bits = []
    if tenant.get("name"):
        bits.append(f"<b>{tenant['name']}</b>")
    if tenant.get("codename"):
        bits.append(f"<i>{tenant['codename']}</i>")
    bits.append(f"framework key: {fw['key']}")
    bits.append(
        "generated " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    )
    if is_nca:
        bits.append("Saudi NCA framework family")
    elements.append(Paragraph(" · ".join(bits), subtle_style))
    elements.append(Spacer(1, 5 * mm))

    # ---- 2) Summary table ---------------------------------------------------
    total = sum(counts.values()) or 0
    state_order = ["deployed", "partial", "in_progress", "idea", "gap", "unmapped"]
    summary_rows = [["State", "Count", "% of controls"]]
    for s in state_order:
        n = counts.get(s, 0)
        pct = f"{(100 * n / total):.1f}%" if total else "—"
        summary_rows.append([s.replace("_", " "), str(n), pct])
    summary_rows.append(["Total", str(total), "100%" if total else "—"])
    summary_table = Table(
        summary_rows, repeatRows=1,
        colWidths=[55 * mm, 30 * mm, 35 * mm],
    )
    summary_styles: list = [
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.25, GREY_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), GREY_BG),
    ]
    # Tint each summary row by state colour for quick visual read.
    for i, s in enumerate(state_order, start=1):
        tint = STATE_TINT.get(s)
        if tint is not None:
            summary_styles.append(("BACKGROUND", (0, i), (-1, i), tint))
    summary_table.setStyle(TableStyle(summary_styles))
    elements.append(summary_table)
    elements.append(Spacer(1, 4 * mm))

    elements.append(
        Paragraph(
            "Per-control evidence follows, organised by domain. "
            "Sub-controls are indented under their parent control. The "
            "'Deployed / mapped' column shows how many of the control's "
            "mapped ATT&CK techniques have a deployed detection.",
            subtle_style,
        )
    )

    # ---- 3) Per-family sections --------------------------------------------
    # Group controls by family in the order they first appear in the payload
    # (the seeder lists them in domain order via sort_order, so the families
    # come out in their natural domain sequence).
    families: dict[str, list[dict]] = defaultdict(list)
    family_order: list[str] = []
    for c in payload["controls"]:
        fam = c.get("family") or "Other"
        if fam not in families:
            family_order.append(fam)
        families[fam].append(c)

    def _control_row(c: dict, indent: bool) -> list[str]:
        name = (c.get("name") or "")[:90]
        if indent:
            name = "    " + name
        deployed = c["deployed_count"]
        mapped = c["mappings_total"]
        ratio = f"{deployed}/{mapped}" if mapped else "—"
        return [
            c["control_id"],
            name,
            c["state"].replace("_", " "),
            ratio,
            str(c.get("user_mappings", 0)),
        ]

    for idx, fam in enumerate(family_order):
        if idx > 0:
            elements.append(PageBreak())
        else:
            elements.append(Spacer(1, 4 * mm))
        elements.append(Paragraph(fam, section_style))

        ctrls = families[fam]
        # Sort: parents first (by control_id), then sub-controls under their
        # parent. The seed's sort_order already does this for NCA / NIST, but
        # we re-sort defensively in case the data drifts.
        parents = [c for c in ctrls if not c.get("parent_control_id")]
        parents.sort(key=lambda c: c["control_id"])
        children_by_parent: dict[str, list[dict]] = defaultdict(list)
        orphans: list[dict] = []
        parent_ids = {p["control_id"] for p in parents}
        for c in ctrls:
            pid = c.get("parent_control_id")
            if pid is None:
                continue
            if pid in parent_ids:
                children_by_parent[pid].append(c)
            else:
                orphans.append(c)
        for kids in children_by_parent.values():
            kids.sort(key=lambda c: c["control_id"])

        rows = [["Control", "Name", "State", "Deployed / mapped", "User maps"]]
        # Track row indices per state for tinting.
        row_states: list[Optional[str]] = [None]  # header
        for p in parents:
            rows.append(_control_row(p, indent=False))
            row_states.append(p["state"])
            for k in children_by_parent.get(p["control_id"], []):
                rows.append(_control_row(k, indent=True))
                row_states.append(k["state"])
        for o in orphans:
            rows.append(_control_row(o, indent=False))
            row_states.append(o["state"])

        section_table = Table(
            rows, repeatRows=1,
            colWidths=[26 * mm, 92 * mm, 22 * mm, 28 * mm, 16 * mm],
        )
        style_cmds: list = [
            ("BACKGROUND", (0, 0), (-1, 0), accent),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.25, GREY_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),  # control ID col
        ]
        for ridx, st in enumerate(row_states):
            if ridx == 0 or st is None:
                continue
            tint = STATE_TINT.get(st)
            if tint is not None:
                style_cmds.append(("BACKGROUND", (0, ridx), (-1, ridx), tint))
        section_table.setStyle(TableStyle(style_cmds))
        # Keep the section header + first few rows together so we don't
        # orphan a heading at the bottom of a page.
        elements.append(KeepTogether([section_table]))

    doc.build(elements)
    return buf.getvalue()


# ---- D3FEND crosswalk ----------------------------------------------------

@dataclass
class ControlD3FEND:
    d3fend_id: str
    name: str
    relations: list[str]          # d3f:detects, d3f:hardens, …
    via_techniques: list[str]     # ATT&CK technique IDs that surfaced it


async def control_d3fend(control_uuid: str) -> Optional[list[ControlD3FEND]]:
    """Derive a control's defensive countermeasures via ATT&CK → D3FEND.

    Returns None when the control doesn't exist, else a list (possibly
    empty) of distinct D3FEND techniques the control's mapped ATT&CK
    techniques are addressed by.
    """
    import uuid as _uuid

    async with AsyncSessionLocal() as session:
        ctrl = (
            await session.execute(
                select(GRCControl).where(GRCControl.id == _uuid.UUID(str(control_uuid)))
            )
        ).scalar_one_or_none()
        if ctrl is None:
            return None

        tids = (
            await session.execute(
                select(GRCTechniqueMapping.technique_id).where(
                    GRCTechniqueMapping.control_id == ctrl.id
                )
            )
        ).scalars().all()
        tids = sorted(set(tids))
        if not tids:
            return []

        links = (
            await session.execute(
                select(
                    AttackTechniqueD3FEND.d3fend_id,
                    AttackTechniqueD3FEND.technique_id,
                    AttackTechniqueD3FEND.relation,
                ).where(AttackTechniqueD3FEND.technique_id.in_(tids))
            )
        ).all()
        if not links:
            return []

        d3_ids = sorted({d3id for (d3id, _t, _r) in links})
        names = dict(
            (
                await session.execute(
                    select(D3FENDTechnique.d3fend_id, D3FENDTechnique.name).where(
                        D3FENDTechnique.d3fend_id.in_(d3_ids)
                    )
                )
            ).all()
        )

    agg: dict[str, dict] = {}
    for d3id, tid, rel in links:
        entry = agg.setdefault(
            d3id, {"relations": set(), "via": set()}
        )
        if rel:
            entry["relations"].add(rel)
        entry["via"].add(tid)

    return [
        ControlD3FEND(
            d3fend_id=d3id,
            name=names.get(d3id, d3id),
            relations=sorted(v["relations"]),
            via_techniques=sorted(v["via"]),
        )
        for d3id, v in sorted(agg.items())
    ]


__all__ = [
    "ControlCoverage",
    "ControlCoverageState",
    "ControlD3FEND",
    "FrameworkCoverage",
    "control_coverage",
    "control_d3fend",
    "evidence_csv",
    "evidence_json",
    "evidence_payload",
    "framework_summary",
]
