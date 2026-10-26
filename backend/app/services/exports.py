"""Report exporters.

Pure-ish builders that turn `CoverageMatrix` / `CoverageScore` / tenant
detection rows into downloadable bytes. The API layer wraps these in
`Response` objects with the right MIME types.
"""
from __future__ import annotations

import csv
import io
import zipfile
from datetime import datetime, timezone
from typing import Iterable, Optional

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.customer import Detection
from app.services.coverage import CoverageMatrix, CoverageScore, CoverageState

# Coverage cell colours — these mirror frontend/app/theme.ts so the UI legend
# and downloaded reports speak the same visual language.
COVERAGE_COLOR = {
    CoverageState.DEPLOYED.value: "#2fb673",
    CoverageState.IN_PROGRESS.value: "#f0a830",
    CoverageState.IDEA.value: "#d6d8e0",
    CoverageState.GAP.value: "#e23a3a",
    CoverageState.NOT_APPLICABLE.value: "#5780e8",
    CoverageState.OUT_OF_SCOPE.value: "#b8b8c2",
}

GRADE_COLOR = {
    "A": "#2fb673",
    "B": "#f0a830",
    "C": "#e8895d",
    "D": "#e23a3a",
}


# ---- CSV / XLSX -----------------------------------------------------------

def _flatten_cells(matrix: CoverageMatrix):
    """Yield (tactic, cell) for every cell across the matrix, in display order."""
    for tac in matrix.tactics:
        for cell in matrix.by_tactic.get(tac, []):
            yield tac, cell


def to_csv(matrix: CoverageMatrix) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "tactic",
            "technique_id",
            "name",
            "is_subtechnique",
            "parent_technique_id",
            "state",
            "detection_count",
            "deployed_count",
            "max_depth",
        ]
    )
    for tac, c in _flatten_cells(matrix):
        writer.writerow(
            [
                tac,
                c.technique_id,
                c.name,
                "yes" if c.is_subtechnique else "no",
                c.parent_technique_id or "",
                c.state.value,
                c.detection_count,
                c.deployed_count,
                c.max_depth,
            ]
        )
    return buf.getvalue().encode("utf-8")


def to_xlsx(matrix: CoverageMatrix, score: CoverageScore) -> bytes:
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    summary.append(["Detection Map — Coverage Report"])
    summary["A1"].font = Font(bold=True, size=14)
    summary.append([])
    summary.append(["Domain", matrix.domain])
    summary.append(["Denominator", matrix.denominator_kind.value])
    summary.append(["Denominator ref", matrix.denominator_ref or ""])
    summary.append(["Technique count", matrix.technique_count])
    summary.append(
        [
            "Generated at",
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        ]
    )
    summary.append([])
    summary.append(["Posture grade", score.posture_grade])
    summary.append(["Breadth grade", score.breadth_grade])
    summary.append(["Depth grade", score.depth_grade])
    summary.append(["Breadth %", round(score.breadth_pct * 100, 1)])
    summary.append(["Depth (avg)", round(score.depth_avg, 2)])
    summary.append(["Covered count", score.covered_count])
    summary.append(["Deployed count", score.deployed_count])
    summary.append([])
    summary.append(["State", "Count"])
    for state, n in score.state_counts.items():
        summary.append([state, n])
    summary.column_dimensions["A"].width = 28
    summary.column_dimensions["B"].width = 30

    grid = wb.create_sheet("Techniques")
    header = [
        "Tactic",
        "Technique ID",
        "Name",
        "Sub-technique",
        "Parent",
        "State",
        "Detections",
        "Deployed",
        "Max depth",
    ]
    grid.append(header)
    for col_idx in range(1, len(header) + 1):
        cell = grid.cell(row=1, column=col_idx)
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="EEEFF6")

    for tac, c in _flatten_cells(matrix):
        grid.append(
            [
                tac,
                c.technique_id,
                c.name,
                "yes" if c.is_subtechnique else "no",
                c.parent_technique_id or "",
                c.state.value,
                c.detection_count,
                c.deployed_count,
                c.max_depth,
            ]
        )
        # Tint the state cell.
        hex_color = COVERAGE_COLOR.get(c.state.value, "#FFFFFF").lstrip("#")
        grid.cell(row=grid.max_row, column=6).fill = PatternFill(
            "solid", fgColor=hex_color
        )
        grid.cell(row=grid.max_row, column=6).alignment = Alignment(horizontal="center")

    widths = [22, 14, 50, 14, 12, 14, 12, 12, 12]
    for i, w in enumerate(widths, start=1):
        grid.column_dimensions[chr(ord("A") + i - 1)].width = w
    grid.freeze_panes = "A2"

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ---- ATT&CK Navigator layer ----------------------------------------------

def to_navigator_layer(
    matrix: CoverageMatrix,
    score: CoverageScore,
    *,
    customer_name: Optional[str] = None,
    attack_version: str = "15",
    navigator_version: str = "4.9.4",
    d3fend_by_technique: Optional[dict] = None,
) -> dict:
    """Return a Navigator-compatible layer JSON dict.

    Schema: https://github.com/mitre-attack/attack-navigator
    We emit a flat techniques list with `score = max_depth (0-5)` and a
    state-based `color`. The Navigator picks `color` over `score` when
    `gradient` is set with one stop, but we provide both so users can flip
    to the gradient view and see depth visualised.
    """
    techniques: list[dict] = []
    seen: set[str] = set()
    for _tac, cell in _flatten_cells(matrix):
        if cell.technique_id in seen:
            # The same technique can appear under multiple tactics; Navigator
            # supports per-tactic entries but we collapse here for simplicity.
            continue
        seen.add(cell.technique_id)
        meta = [
            {"name": "state", "value": cell.state.value},
            {"name": "detection_count", "value": str(cell.detection_count)},
            {"name": "deployed_count", "value": str(cell.deployed_count)},
            {"name": "max_depth", "value": str(cell.max_depth)},
        ]
        defenses = (d3fend_by_technique or {}).get(cell.technique_id) or []
        if defenses:
            meta.append(
                {"name": "d3fend_defenses", "value": ", ".join(defenses)}
            )
        techniques.append(
            {
                "techniqueID": cell.technique_id,
                "score": cell.max_depth,
                "color": COVERAGE_COLOR.get(cell.state.value, ""),
                "comment": (
                    f"state={cell.state.value} "
                    f"detections={cell.detection_count} "
                    f"deployed={cell.deployed_count}"
                    + (f" d3fend={len(defenses)}" if defenses else "")
                ),
                "enabled": True,
                "metadata": meta,
            }
        )

    name = "Detection Map coverage"
    if customer_name:
        name = f"{customer_name} — {name}"
    description = (
        f"Denominator: {matrix.denominator_kind.value}"
        + (f" ({matrix.denominator_ref})" if matrix.denominator_ref else "")
        + f". Breadth {round(score.breadth_pct * 100, 1)}% (grade {score.breadth_grade}), "
        + f"depth avg {round(score.depth_avg, 2)} (grade {score.depth_grade}), "
        + f"posture {score.posture_grade}."
    )

    return {
        "name": name,
        "versions": {
            "attack": attack_version,
            "navigator": navigator_version,
            "layer": "4.5",
        },
        "domain": (
            "enterprise-attack"
            if matrix.domain == "enterprise"
            else f"{matrix.domain}-attack"
        ),
        "description": description,
        "filters": {"platforms": []},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#2fb673"],
            "minValue": 0,
            "maxValue": 5,
        },
        "legendItems": [
            {"label": "deployed",   "color": COVERAGE_COLOR["deployed"]},
            {"label": "in progress","color": COVERAGE_COLOR["in_progress"]},
            {"label": "idea",       "color": COVERAGE_COLOR["idea"]},
            {"label": "gap",        "color": COVERAGE_COLOR["gap"]},
            {"label": "n/a",        "color": COVERAGE_COLOR["not_applicable"]},
        ],
        "metadata": [
            {"name": "posture", "value": score.posture_grade},
            {"name": "breadth_grade", "value": score.breadth_grade},
            {"name": "depth_grade", "value": score.depth_grade},
        ],
    }


# ---- Sigma bundle ZIP ----------------------------------------------------

def _safe_filename(stem: str) -> str:
    safe = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in stem)
    return safe[:120] or "rule"


def bundle_sigma_yaml(detections: Iterable[Detection]) -> bytes:
    """Pack every detection's `raw_yaml` into a ZIP grouped by source.

    Detection rows missing raw_yaml are skipped silently — they're a data
    health issue, not a 500.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest_rows: list[dict] = []
        for d in detections:
            if not d.raw_yaml:
                continue
            folder = (d.source.value if hasattr(d.source, "value") else d.source) or "unknown"
            stem = _safe_filename(d.sigma_id or str(d.id))
            path = f"{folder}/{stem}.yml"
            zf.writestr(path, d.raw_yaml)
            manifest_rows.append(
                {
                    "path": path,
                    "id": str(d.id),
                    "sigma_id": d.sigma_id,
                    "title": d.title,
                    "source": folder,
                    "detection_status": (
                        d.detection_status.value
                        if hasattr(d.detection_status, "value")
                        else d.detection_status
                    ),
                }
            )

        # Manifest CSV for indexing.
        manifest = io.StringIO()
        w = csv.DictWriter(
            manifest,
            fieldnames=[
                "path",
                "id",
                "sigma_id",
                "title",
                "source",
                "detection_status",
            ],
        )
        w.writeheader()
        w.writerows(manifest_rows)
        zf.writestr("MANIFEST.csv", manifest.getvalue())
    return buf.getvalue()


# ---- Executive PDF ------------------------------------------------------

def to_pdf(
    *,
    customer_name: str,
    matrix: CoverageMatrix,
    score: CoverageScore,
    top_gaps: list,
    branding: Optional[dict] = None,
    d3fend_defenses: Optional[dict] = None,
) -> bytes:
    """Branded executive coverage summary.

    Logo support is intentionally simple — `branding.logo_url` is not fetched;
    PDFs are generated server-side and we don't want surprise network calls.
    Phase 8 settings will let customers upload a logo image to be embedded.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title=f"Detection coverage — {customer_name}",
    )
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
    )
    h1 = ParagraphStyle(
        "h1",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#16151c"),
    )
    h2 = ParagraphStyle(
        "h2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#4f46e5"),
        spaceAfter=8,
    )
    small = ParagraphStyle(
        "small",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#5a5868"),
    )

    elements = []
    brand_name = (branding or {}).get("display_name") or customer_name
    elements.append(Paragraph(f"{brand_name} — Detection Coverage", h1))
    elements.append(
        Paragraph(
            f"Domain: <b>{matrix.domain}</b> · Denominator: "
            f"<b>{matrix.denominator_kind.value}</b>"
            + (
                f" ({matrix.denominator_ref})"
                if matrix.denominator_ref
                else ""
            )
            + f" · Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            small,
        )
    )
    elements.append(Spacer(1, 12))

    # Posture hero
    grade_color = colors.HexColor(GRADE_COLOR.get(score.posture_grade, "#5a5868"))
    posture_table = Table(
        [
            [
                Paragraph(
                    f"<font size=44 color='{GRADE_COLOR.get(score.posture_grade, '#5a5868')}'>"
                    f"<b>{score.posture_grade}</b></font>",
                    body,
                ),
                Table(
                    [
                        ["Breadth", f"{round(score.breadth_pct * 100, 1)}%", score.breadth_grade],
                        ["Depth", f"{round(score.depth_avg, 2)} / 5", score.depth_grade],
                        ["Covered", f"{score.covered_count} / {score.denominator_size}", ""],
                        ["Deployed", str(score.deployed_count), ""],
                    ],
                    colWidths=[1.0 * inch, 1.4 * inch, 0.6 * inch],
                    style=TableStyle(
                        [
                            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#5a5868")),
                            ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
                            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ]
                    ),
                ),
            ]
        ],
        colWidths=[1.4 * inch, None],
        style=TableStyle(
            [
                ("BOX", (0, 0), (0, 0), 2, grade_color),
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#fbfbff")),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (0, 0), 8),
                ("RIGHTPADDING", (0, 0), (0, 0), 8),
                ("TOPPADDING", (0, 0), (0, 0), 12),
                ("BOTTOMPADDING", (0, 0), (0, 0), 12),
            ]
        ),
    )
    elements.append(posture_table)
    elements.append(Spacer(1, 18))

    # Coverage state breakdown
    elements.append(Paragraph("Coverage state breakdown", h2))
    state_rows = [["State", "Count", "% of denominator"]]
    for state in ("deployed", "in_progress", "idea", "gap", "not_applicable", "out_of_scope"):
        n = int(score.state_counts.get(state, 0))
        pct = (n / max(1, score.denominator_size)) * 100
        state_rows.append([state.replace("_", " "), str(n), f"{pct:.1f}%"])
    elements.append(
        Table(
            state_rows,
            colWidths=[2.2 * inch, 1.0 * inch, 1.4 * inch],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0ff")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d6d8e0")),
                ]
            ),
        )
    )
    elements.append(Spacer(1, 16))

    # Tactic coverage
    elements.append(Paragraph("Coverage by tactic", h2))
    tac_rows = [["Tactic", "Techniques", "Deployed", "Gap"]]
    for tac in matrix.tactics:
        cells = matrix.by_tactic.get(tac, [])
        deployed = sum(1 for c in cells if c.state == CoverageState.DEPLOYED)
        gaps = sum(1 for c in cells if c.state == CoverageState.GAP)
        tac_rows.append([tac, str(len(cells)), str(deployed), str(gaps)])
    elements.append(
        Table(
            tac_rows,
            colWidths=[2.6 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0ff")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d6d8e0")),
                ]
            ),
        )
    )
    elements.append(Spacer(1, 16))

    # Top gaps by APT prevalence
    if top_gaps:
        elements.append(Paragraph("Top gaps by APT prevalence", h2))
        gap_rows = [["Technique", "Name", "APTs", "Tactic"]]
        for g in top_gaps[:15]:
            gap_rows.append(
                [
                    g.technique_id,
                    (g.name[:55] + "…") if len(g.name) > 55 else g.name,
                    str(g.apt_count),
                    ", ".join(g.tactics[:2]),
                ]
            )
        elements.append(
            Table(
                gap_rows,
                colWidths=[1.0 * inch, 3.2 * inch, 0.7 * inch, 1.6 * inch],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0ff")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                        ("FONTNAME", (0, 1), (0, -1), "Courier"),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d6d8e0")),
                        ("TEXTCOLOR", (2, 1), (2, -1), colors.HexColor("#e23a3a")),
                    ]
                ),
            )
        )

    # Defensive countermeasures (D3FEND) — top defenses by # of in-scope
    # ATT&CK techniques they address.
    if d3fend_defenses:
        ranked = sorted(
            d3fend_defenses.items(),
            key=lambda kv: len(kv[1].get("techniques", [])),
            reverse=True,
        )[:15]
        if ranked:
            elements.append(Spacer(1, 16))
            elements.append(
                Paragraph("Defensive countermeasures (D3FEND)", h2)
            )
            d3_rows = [["D3FEND ID", "Name", "Addresses", "Relations"]]
            for d3id, meta in ranked:
                name = meta.get("name", d3id)
                d3_rows.append(
                    [
                        d3id,
                        (name[:42] + "…") if len(name) > 42 else name,
                        str(len(meta.get("techniques", []))),
                        ", ".join(meta.get("relations", [])[:2]),
                    ]
                )
            elements.append(
                Table(
                    d3_rows,
                    colWidths=[1.9 * inch, 2.6 * inch, 0.9 * inch, 1.1 * inch],
                    style=TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6fbf6")),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                            ("FONTNAME", (0, 1), (0, -1), "Courier"),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d6d8e0")),
                        ]
                    ),
                )
            )

    doc.build(elements)
    return buf.getvalue()


__all__ = [
    "COVERAGE_COLOR",
    "GRADE_COLOR",
    "bundle_sigma_yaml",
    "to_csv",
    "to_navigator_layer",
    "to_pdf",
    "to_xlsx",
]
