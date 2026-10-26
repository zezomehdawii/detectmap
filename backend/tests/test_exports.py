"""Unit tests for the exporters in app.services.exports.

Pure construction tests — we build small synthetic CoverageMatrix and
CoverageScore objects and assert on the bytes/dict shapes.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile

import pytest
from openpyxl import load_workbook

from app.services.coverage import (
    CoverageMatrix,
    CoverageScore,
    CoverageState,
    DenominatorKind,
    TechniqueCell,
)
from app.services.exports import (
    bundle_sigma_yaml,
    to_csv,
    to_navigator_layer,
    to_pdf,
    to_xlsx,
)


def _toy_matrix() -> CoverageMatrix:
    cells = {
        "execution": [
            TechniqueCell(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                parent_technique_id=None,
                is_subtechnique=False,
                tactics=["execution"],
                state=CoverageState.DEPLOYED,
                detection_count=2,
                max_depth=4,
                deployed_count=1,
            ),
            TechniqueCell(
                technique_id="T1059.001",
                name="PowerShell",
                parent_technique_id="T1059",
                is_subtechnique=True,
                tactics=["execution"],
                state=CoverageState.IN_PROGRESS,
                detection_count=1,
                max_depth=2,
                deployed_count=0,
            ),
        ],
        "credential-access": [
            TechniqueCell(
                technique_id="T1003",
                name="OS Credential Dumping",
                parent_technique_id=None,
                is_subtechnique=False,
                tactics=["credential-access"],
                state=CoverageState.GAP,
                detection_count=0,
                max_depth=0,
                deployed_count=0,
            ),
        ],
    }
    return CoverageMatrix(
        domain="enterprise",
        denominator_kind=DenominatorKind.FULL,
        denominator_ref=None,
        technique_count=3,
        tactics=["execution", "credential-access"],
        by_tactic=cells,
    )


def _toy_score() -> CoverageScore:
    return CoverageScore(
        domain="enterprise",
        denominator_kind=DenominatorKind.FULL,
        denominator_ref=None,
        denominator_size=3,
        covered_count=2,
        deployed_count=1,
        breadth_pct=2 / 3,
        depth_avg=3.0,
        breadth_grade="B",
        depth_grade="B",
        posture_grade="B",
        state_counts={
            "deployed": 1,
            "in_progress": 1,
            "idea": 0,
            "gap": 1,
            "not_applicable": 0,
            "out_of_scope": 0,
        },
    )


class TestCSV:
    def test_header_and_rows(self) -> None:
        body = to_csv(_toy_matrix())
        rows = list(csv.reader(io.StringIO(body.decode("utf-8"))))
        assert rows[0] == [
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
        assert len(rows) == 4  # header + 3 cells
        tids = {r[1] for r in rows[1:]}
        assert tids == {"T1059", "T1059.001", "T1003"}


class TestXLSX:
    def test_workbook_has_summary_and_techniques_sheets(self) -> None:
        body = to_xlsx(_toy_matrix(), _toy_score())
        wb = load_workbook(io.BytesIO(body))
        assert "Summary" in wb.sheetnames
        assert "Techniques" in wb.sheetnames

        tech = wb["Techniques"]
        headers = [c.value for c in tech[1]]
        assert headers[0] == "Tactic"
        assert headers[5] == "State"
        # +1 header row → 4 rows total
        assert tech.max_row == 4


class TestNavigatorLayer:
    def test_layer_shape(self) -> None:
        layer = to_navigator_layer(_toy_matrix(), _toy_score(), customer_name="Acme")
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert "Acme" in layer["name"]
        tids = sorted(t["techniqueID"] for t in layer["techniques"])
        assert tids == ["T1003", "T1059", "T1059.001"]
        # color reflects state
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        # gap → red
        assert by_id["T1003"]["color"].lower() == "#e23a3a"
        # deployed → green
        assert by_id["T1059"]["color"].lower() == "#2fb673"
        # metadata captures state
        meta = {m["name"]: m["value"] for m in by_id["T1059"]["metadata"]}
        assert meta["state"] == "deployed"
        assert meta["max_depth"] == "4"


class TestPDF:
    def test_pdf_starts_with_magic_and_has_content(self) -> None:
        body = to_pdf(
            customer_name="Acme",
            matrix=_toy_matrix(),
            score=_toy_score(),
            top_gaps=[],
            branding=None,
        )
        assert body[:4] == b"%PDF"
        assert len(body) > 1000


class TestSigmaBundle:
    def test_zip_groups_by_source_and_writes_manifest(self) -> None:
        class _D:
            def __init__(self, did, sid, title, src, status, raw):
                from app.models.customer import DetectionSource, DetectionStatus
                self.id = did
                self.sigma_id = sid
                self.title = title
                self.source = DetectionSource(src)
                self.detection_status = DetectionStatus(status)
                self.raw_yaml = raw

        rows = [
            _D(
                "11111111-1111-1111-1111-111111111111",
                "abc",
                "Hello",
                "global",
                "idea",
                "title: Hello\nid: abc\ndetection:\n  s:\n    a: b\n  condition: s\n",
            ),
            _D(
                "22222222-2222-2222-2222-222222222222",
                "def",
                "Custom",
                "custom",
                "deployed",
                "title: Custom\nid: def\ndetection:\n  s:\n    a: b\n  condition: s\n",
            ),
            _D(
                "33333333-3333-3333-3333-333333333333",
                "empty",
                "Empty",
                "custom",
                "idea",
                "",  # no raw_yaml → skipped
            ),
        ]
        body = bundle_sigma_yaml(rows)
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = sorted(zf.namelist())
            assert "MANIFEST.csv" in names
            assert "global/abc.yml" in names
            assert "custom/def.yml" in names
            # Skipped empty rule should NOT appear
            assert "custom/empty.yml" not in names
            manifest_rows = list(
                csv.DictReader(io.StringIO(zf.read("MANIFEST.csv").decode("utf-8")))
            )
            assert len(manifest_rows) == 2
            assert {r["sigma_id"] for r in manifest_rows} == {"abc", "def"}
