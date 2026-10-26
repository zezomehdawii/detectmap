"""Tests for D3FEND mapping ingest.

Pure parser tests (`parse_mappings_csv`) need no DB. The end-to-end
`refresh()` path that writes to the public schema is marked `wipes_db`
because it inserts into `d3fend_techniques` / `attack_technique_d3fend`
across the shared dev DB.
"""
from __future__ import annotations

import textwrap

import pytest

from app.services.d3fend_ingest import parse_mappings_csv


# ---- pure parser ---------------------------------------------------------

_SAMPLE_CSV = textwrap.dedent(
    """\
    off_tech_id,def_tech_label,def_tech_id,def_tech_rel_label
    T1059.001,Network Traffic Analysis,http://d3fend.mitre.org/ontologies/d3fend.owl#NetworkTrafficAnalysis,d3f:detects
    T1059.001,System Configuration Hardening,d3f:SystemConfigurationHardening,d3f:hardens
    T1003,Credential Hardening,d3f:CredentialHardening,d3f:hardens
    ,Bad row,d3f:NoAttack,d3f:detects
    T1078,,,
    """
)


def test_parse_extracts_techniques_and_mappings():
    out = parse_mappings_csv(_SAMPLE_CSV)
    tids = {t["d3fend_id"] for t in out["techniques"]}
    assert tids == {
        "NetworkTrafficAnalysis",
        "SystemConfigurationHardening",
        "CredentialHardening",
    }
    # The bad rows (missing attack_id or d3fend_id) are skipped.
    assert all(m["technique_id"] for m in out["mappings"])
    assert all(m["d3fend_id"] for m in out["mappings"])
    # Relations preserved as given.
    rels = {m["relation"] for m in out["mappings"]}
    assert "d3f:detects" in rels
    assert "d3f:hardens" in rels


def test_parse_returns_empty_on_missing_columns():
    out = parse_mappings_csv("foo,bar,baz\n1,2,3\n")
    assert out["techniques"] == []
    assert out["mappings"] == []


def test_parse_handles_short_iri_form():
    """The parser should accept both 'd3f:Foo' and the full URI form."""
    csv = textwrap.dedent(
        """\
        off_tech_id,def_tech_id
        T1059,d3f:ApplicationConfigurationHardening
        T1059,http://d3fend.mitre.org/ontologies/d3fend.owl#FileEncryption
        """
    )
    out = parse_mappings_csv(csv)
    ids = sorted(t["d3fend_id"] for t in out["techniques"])
    assert ids == ["ApplicationConfigurationHardening", "FileEncryption"]


def test_parse_dedupes_technique_definitions():
    csv = textwrap.dedent(
        """\
        off_tech_id,def_tech_id,def_tech_rel_label
        T1059,d3f:NetworkTrafficAnalysis,d3f:detects
        T1003,d3f:NetworkTrafficAnalysis,d3f:detects
        """
    )
    out = parse_mappings_csv(csv)
    assert len(out["techniques"]) == 1
    assert len(out["mappings"]) == 2


def test_parse_accepts_real_csv_columns():
    """The live d3fend.mitre.org CSV uses def_artifact_rel_label for the
    predicate and a full IRI in def_tech. Make sure the parser handles it."""
    csv = textwrap.dedent(
        """\
        off_tech_id,def_tech_label,def_tech,def_artifact_rel_label
        T1003.001,Process Isolation,http://d3fend.mitre.org/ontologies/d3fend.owl#ProcessIsolation,hardens
        """
    )
    out = parse_mappings_csv(csv)
    assert out["techniques"][0]["d3fend_id"] == "ProcessIsolation"
    assert out["mappings"][0]["technique_id"] == "T1003.001"
    assert out["mappings"][0]["relation"] == "hardens"


@pytest.mark.asyncio
async def test_d3fend_for_techniques_empty_input():
    """No technique IDs → empty structure, no DB round-trip required."""
    from app.services.d3fend_ingest import d3fend_for_techniques

    out = await d3fend_for_techniques([])
    assert out == {"by_technique": {}, "defenses": {}}
