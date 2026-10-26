"""Unit tests for pySigma backend conversion."""
from __future__ import annotations

import pytest

from app.services.sigma_convert import SigmaBackend, convert_many, convert_yaml


SAMPLE_RULE = """
title: PowerShell EncodedCommand
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  product: windows
  category: process_creation
detection:
  s:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: s
level: high
"""


class TestConvertYaml:
    @pytest.mark.parametrize(
        "backend, fragment",
        [
            (SigmaBackend.SPLUNK, "EncodedCommand"),
            (SigmaBackend.ELASTIC, "EncodedCommand"),
            (SigmaBackend.SENTINEL, "EncodedCommand"),
        ],
    )
    def test_each_backend_produces_query_with_payload(self, backend, fragment) -> None:
        queries = convert_yaml(SAMPLE_RULE, backend)
        assert len(queries) >= 1
        assert any(fragment in q for q in queries)

    def test_empty_yaml_raises(self) -> None:
        with pytest.raises(ValueError):
            convert_yaml("   ", SigmaBackend.SPLUNK)


class TestConvertMany:
    def test_per_rule_errors_isolated(self) -> None:
        results = convert_many(
            [
                ("aaa", SAMPLE_RULE),
                ("bbb", ""),  # empty → error
                ("ccc", "not: actually: sigma"),  # broken YAML
            ],
            SigmaBackend.SPLUNK,
        )
        by_id = {r["detection_id"]: r for r in results}
        assert by_id["aaa"]["error"] is None
        assert by_id["aaa"]["queries"]
        assert by_id["bbb"]["error"] == "empty YAML"
        assert by_id["ccc"]["error"] is not None
        assert by_id["ccc"]["queries"] == []
