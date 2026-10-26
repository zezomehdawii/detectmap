"""Pure-unit tests for Sigma YAML validator + tag parser."""
from __future__ import annotations

import pytest

from app.services.sigma_validate import (
    SigmaValidationError,
    parse_sigma_yaml,
    techniques_from_tags,
)


VALID_RULE = """
title: Suspicious PowerShell EncodedCommand
id: 5b3192fe-2967-4b30-bf52-a73da17d2c4f
status: stable
description: Detects PowerShell EncodedCommand usage.
author: detectmap-tests
references:
  - https://example.com
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1059
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
falsepositives:
  - admin scripts
level: high
"""


class TestParseSigmaYaml:
    def test_valid_rule(self) -> None:
        d = parse_sigma_yaml(VALID_RULE)
        assert d["global_id"] == "5b3192fe-2967-4b30-bf52-a73da17d2c4f"
        assert d["title"].startswith("Suspicious PowerShell")
        assert d["tags"] == ["attack.execution", "attack.t1059.001", "attack.t1059"]
        assert d["level"] == "high"
        assert d["logsource"]["product"] == "windows"
        assert d["raw_yaml"] == VALID_RULE

    def test_missing_id_rejected(self) -> None:
        yaml = VALID_RULE.replace("id: 5b3192fe-2967-4b30-bf52-a73da17d2c4f\n", "")
        with pytest.raises(SigmaValidationError, match="missing required field"):
            parse_sigma_yaml(yaml)

    def test_non_mapping_rejected(self) -> None:
        with pytest.raises(SigmaValidationError, match="must be a mapping"):
            parse_sigma_yaml("- just a list")

    def test_malformed_yaml_rejected(self) -> None:
        with pytest.raises(SigmaValidationError, match="invalid YAML"):
            parse_sigma_yaml("title: x\n  : bad indent\n  invalid")


class TestTechniquesFromTags:
    def test_extracts_techniques(self) -> None:
        tids = techniques_from_tags(
            [
                "attack.execution",
                "attack.t1059",
                "attack.t1059.001",
                "attack.persistence",
                "attack.t1078.004",
                "cve.2023.1234",
                "tlp.amber",
            ]
        )
        assert tids == ["T1059", "T1059.001", "T1078.004"]

    def test_empty_and_non_strings(self) -> None:
        assert techniques_from_tags([]) == []
        assert techniques_from_tags(["attack.t", None, 42, "attack.tactic"]) == []
