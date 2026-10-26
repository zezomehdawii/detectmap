"""Unit tests for AI-assisted Sigma authoring — prompt + validator.

These tests do NOT call Anthropic. They assert on the structure of the
prompt we build and on the behavior of the validator against a small
hand-crafted set of model-reply samples (both well-formed and broken).
"""
from __future__ import annotations

import json
import uuid

import pytest

from app.services.ai_sigma_prompt import (
    SigmaBrief,
    build_messages,
    build_retry_messages,
)
from app.services.ai_sigma_validate import (
    AISigmaValidationError,
    extract_yaml,
    validate,
)


# ---- prompt builder ------------------------------------------------------

def test_brief_is_minimal_when_empty():
    assert SigmaBrief().is_minimal() is True


def test_brief_with_techniques_is_not_minimal():
    assert SigmaBrief(techniques=["T1059"]).is_minimal() is False


def test_build_messages_returns_system_and_user():
    brief = SigmaBrief(
        intent="catch encoded powershell",
        techniques=["T1059.001"],
        log_source_product="windows",
        log_source_category="process_creation",
    )
    system, messages = build_messages(brief)
    assert "Sigma" in system
    assert "yaml" in system.lower()
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    # The structured brief is embedded as JSON inside the user turn.
    assert "T1059.001" in messages[0]["content"]
    assert "process_creation" in messages[0]["content"]


def test_build_messages_truncates_long_intent():
    long = "x" * 5000
    _, messages = build_messages(SigmaBrief(intent=long))
    payload = messages[0]["content"]
    # Find the embedded JSON and parse it to check the intent length.
    json_start = payload.index("{")
    json_end = payload.rindex("}") + 1
    parsed = json.loads(payload[json_start:json_end])
    assert len(parsed["intent"]) <= 1500


def test_build_retry_messages_includes_prior_yaml_and_errors():
    brief = SigmaBrief(intent="x", techniques=["T1059"])
    system, messages = build_retry_messages(
        brief,
        prior_yaml="title: bad\nid: not-a-uuid\n",
        validation_errors=["rule `id` must be a UUID", "missing logsource"],
    )
    assert system  # same system prompt
    # initial user, assistant prior draft, follow-up user
    roles = [m["role"] for m in messages]
    assert roles == ["user", "assistant", "user"]
    assert "not-a-uuid" in messages[1]["content"]
    assert "must be a UUID" in messages[2]["content"]


# ---- validator: fenced block extraction ----------------------------------

def test_extract_yaml_from_fenced_block():
    out = extract_yaml("Sure, here's your rule:\n```yaml\ntitle: foo\nid: x\n```\nDone.")
    assert out.strip().startswith("title: foo")
    assert "Done" not in out


def test_extract_yaml_without_fence_returns_full_text():
    out = extract_yaml("title: foo\nid: x")
    assert out.startswith("title: foo")


def test_extract_yaml_empty_input():
    assert extract_yaml("") == ""


# ---- validator: full happy + sad paths -----------------------------------

_GOOD_YAML = """\
title: PowerShell encoded command from analyst host
id: {uid}
status: experimental
description: Detect base64-encoded PowerShell.
references:
  - https://example.invalid/ref
tags:
  - attack.t1059.001
  - attack.execution
author: pytest
date: 2026-05-21
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: sel
falsepositives:
  - administrators running encoded one-liners
level: high
"""


def test_validator_accepts_well_formed_rule():
    yaml_text = _GOOD_YAML.format(uid=str(uuid.uuid4()))
    fenced = f"```yaml\n{yaml_text}\n```"
    out_yaml, parsed = validate(fenced)
    assert "powershell" in out_yaml.lower()
    assert parsed["sigma_id"]
    assert parsed["level"] == "high"


def test_validator_rejects_non_uuid_id():
    bad = _GOOD_YAML.format(uid="not-a-uuid")
    with pytest.raises(AISigmaValidationError) as exc:
        validate(f"```yaml\n{bad}\n```")
    assert any("UUID" in e for e in exc.value.errors)


def test_validator_rejects_invalid_level():
    yaml_text = _GOOD_YAML.format(uid=str(uuid.uuid4())).replace(
        "level: high", "level: extreme"
    )
    with pytest.raises(AISigmaValidationError) as exc:
        validate(f"```yaml\n{yaml_text}\n```")
    # `extreme` is the violation; pySigma also rejects unknown levels, so
    # either path is acceptable as long as we flagged something.
    assert exc.value.errors


def test_validator_rejects_malformed_yaml():
    with pytest.raises(AISigmaValidationError) as exc:
        validate("```yaml\nthis is: : not yaml\n```")
    assert exc.value.errors


def test_validator_rejects_empty_output():
    with pytest.raises(AISigmaValidationError) as exc:
        validate("")
    assert "no YAML content" in exc.value.errors[0]
