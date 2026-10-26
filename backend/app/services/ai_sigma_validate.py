"""Validate and normalize AI-generated Sigma YAML.

The output-refinement layer. LLMs reliably emit YAML, but they
occasionally:

  - wrap it in prose ("Sure! Here's your rule: …")
  - drop or invent required Sigma fields
  - use an ATT&CK tag that isn't real (e.g. attack.t9999)
  - generate a non-UUID `id`
  - pick a `level` outside the Sigma vocabulary

We:

  1. Extract the YAML fenced code block (first ```yaml ... ``` if present,
     else assume the whole thing is YAML).
  2. Parse + validate via the existing `sigma_validate.parse_sigma_yaml`
     (which goes through pySigma — same path used for human-authored rules).
  3. Run a few cheap sanity checks on top (UUID format, level/status
     vocabulary, ATT&CK tags look like attack.t#### patterns).
  4. Return either `(yaml_text, parsed_dict)` on success, or a list of
     normalized error strings that the retry loop can feed back to the
     model.
"""
from __future__ import annotations

import re
import uuid
from typing import Any

from app.services.sigma_validate import SigmaValidationError, parse_sigma_yaml


_FENCED_RE = re.compile(
    r"```(?:yaml|yml)?\s*\n(.*?)\n```",
    re.DOTALL | re.IGNORECASE,
)
_ATTACK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
_VALID_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}


class AISigmaValidationError(ValueError):
    """Carries a list of normalized error messages for the retry loop."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = list(errors)


def extract_yaml(model_output: str) -> str:
    """Pull the first fenced YAML block out of an LLM reply.

    If there's no fence, assume the entire string is YAML. Leading/trailing
    whitespace is stripped. Never raises — empty input returns empty string.
    """
    if not model_output:
        return ""
    m = _FENCED_RE.search(model_output)
    if m:
        return m.group(1).strip()
    return model_output.strip()


def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(str(s))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _post_parse_checks(parsed: dict[str, Any]) -> list[str]:
    """Cheap Sigma-shape sanity checks beyond what pySigma enforces."""
    errs: list[str] = []

    rid = parsed.get("sigma_id") or parsed.get("global_id")
    if not _is_uuid(rid):
        errs.append(
            f"rule `id` must be a UUID, got {rid!r}. Regenerate with a fresh "
            "lowercase UUIDv4."
        )

    level = (parsed.get("level") or "").strip().lower() if parsed.get("level") else None
    if level and level not in _VALID_LEVELS:
        errs.append(
            f"`level: {level}` is not a Sigma level. Use one of "
            f"{sorted(_VALID_LEVELS)}."
        )

    status = (parsed.get("sigma_status") or "").strip().lower() if parsed.get("sigma_status") else None
    if status and status not in _VALID_STATUSES:
        errs.append(
            f"`status: {status}` is not a Sigma status. Use one of "
            f"{sorted(_VALID_STATUSES)}."
        )

    tags = parsed.get("tags") or []
    bad_tags = [
        t for t in tags
        if isinstance(t, str)
        and t.lower().startswith("attack.t")
        and not _ATTACK_TAG_RE.match(t)
    ]
    if bad_tags:
        errs.append(
            f"these ATT&CK tags don't look like real technique IDs: {bad_tags}. "
            "Use the lowercase `attack.tNNNN` or `attack.tNNNN.NNN` format."
        )

    ls = parsed.get("logsource") or {}
    if not isinstance(ls, dict) or not (
        ls.get("product") or ls.get("category") or ls.get("service")
    ):
        errs.append("`logsource` must specify at least one of product/category/service.")

    det = parsed.get("detection") or {}
    if not isinstance(det, dict) or "condition" not in det:
        errs.append("`detection` must contain a `condition` key.")
    elif len([k for k in det.keys() if k != "condition"]) == 0:
        errs.append("`detection` must contain at least one selection besides `condition`.")

    return errs


def validate(model_output: str) -> tuple[str, dict[str, Any]]:
    """Validate the model's reply.

    Returns (clean_yaml_text, parsed_fields) on success.
    Raises AISigmaValidationError(errors=[...]) on failure.
    """
    yaml_text = extract_yaml(model_output)
    if not yaml_text:
        raise AISigmaValidationError(
            ["model returned no YAML content; expected a ```yaml ...``` block"]
        )

    try:
        parsed = parse_sigma_yaml(yaml_text)
    except SigmaValidationError as e:
        raise AISigmaValidationError([str(e)]) from e

    extra = _post_parse_checks(parsed)
    if extra:
        raise AISigmaValidationError(extra)

    return yaml_text, parsed


__all__ = [
    "AISigmaValidationError",
    "extract_yaml",
    "validate",
]
