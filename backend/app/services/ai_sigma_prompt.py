"""Prompt construction for AI-assisted Sigma authoring.

This module is the *input-refinement* layer. The UI never sends a raw
freeform "talk to the AI" string to the model — it sends a structured
brief (technique IDs, log source, severity, FP notes, etc.) which we
compose into a strict, schema-aware prompt here. That keeps the surface
area small, makes outputs reproducible, and stops users from prompt-
injecting their way around the Sigma format requirement.

The actual API call is in `ai_sigma.py`; this file only assembles text.
"""
from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from typing import Optional


# ---- structured input -----------------------------------------------------

@dataclass
class SigmaBrief:
    """A structured user request for a Sigma rule.

    Every field is optional but the more is supplied, the better the
    output tends to be. The frontend form mirrors this shape exactly.
    """
    intent: str = ""  # one-line "what should this rule catch?"
    techniques: list[str] = field(default_factory=list)  # ATT&CK IDs e.g. T1059.001
    log_source_product: Optional[str] = None  # windows, linux, aws, …
    log_source_category: Optional[str] = None  # process_creation, file_event, …
    log_source_service: Optional[str] = None  # sysmon, security, …
    severity: str = "medium"  # informational | low | medium | high | critical
    fp_notes: str = ""  # known false-positive considerations
    reference_urls: list[str] = field(default_factory=list)
    tenant_codename: Optional[str] = None  # carried for the rule's id/title prefix

    def is_minimal(self) -> bool:
        """True if the brief is too thin to bother calling the model."""
        return not self.intent.strip() and not self.techniques


# ---- prompt construction --------------------------------------------------

# Hard schema instructions. These go in the *system* message so the model
# treats them as load-bearing, not as a suggestion in the user message.
_SYSTEM_PROMPT = textwrap.dedent(
    """
    You are a senior detection engineer drafting Sigma rules for a SOC's
    detection-as-code pipeline. You output Sigma YAML and nothing else.

    Strict output contract — violating any of these is a failure:

    1. Reply with exactly one fenced code block tagged `yaml`. No prose
       before or after the block.
    2. The YAML MUST be a valid Sigma rule that parses with pySigma:
       - Top-level keys: title, id, status, description, references,
         tags, author, date, logsource, detection, falsepositives,
         level.
       - `id` MUST be a fresh lowercase UUIDv4 you generate.
       - `status` MUST be one of: experimental, test, stable, deprecated,
         unsupported. Default to "experimental" for new drafts.
       - `level` MUST be one of: informational, low, medium, high,
         critical.
       - `logsource` MUST be a dict with `product` and/or `category` and
         optionally `service`.
       - `detection` MUST contain at least one selection plus a
         `condition` key.
       - `tags` SHOULD include `attack.<technique-id-lowercased>` for
         every ATT&CK technique provided (e.g. attack.t1059.001).
    3. Use realistic field names for the chosen log source (Image,
       CommandLine, User for Windows process_creation; SourceIp,
       EventType for AWS CloudTrail; etc.).
    4. Prefer value modifiers (|contains, |startswith, |endswith, |re)
       over raw wildcards when they match the intent better.
    5. NEVER output base64-encoded payloads or `|base64offset` modifiers
       — those break the downstream matcher.
    6. The rule MUST be useful as written; don't emit placeholders like
       "TODO" or "<your-value-here>". Pick reasonable defaults inferred
       from the brief.
    7. If the brief is too vague to write a useful rule, still emit a
       compilable rule but make `description` explicitly say it needs
       human review and what specifically is unclear.
    """
).strip()


def build_messages(brief: SigmaBrief) -> tuple[str, list[dict]]:
    """Return (system_prompt, messages) ready to pass to the Anthropic SDK.

    The messages list has a single user turn containing the structured
    brief as JSON plus a short natural-language wrapper. We don't let the
    user inject content directly into the system prompt.
    """
    payload = {
        "intent": brief.intent.strip()[:1500],
        "techniques": [t.strip() for t in brief.techniques if t.strip()][:8],
        "log_source": {
            "product": brief.log_source_product,
            "category": brief.log_source_category,
            "service": brief.log_source_service,
        },
        "severity": brief.severity,
        "false_positive_notes": brief.fp_notes.strip()[:800],
        "references": [u.strip() for u in brief.reference_urls if u.strip()][:6],
    }

    user_text = (
        "Draft a Sigma rule from this structured brief. Output only the YAML "
        "code block per the system instructions.\n\nBRIEF:\n```json\n"
        + json.dumps(payload, indent=2)
        + "\n```"
    )

    return _SYSTEM_PROMPT, [{"role": "user", "content": user_text}]


def build_retry_messages(
    brief: SigmaBrief,
    prior_yaml: str,
    validation_errors: list[str],
) -> tuple[str, list[dict]]:
    """Build a retry turn that includes the prior draft + parser errors.

    Keeps the same system prompt so the format contract is unchanged.
    """
    system, base = build_messages(brief)
    base.append({"role": "assistant", "content": f"```yaml\n{prior_yaml}\n```"})
    base.append(
        {
            "role": "user",
            "content": (
                "The previous draft failed validation with these errors:\n\n"
                + "\n".join(f"- {e}" for e in validation_errors[:10])
                + "\n\nFix every error and output the corrected rule. "
                "Output ONLY the YAML code block — no commentary."
            ),
        }
    )
    return system, base


__all__ = ["SigmaBrief", "build_messages", "build_retry_messages"]
