"""Detection event samples (unit tests for Sigma rules).

The runner matches an event dict against the rule's `detection` block.
Supports the common Sigma surface area:

- Field equality: case-insensitive scalar match
- List values on a field: OR over members
- List of dicts at selection top level: OR over each sub-dict
- Value modifiers: |contains, |startswith, |endswith, |re, |windash,
  |cidr, |fieldref (compare to another event field), |base64,
  |base64offset (embedded-base64 search),
  |contains|all (every value must hit), |all, |lt, |lte, |gt, |gte
- Wildcard values: '*' and '?' shell-style patterns (when no modifier present)
- Conditions: parenthesised boolean expressions with `and`, `or`, `not`,
  selection name references, `1 of selectionN`, `all of selectionN`,
  `1 of them`, `all of them`, and `n of` quantifiers
- `keywords:` selections (list of strings; OR-of-contains across any field)

Conditions we still mark indeterminate:
- count() / pipe aggregations
- timeframe-based aggregation
- |expand placeholder expansion (needs a processing pipeline)

These cases are explicitly returned as `(None, reason)` so the UI shows '?'
rather than silently passing or failing.
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select

from app.db.tenant import tenant_session
from app.models.customer import Detection, DetectionEventSample


class IndeterminateMatch(Exception):
    """Raised when the matcher can't decide. Carries a human reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---- model wrappers -------------------------------------------------------

@dataclass
class SampleOut:
    id: str
    detection_id: str
    label: str
    kind: str  # positive | negative
    event: dict
    expected_match: bool
    last_run_at: Optional[str]
    last_run_pass: Optional[bool]
    last_run_message: Optional[str]
    author_email: Optional[str]


@dataclass
class SampleRunResult:
    sample_id: str
    matched: Optional[bool]  # None means indeterminate
    passed: Optional[bool]
    message: str


def _to_out(r: DetectionEventSample) -> SampleOut:
    return SampleOut(
        id=str(r.id),
        detection_id=str(r.detection_id),
        label=r.label,
        kind=r.kind,
        event=dict(r.event or {}),
        expected_match=bool(r.expected_match),
        last_run_at=r.last_run_at.isoformat() if r.last_run_at else None,
        last_run_pass=r.last_run_pass,
        last_run_message=r.last_run_message,
        author_email=r.author_email,
    )


# ---- value-level matcher --------------------------------------------------

_UNSUPPORTED_MODIFIERS = {
    "expand",  # %placeholder% expansion needs a pipeline we don't run here
}


def _base64_variant(expected: str) -> str:
    """Sigma `|base64`: the expected value becomes its base64 encoding."""
    return base64.b64encode(str(expected).encode("utf-8")).decode("ascii")


# Mirrors pySigma's SigmaBase64OffsetModifier so embedded-base64 rules
# (`Field|base64offset|contains`) match the same way a real backend would.
_B64_START_OFFSETS = (0, 2, 3)
_B64_END_OFFSETS = (None, -3, -2)


def _base64offset_variants(expected: str) -> list[str]:
    """Three offset encodings of `expected` for embedded-base64 search.

    The plaintext can begin at any of three byte boundaries inside a larger
    base64 blob; each offset yields a distinct substring once the
    boundary-affected edge characters are trimmed.
    """
    raw = str(expected).encode("utf-8")
    variants: list[str] = []
    for i in range(3):
        encoded = base64.b64encode(b" " * i + raw)
        end = _B64_END_OFFSETS[(len(raw) + i) % 3]
        variants.append(encoded[_B64_START_OFFSETS[i] : end].decode("ascii"))
    return variants


def _cidr_match(actual: Any, expected: Any) -> bool:
    """Sigma `|cidr` — `actual` is an IP, `expected` is a CIDR string.

    Returns False (not indeterminate) on parse errors so a malformed
    rule doesn't poison the run. Empty / null values are False.
    """
    if not actual or not expected:
        return False
    try:
        ip = ipaddress.ip_address(str(actual).strip())
        net = ipaddress.ip_network(str(expected).strip(), strict=False)
    except (ValueError, TypeError):
        return False
    # ip_network rejects mixing v4 / v6, so a False here is correct semantics.
    if ip.version != net.version:
        return False
    return ip in net

_NUMERIC_MODIFIERS = {"lt", "lte", "gt", "gte"}


def _windash_variants(expected: str) -> list[str]:
    """Sigma `|windash` expands a flag like `-Foo` into
    `-Foo`, `/Foo`, `-foo` (case is already insensitive on our side).
    Empty string returns [""] unchanged.
    """
    e = str(expected)
    if not e:
        return [e]
    if not e.startswith(("-", "/")):
        return [e]
    rest = e[1:]
    return list({f"-{rest}", f"/{rest}", f"--{rest}"})


def _coerce_number(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def _value_matches_one(
    actual: Any, expected: Any, modifiers: set[str]
) -> bool:
    if actual is None:
        return False
    if expected is None:
        # Sigma `field: null` matches when the field is missing or null —
        # callers handle the "missing" path; if we got here, actual is not None.
        return False

    if "base64offset" in modifiers:
        # Embedded-base64 search. Produce the 3 offset encodings and OR a
        # contains-check across them (unless an explicit comparator is set).
        rest = modifiers - {"base64offset"}
        if not (rest & {"contains", "startswith", "endswith", "re"}):
            rest = rest | {"contains"}
        return any(
            _value_matches_one(actual, v, rest)
            for v in _base64offset_variants(expected)
        )

    if "base64" in modifiers:
        # The expected value is matched in its base64-encoded form.
        rest = modifiers - {"base64"}
        return _value_matches_one(actual, _base64_variant(expected), rest)

    if "cidr" in modifiers:
        # `|cidr` short-circuits everything else — the value is an IP
        # network, not a wildcard/regex expression.
        if isinstance(expected, list):
            return any(_cidr_match(actual, e) for e in expected)
        return _cidr_match(actual, expected)

    if modifiers & _NUMERIC_MODIFIERS:
        a = _coerce_number(actual)
        e = _coerce_number(expected)
        if a is None or e is None:
            return False
        if "lt" in modifiers:
            return a < e
        if "lte" in modifiers:
            return a <= e
        if "gt" in modifiers:
            return a > e
        if "gte" in modifiers:
            return a >= e

    a_str = str(actual)
    e_str = str(expected)

    # `|windash` expands a flag form like '-EncodedCommand' into
    # ['-EncodedCommand', '/EncodedCommand', '--EncodedCommand']. We
    # apply it once here and then fall through to the regular comparator,
    # OR-ing across the variants.
    if "windash" in modifiers:
        rest = modifiers - {"windash"}
        return any(
            _value_matches_one(actual, v, rest)
            for v in _windash_variants(e_str)
        )

    if "re" in modifiers:
        try:
            return bool(re.search(e_str, a_str))
        except re.error:
            return False
    if "contains" in modifiers:
        return e_str.lower() in a_str.lower()
    if "startswith" in modifiers:
        return a_str.lower().startswith(e_str.lower())
    if "endswith" in modifiers:
        return a_str.lower().endswith(e_str.lower())

    # No special modifier: wildcards if present, else case-insensitive equality
    if "*" in e_str or "?" in e_str:
        return fnmatch.fnmatchcase(a_str.lower(), e_str.lower())
    return a_str.lower() == e_str.lower()


def _match_field(field_spec: str, expected: Any, event: dict) -> bool:
    """Match a field against an expected value (or list of values).

    Field spec is `Field` or `Field|modifier|modifier...`.
    """
    parts = field_spec.split("|")
    field = parts[0]
    modifiers = set(parts[1:])

    if modifiers & _UNSUPPORTED_MODIFIERS:
        raise IndeterminateMatch(
            f"modifier(s) not supported by matcher: "
            f"{sorted(modifiers & _UNSUPPORTED_MODIFIERS)}"
        )

    # `|fieldref`: the "value" is the NAME of another event field. We
    # resolve it against the event, then compare with the remaining
    # modifiers (contains/startswith/endswith/equality). A referenced
    # field that's absent contributes no match. The base field must be
    # present too.
    if "fieldref" in modifiers:
        if field not in event:
            return False
        actual = event[field]
        rest = modifiers - {"fieldref", "all"}
        ref_names = expected if isinstance(expected, list) else [expected]
        resolved = [
            event[r] for r in ref_names if isinstance(r, str) and r in event
        ]
        if not resolved:
            return False
        if "all" in modifiers:
            return all(_value_matches_one(actual, v, rest) for v in resolved)
        return any(_value_matches_one(actual, v, rest) for v in resolved)

    # Sigma special: `field|exists: true` (we don't strictly need it for MVP)
    if field not in event:
        # `null` expected with no value present → True
        if expected is None:
            return True
        return False

    actual = event[field]

    if isinstance(expected, list):
        expecteds = expected
        # `|all` modifier: every expected value must match (otherwise OR)
        if "all" in modifiers:
            return all(
                _value_matches_one(actual, e, modifiers - {"all"})
                for e in expecteds
            )
        return any(
            _value_matches_one(actual, e, modifiers - {"all"}) for e in expecteds
        )

    return _value_matches_one(actual, expected, modifiers)


_SCALAR_TYPES = (str, int, float, bool)


def _match_keywords(values: list, event: dict) -> bool:
    """`keywords:` selections are an OR of contains across every field value.

    Scalar needles (str/int/float/bool) are stringified before the
    substring test, so a numeric keyword like `4625` matches an event
    field rendered as `"4625"`.
    """
    haystack = " ".join(
        str(v) for v in event.values() if v is not None
    ).lower()
    for needle in values:
        if isinstance(needle, _SCALAR_TYPES) and str(needle).lower() in haystack:
            return True
    return False


def _match_selection(spec: Any, event: dict) -> bool:
    """A selection is True iff every constraint inside it is True."""
    # Bare scalar selection (e.g. `sel: 4625` or `sel: 'mimikatz'`) — Sigma
    # treats it as a single free-text keyword across all event values.
    if isinstance(spec, _SCALAR_TYPES):
        return _match_keywords([spec], event)
    if isinstance(spec, list):
        # list of scalars → treated as keywords (Sigma "free text"); a mix
        # of scalars is fine, we stringify each.
        if all(isinstance(x, _SCALAR_TYPES) for x in spec):
            return _match_keywords(spec, event)
        # list of dicts (or mixed) → OR over each member.
        for item in spec:
            if _match_selection(item, event):
                return True
        return False
    if isinstance(spec, dict):
        for k, v in spec.items():
            if k == "keywords" and isinstance(v, list):
                if not _match_keywords(v, event):
                    return False
                continue
            if not _match_field(k, v, event):
                return False
        return True
    raise IndeterminateMatch(f"selection has unsupported type: {type(spec).__name__}")


# ---- condition parser (recursive descent over tokens) ---------------------

_TOKEN_RE = re.compile(r"\(|\)|\s+|[A-Za-z0-9_*]+")


def _tokenize(condition: str) -> list[str]:
    out: list[str] = []
    for m in _TOKEN_RE.finditer(condition):
        tok = m.group(0)
        if tok.isspace():
            continue
        out.append(tok)
    return out


def _expand_glob(name: str, selections: dict[str, Any]) -> list[str]:
    if "*" not in name and "?" not in name:
        return [name] if name in selections else []
    return [n for n in selections if fnmatch.fnmatchcase(n, name)]


class _Parser:
    def __init__(self, tokens: list[str], selections: dict[str, Any], event: dict):
        self.t = tokens
        self.i = 0
        self.selections = selections
        self.event = event

    def peek(self) -> Optional[str]:
        return self.t[self.i] if self.i < len(self.t) else None

    def eat(self) -> str:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        v = self.parse_or()
        if self.peek() is not None:
            raise IndeterminateMatch(f"trailing tokens in condition: {self.t[self.i:]}")
        return v

    def parse_or(self) -> bool:
        v = self.parse_and()
        while self.peek() and self.peek().lower() == "or":
            self.eat()
            v = self.parse_and() or v
        return v

    def parse_and(self) -> bool:
        v = self.parse_not()
        while self.peek() and self.peek().lower() == "and":
            self.eat()
            v = self.parse_not() and v
        return v

    def parse_not(self) -> bool:
        if self.peek() and self.peek().lower() == "not":
            self.eat()
            return not self.parse_not()
        return self.parse_atom()

    def parse_atom(self) -> bool:
        tok = self.peek()
        if tok is None:
            raise IndeterminateMatch("unexpected end of condition")
        if tok == "(":
            self.eat()
            v = self.parse_or()
            if self.peek() != ")":
                raise IndeterminateMatch("missing closing paren")
            self.eat()
            return v
        # quantifier?  `1 of X`, `all of X`, `<n> of X`
        if tok.lower() in {"1", "all", "any"} or tok.isdigit():
            # peek ahead to confirm we have `<q> of <target>`
            if (
                self.i + 2 < len(self.t)
                and self.t[self.i + 1].lower() == "of"
            ):
                quant = self.eat().lower()
                self.eat()  # 'of'
                target = self.eat()
                names = (
                    list(self.selections.keys())
                    if target.lower() == "them"
                    else _expand_glob(target, self.selections)
                )
                if not names:
                    return False
                matches = sum(
                    1 for n in names if _match_selection(self.selections[n], self.event)
                )
                if quant == "all":
                    return matches == len(names)
                if quant in {"1", "any"}:
                    return matches >= 1
                try:
                    threshold = int(quant)
                except ValueError:
                    raise IndeterminateMatch(f"unknown quantifier: {quant!r}")
                return matches >= threshold
        # plain selection name
        name = self.eat()
        if name not in self.selections:
            raise IndeterminateMatch(f"unknown selection: {name!r}")
        return _match_selection(self.selections[name], self.event)


def match_event(detection_body: dict, event: dict) -> tuple[Optional[bool], str]:
    """Returns (matched, reason).

    matched is True/False on a clean decision, or None when the matcher hits
    a case it can't safely evaluate (aggregations, unsupported modifiers,
    malformed conditions). On None, `reason` is human-readable.
    """
    if not isinstance(detection_body, dict):
        return None, "rule has no detection block"

    condition = detection_body.get("condition")
    if condition is None:
        return None, "rule lacks a 'condition' clause"
    if not isinstance(condition, str):
        return None, "condition is not a string"

    cond = condition.strip()
    if "|" in cond:
        # pipe aggregations (count, by, etc.) — out of scope.
        return None, "aggregations (|count, |by) not supported"

    selections = {
        k: v for k, v in detection_body.items()
        if k not in {"condition", "timeframe"}
    }
    if not selections:
        return None, "rule has no selections"

    tokens = _tokenize(cond)
    if not tokens:
        return None, "empty condition"

    try:
        result = _Parser(tokens, selections, event).parse()
    except IndeterminateMatch as e:
        return None, f"indeterminate: {e.reason}"
    return result, "matched" if result else "no match"


# ---- CRUD -----------------------------------------------------------------

async def list_samples(detection_id: str) -> list[SampleOut]:
    try:
        did = uuid.UUID(detection_id)
    except ValueError:
        return []
    async with tenant_session() as session:
        rows = (
            await session.execute(
                select(DetectionEventSample)
                .where(DetectionEventSample.detection_id == did)
                .order_by(DetectionEventSample.created_at.asc())
            )
        ).scalars().all()
        return [_to_out(r) for r in rows]


async def upsert_sample(
    *,
    detection_id: str,
    label: str,
    kind: str,
    event: dict,
    expected_match: Optional[bool] = None,
    sample_id: Optional[str] = None,
    author_email: Optional[str] = None,
) -> SampleOut:
    if kind not in {"positive", "negative"}:
        raise ValueError(f"invalid sample kind: {kind!r}")
    did = uuid.UUID(detection_id)
    # default: positive samples should match, negative should not
    if expected_match is None:
        expected_match = kind == "positive"
    async with tenant_session() as session:
        if sample_id:
            row = (
                await session.execute(
                    select(DetectionEventSample).where(
                        DetectionEventSample.id == uuid.UUID(sample_id),
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                raise ValueError("sample not found")
            row.label = label
            row.kind = kind
            row.event = event
            row.expected_match = expected_match
            row.author_email = author_email
        else:
            row = DetectionEventSample(
                id=uuid.uuid4(),
                detection_id=did,
                label=label,
                kind=kind,
                event=event,
                expected_match=expected_match,
                author_email=author_email,
            )
            session.add(row)
        await session.flush()
        await session.refresh(row)
        return _to_out(row)


async def delete_sample(sample_id: str) -> bool:
    try:
        sid = uuid.UUID(sample_id)
    except ValueError:
        return False
    async with tenant_session() as session:
        row = (
            await session.execute(
                select(DetectionEventSample).where(DetectionEventSample.id == sid)
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        await session.delete(row)
        return True


async def run_samples_for_detection(
    detection_id: str,
) -> list[SampleRunResult]:
    """Re-evaluate every sample for a detection and persist results."""
    try:
        did = uuid.UUID(detection_id)
    except ValueError:
        return []
    results: list[SampleRunResult] = []
    async with tenant_session() as session:
        det = (
            await session.execute(
                select(Detection).where(Detection.id == did)
            )
        ).scalar_one_or_none()
        if det is None:
            return []
        samples = (
            await session.execute(
                select(DetectionEventSample).where(
                    DetectionEventSample.detection_id == did,
                )
            )
        ).scalars().all()
        for s in samples:
            matched, msg = match_event(dict(det.detection or {}), s.event)
            if matched is None:
                passed: Optional[bool] = None
                message = f"indeterminate · {msg}"
            else:
                passed = matched == s.expected_match
                message = (
                    f"matched={matched}, expected={s.expected_match}: "
                    f"{'PASS' if passed else 'FAIL'}"
                )
            s.last_run_at = datetime.now(timezone.utc)
            s.last_run_pass = passed
            s.last_run_message = message
            results.append(
                SampleRunResult(
                    sample_id=str(s.id),
                    matched=matched,
                    passed=passed,
                    message=message,
                )
            )
    return results


__all__ = [
    "SampleOut",
    "SampleRunResult",
    "delete_sample",
    "list_samples",
    "match_event",
    "run_samples_for_detection",
    "upsert_sample",
]
