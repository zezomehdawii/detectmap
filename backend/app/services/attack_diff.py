"""ATT&CK catalog diff — pure functions, no DB."""
from __future__ import annotations

from typing import Iterable, TypedDict


class TechniqueSnapshot(TypedDict):
    technique_id: str
    name: str
    deprecated: bool
    revoked: bool


class DiffPayload(TypedDict):
    added: list[str]
    removed: list[str]
    renamed: list[dict]
    deprecated: list[str]
    revived: list[str]
    revoked: list[str]


def compute_diff(
    prev: Iterable[TechniqueSnapshot],
    curr: Iterable[TechniqueSnapshot],
) -> DiffPayload:
    prev_by_id = {t["technique_id"]: t for t in prev}
    curr_by_id = {t["technique_id"]: t for t in curr}

    prev_ids = set(prev_by_id)
    curr_ids = set(curr_by_id)

    added = sorted(curr_ids - prev_ids)
    removed = sorted(prev_ids - curr_ids)

    renamed: list[dict] = []
    deprecated: list[str] = []
    revived: list[str] = []
    revoked: list[str] = []

    for tid in sorted(prev_ids & curr_ids):
        p = prev_by_id[tid]
        c = curr_by_id[tid]
        if p["name"] != c["name"]:
            renamed.append(
                {"technique_id": tid, "old_name": p["name"], "new_name": c["name"]}
            )
        if not p["deprecated"] and c["deprecated"]:
            deprecated.append(tid)
        elif p["deprecated"] and not c["deprecated"]:
            revived.append(tid)
        if not p["revoked"] and c["revoked"]:
            revoked.append(tid)

    return {
        "added": added,
        "removed": removed,
        "renamed": renamed,
        "deprecated": deprecated,
        "revived": revived,
        "revoked": revoked,
    }


__all__ = ["TechniqueSnapshot", "DiffPayload", "compute_diff"]
