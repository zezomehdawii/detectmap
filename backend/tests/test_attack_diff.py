"""Unit tests for the ATT&CK diff computation. No DB."""
from __future__ import annotations

from app.services.attack_diff import compute_diff


def _snap(tid: str, name: str = "n", deprecated: bool = False, revoked: bool = False):
    return {"technique_id": tid, "name": name, "deprecated": deprecated, "revoked": revoked}


class TestComputeDiff:
    def test_added_and_removed(self) -> None:
        prev = [_snap("T1059", "X")]
        curr = [_snap("T1059", "X"), _snap("T1078", "Y")]
        d = compute_diff(prev, curr)
        assert d["added"] == ["T1078"]
        assert d["removed"] == []

        d2 = compute_diff(curr, prev)
        assert d2["added"] == []
        assert d2["removed"] == ["T1078"]

    def test_renamed(self) -> None:
        prev = [_snap("T1059", "Old Name")]
        curr = [_snap("T1059", "New Name")]
        d = compute_diff(prev, curr)
        assert d["renamed"] == [
            {"technique_id": "T1059", "old_name": "Old Name", "new_name": "New Name"}
        ]
        assert d["added"] == [] and d["removed"] == []

    def test_deprecated_and_revived(self) -> None:
        prev = [_snap("T1", "a", deprecated=False), _snap("T2", "b", deprecated=True)]
        curr = [_snap("T1", "a", deprecated=True), _snap("T2", "b", deprecated=False)]
        d = compute_diff(prev, curr)
        assert d["deprecated"] == ["T1"]
        assert d["revived"] == ["T2"]

    def test_revoked(self) -> None:
        prev = [_snap("T1", "a", revoked=False)]
        curr = [_snap("T1", "a", revoked=True)]
        d = compute_diff(prev, curr)
        assert d["revoked"] == ["T1"]

    def test_empty_inputs(self) -> None:
        d = compute_diff([], [])
        assert d == {
            "added": [],
            "removed": [],
            "renamed": [],
            "deprecated": [],
            "revived": [],
            "revoked": [],
        }
