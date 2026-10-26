"""Integration tests for the Phase 4 extension to ATT&CK ingest:
groups, software, and the 'uses' SRO graph.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.base import AsyncSessionLocal
from app.models.public import (
    AttackGroup,
    AttackGroupSoftware,
    AttackGroupTechnique,
    AttackSoftware,
    AttackSoftwareTechnique,
)
from app.services.attack_ingest import parse_bundle, refresh_domain
from tests.conftest import load_bundle

pytestmark = pytest.mark.wipes_db


class TestParseGroupsBundle:
    def test_extracts_groups_software_relationships(self) -> None:
        parsed = parse_bundle("enterprise", load_bundle("enterprise_groups"))
        assert sorted(g["group_id"] for g in parsed["groups"]) == ["G9999"]
        assert sorted(s["software_id"] for s in parsed["software"]) == ["S9001", "S9002"]
        # software 'kind' tracks the STIX type (malware vs tool)
        by_id = {s["software_id"]: s for s in parsed["software"]}
        assert by_id["S9001"]["kind"] == "malware"
        assert by_id["S9002"]["kind"] == "tool"
        # group→technique relationships
        gtech = sorted(
            (r["group_id"], r["technique_id"]) for r in parsed["group_techniques"]
        )
        assert gtech == [("G9999", "T1003"), ("G9999", "T1078")]
        # software→technique relationships
        stech = sorted(
            (r["software_id"], r["technique_id"]) for r in parsed["software_techniques"]
        )
        assert stech == [("S9001", "T1059"), ("S9002", "T1090")]
        # group→software relationships (so APT denominator can expand via software)
        gsw = sorted(
            (r["group_id"], r["software_id"]) for r in parsed["group_software"]
        )
        assert gsw == [("G9999", "S9001"), ("G9999", "S9002")]


@pytest.mark.asyncio
class TestGroupsRefreshDomain:
    async def test_upserts_groups_software_and_uses(
        self, clean_attack_tables, fetch_groups
    ) -> None:
        result = await refresh_domain("enterprise", fetch_fn=fetch_groups)
        assert result["group_count"] == 1
        assert result["software_count"] == 2
        assert result["group_technique_count"] == 2
        assert result["software_technique_count"] == 2

        async with AsyncSessionLocal() as session:
            groups = (await session.execute(select(AttackGroup))).scalars().all()
            assert [g.group_id for g in groups] == ["G9999"]
            assert sorted(groups[0].aliases) == sorted(["TestGroup", "Fake Bear"])

            software = (await session.execute(select(AttackSoftware))).scalars().all()
            kinds = {s.software_id: s.kind for s in software}
            assert kinds == {"S9001": "malware", "S9002": "tool"}

            gtech = (
                await session.execute(
                    select(AttackGroupTechnique.technique_id).where(
                        AttackGroupTechnique.group_id == "G9999"
                    )
                )
            ).scalars().all()
            assert sorted(gtech) == ["T1003", "T1078"]

            stech_s9001 = (
                await session.execute(
                    select(AttackSoftwareTechnique.technique_id).where(
                        AttackSoftwareTechnique.software_id == "S9001"
                    )
                )
            ).scalars().all()
            assert stech_s9001 == ["T1059"]

            gsw = (
                await session.execute(
                    select(AttackGroupSoftware.software_id).where(
                        AttackGroupSoftware.group_id == "G9999"
                    )
                )
            ).scalars().all()
            assert sorted(gsw) == ["S9001", "S9002"]
