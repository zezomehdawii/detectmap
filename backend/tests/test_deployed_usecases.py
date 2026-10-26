"""Unit tests for deployed use-case ingest (pure functions, no DB/network)."""
from app.services.deployed_usecases import extract_technique_ids, parse_csv


class TestExtractTechniqueIds:
    def test_plain_and_subtechnique(self):
        ids = extract_technique_ids("uses T1059 and T1059.001")
        assert ids == ["T1059", "T1059.001"]

    def test_case_insensitive_and_dedupe_order(self):
        ids = extract_technique_ids("t1003 then T1003 again, then T1566")
        assert ids == ["T1003", "T1566"]

    def test_walks_lists_and_dicts(self):
        ids = extract_technique_ids(
            [{"technique": {"id": "T1486"}}, {"technique": {"id": "T1490"}}]
        )
        assert ids == ["T1486", "T1490"]

    def test_no_false_match_inside_longer_token(self):
        # Should not match T12345 (5 digits) or an embedded ABCT1059
        assert extract_technique_ids("T12345 ABCT1059 foo") == []

    def test_ignores_none(self):
        assert extract_technique_ids(None, "T1059", None) == ["T1059"]


class TestParseCsv:
    def test_standard_headers(self):
        csv_text = (
            "id,name,description,severity,enabled,query,techniques\n"
            "r1,Suspicious PowerShell,detects encoded cmd,high,true,"
            "EventCode=4688,T1059.001\n"
        )
        rows = parse_csv(csv_text)
        assert len(rows) == 1
        r = rows[0]
        assert r.external_id == "r1"
        assert r.name == "Suspicious PowerShell"
        assert r.severity == "high"
        assert r.enabled is True
        assert r.query == "EventCode=4688"
        assert r.technique_ids == ["T1059.001"]

    def test_alternate_header_names(self):
        csv_text = (
            "rule_name,search,mitre_attack\n"
            "Brute force,index=auth status=failed,T1110\n"
        )
        rows = parse_csv(csv_text)
        assert len(rows) == 1
        assert rows[0].name == "Brute force"
        assert rows[0].query == "index=auth status=failed"
        assert rows[0].technique_ids == ["T1110"]

    def test_disabled_column_inverts_enabled(self):
        csv_text = "name,disabled\nRule A,true\nRule B,false\n"
        rows = parse_csv(csv_text)
        assert rows[0].enabled is False
        assert rows[1].enabled is True

    def test_skips_rows_without_name_or_query(self):
        csv_text = "name,query\n,,\nReal rule,index=foo\n"
        rows = parse_csv(csv_text)
        assert len(rows) == 1
        assert rows[0].name == "Real rule"

    def test_synthesizes_external_id_when_absent(self):
        csv_text = "name,query\nMy rule,index=foo\n"
        rows = parse_csv(csv_text)
        assert rows[0].external_id == "csv:My rule"

    def test_technique_extracted_from_name_when_no_column(self):
        csv_text = "name,query\nDetects T1027 obfuscation,index=foo\n"
        rows = parse_csv(csv_text)
        assert rows[0].technique_ids == ["T1027"]

    def test_empty_csv(self):
        assert parse_csv("") == []
