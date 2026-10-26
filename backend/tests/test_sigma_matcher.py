"""Unit tests for app.services.detection_samples.match_event.

Pure-function tests, no DB or fixtures. Run as part of the default
`pytest -q` because they're cheap and don't touch shared state.
"""
from __future__ import annotations

import pytest

from app.services.detection_samples import match_event

pytestmark = pytest.mark.matcher


# ---- basic single-selection cases ----------------------------------------

def test_simple_field_equality_matches():
    body = {"sel": {"Image": "powershell.exe"}, "condition": "sel"}
    matched, _ = match_event(body, {"Image": "powershell.exe"})
    assert matched is True


def test_case_insensitive_equality():
    body = {"sel": {"Image": "POWERSHELL.EXE"}, "condition": "sel"}
    matched, _ = match_event(body, {"Image": "powershell.exe"})
    assert matched is True


def test_field_missing_returns_false():
    body = {"sel": {"Image": "powershell.exe"}, "condition": "sel"}
    matched, _ = match_event(body, {"CommandLine": "x"})
    assert matched is False


# ---- value modifiers ------------------------------------------------------

def test_contains_modifier():
    body = {"sel": {"CommandLine|contains": "EncodedCommand"}, "condition": "sel"}
    matched, _ = match_event(body, {"CommandLine": "powershell -EncodedCommand abc"})
    assert matched is True


def test_endswith_modifier():
    body = {"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"}
    matched, _ = match_event(body, {"Image": "C:\\Windows\\System32\\powershell.exe"})
    assert matched is True


def test_re_modifier():
    body = {"sel": {"CommandLine|re": r"-(e|E)nc(odedCommand)?"}, "condition": "sel"}
    matched, _ = match_event(body, {"CommandLine": "powershell -enc abc"})
    assert matched is True


def test_wildcard_value_without_modifier():
    body = {"sel": {"Image": "*powershell.exe"}, "condition": "sel"}
    matched, _ = match_event(body, {"Image": "C:\\windows\\powershell.exe"})
    assert matched is True


def test_list_value_or_semantics():
    body = {
        "sel": {"CommandLine|contains": ["-enc", "-EncodedCommand"]},
        "condition": "sel",
    }
    matched, _ = match_event(body, {"CommandLine": "powershell -enc abc"})
    assert matched is True


def test_all_modifier_requires_every_value():
    body = {
        "sel": {"CommandLine|contains|all": ["foo", "bar"]},
        "condition": "sel",
    }
    matched_both, _ = match_event(body, {"CommandLine": "foo and bar"})
    matched_one, _ = match_event(body, {"CommandLine": "foo only"})
    assert matched_both is True
    assert matched_one is False


# ---- numeric modifiers ---------------------------------------------------

def test_numeric_gte():
    body = {"sel": {"EventID|gte": 4625}, "condition": "sel"}
    assert match_event(body, {"EventID": 4625})[0] is True
    assert match_event(body, {"EventID": 4624})[0] is False


def test_numeric_lt_string_coerce():
    body = {"sel": {"Severity|lt": 5}, "condition": "sel"}
    assert match_event(body, {"Severity": "3"})[0] is True


# ---- selection structures ------------------------------------------------

def test_keywords_selection_matches_any_field_substring():
    body = {"sel": ["malware", "encoded"], "condition": "sel"}
    matched, _ = match_event(
        body, {"CommandLine": "ran some encoded payload", "User": "joe"}
    )
    assert matched is True


def test_keywords_selection_no_hit():
    body = {"sel": ["malware", "rootkit"], "condition": "sel"}
    matched, _ = match_event(body, {"CommandLine": "innocuous"})
    assert matched is False


def test_list_of_dicts_top_level_is_or():
    body = {
        "sel": [{"Image": "cmd.exe"}, {"Image": "powershell.exe"}],
        "condition": "sel",
    }
    assert match_event(body, {"Image": "powershell.exe"})[0] is True
    assert match_event(body, {"Image": "notepad.exe"})[0] is False


# ---- condition combinators -----------------------------------------------

def test_and_not_filter():
    body = {
        "sel": {"Image|endswith": "\\powershell.exe"},
        "filter": {"User|startswith": "admin-"},
        "condition": "sel and not filter",
    }
    full_path = "C:\\Windows\\System32\\powershell.exe"
    assert (
        match_event(body, {"Image": full_path, "User": "admin-jane"})[0]
        is False
    )
    assert (
        match_event(body, {"Image": full_path, "User": "alice"})[0] is True
    )


def test_or_combination():
    body = {
        "a": {"Image": "cmd.exe"},
        "b": {"Image": "powershell.exe"},
        "condition": "a or b",
    }
    assert match_event(body, {"Image": "cmd.exe"})[0] is True
    assert match_event(body, {"Image": "wmic.exe"})[0] is False


def test_paren_grouping():
    body = {
        "a": {"User": "alice"},
        "b": {"User": "bob"},
        "c": {"Image": "cmd.exe"},
        "condition": "(a or b) and c",
    }
    assert match_event(body, {"User": "alice", "Image": "cmd.exe"})[0] is True
    assert match_event(body, {"User": "carol", "Image": "cmd.exe"})[0] is False
    assert match_event(body, {"User": "alice", "Image": "notepad.exe"})[0] is False


# ---- quantifiers ---------------------------------------------------------

def test_one_of_glob():
    body = {
        "sel_exe": {"Image|endswith": ".exe"},
        "sel_dll": {"Image|endswith": ".dll"},
        "condition": "1 of sel_*",
    }
    assert match_event(body, {"Image": "mal.dll"})[0] is True
    assert match_event(body, {"Image": "data.txt"})[0] is False


def test_all_of_them():
    body = {
        "a": {"Image": "cmd.exe"},
        "b": {"User": "alice"},
        "condition": "all of them",
    }
    assert match_event(body, {"Image": "cmd.exe", "User": "alice"})[0] is True
    assert match_event(body, {"Image": "cmd.exe", "User": "bob"})[0] is False


def test_n_of_quantifier():
    body = {
        "a": {"Tag": "x"},
        "b": {"Tag": "y"},
        "c": {"Tag": "z"},
        "condition": "2 of (a, b, c)".replace("(a, b, c)", "them"),
    }
    # 2 of them — event has Tag=x so only one matches → False
    assert match_event(body, {"Tag": "x"})[0] is False


# ---- indeterminate paths -------------------------------------------------

def test_aggregation_returns_none():
    body = {"sel": {"Image": "cmd.exe"}, "condition": "sel | count() > 5"}
    matched, msg = match_event(body, {"Image": "cmd.exe"})
    assert matched is None
    assert "aggregations" in msg


def test_unsupported_modifier_returns_none():
    # `|expand` needs a processing pipeline we don't run, so it stays
    # indeterminate (unlike base64/cidr/windash which are now supported).
    body = {"sel": {"CommandLine|expand": "%var%"}, "condition": "sel"}
    matched, msg = match_event(body, {"CommandLine": "abc"})
    assert matched is None
    assert "not supported" in msg


# ---- windash modifier (Phase 10) -----------------------------------------

def test_windash_matches_slash_variant():
    body = {
        "sel": {"CommandLine|windash|contains": "-EncodedCommand"},
        "condition": "sel",
    }
    matched, _ = match_event(body, {"CommandLine": "powershell /EncodedCommand abc"})
    assert matched is True


def test_windash_matches_dash_variant():
    body = {
        "sel": {"CommandLine|windash|contains": "-Enc"},
        "condition": "sel",
    }
    matched, _ = match_event(body, {"CommandLine": "powershell -Enc abc"})
    assert matched is True


def test_windash_no_match_on_unrelated_text():
    body = {
        "sel": {"CommandLine|windash|contains": "-Enc"},
        "condition": "sel",
    }
    matched, _ = match_event(body, {"CommandLine": "notepad foo.txt"})
    assert matched is False


# ---- cidr modifier (Phase 10 follow-up) ----------------------------------

def test_cidr_v4_match():
    body = {"sel": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "sel"}
    assert match_event(body, {"DestinationIp": "10.1.2.3"})[0] is True
    assert match_event(body, {"DestinationIp": "192.168.0.1"})[0] is False


def test_cidr_list_or_semantics():
    body = {
        "sel": {"DestinationIp|cidr": ["10.0.0.0/8", "172.16.0.0/12"]},
        "condition": "sel",
    }
    assert match_event(body, {"DestinationIp": "172.16.5.5"})[0] is True
    assert match_event(body, {"DestinationIp": "8.8.8.8"})[0] is False


def test_cidr_v6_match():
    body = {"sel": {"SourceIp|cidr": "2001:db8::/32"}, "condition": "sel"}
    assert match_event(body, {"SourceIp": "2001:db8::1"})[0] is True
    assert match_event(body, {"SourceIp": "2002:db8::1"})[0] is False


def test_cidr_malformed_value_is_false_not_indeterminate():
    body = {"sel": {"DestinationIp|cidr": "not-a-cidr"}, "condition": "sel"}
    matched, _ = match_event(body, {"DestinationIp": "10.0.0.1"})
    assert matched is False


# ---- fieldref modifier (Phase 10 follow-up) ------------------------------

def test_fieldref_equality_match():
    body = {"sel": {"Image|fieldref": "ParentImage"}, "condition": "sel"}
    same = {"Image": "C:\\a.exe", "ParentImage": "C:\\a.exe"}
    diff = {"Image": "C:\\a.exe", "ParentImage": "C:\\b.exe"}
    assert match_event(body, same)[0] is True
    assert match_event(body, diff)[0] is False


def test_fieldref_missing_referenced_field_is_false():
    body = {"sel": {"Image|fieldref": "ParentImage"}, "condition": "sel"}
    assert match_event(body, {"Image": "C:\\a.exe"})[0] is False


def test_fieldref_with_endswith():
    body = {"sel": {"Image|fieldref|endswith": "ParentImage"}, "condition": "sel"}
    ev = {"Image": "C:\\Win\\powershell.exe", "ParentImage": "powershell.exe"}
    assert match_event(body, ev)[0] is True


# ---- scalar selection values (Phase 10 follow-up) ------------------------

def test_bare_int_selection_is_keyword():
    body = {"sel": 4625, "condition": "sel"}
    assert match_event(body, {"EventID": 4625})[0] is True
    assert match_event(body, {"EventID": 4624})[0] is False


def test_mixed_scalar_list_selection_is_keywords():
    body = {"sel": ["mimikatz", 1337], "condition": "sel"}
    assert match_event(body, {"CommandLine": "ran mimikatz"})[0] is True
    assert match_event(body, {"Port": 1337})[0] is True
    assert match_event(body, {"CommandLine": "innocent"})[0] is False


# ---- base64 / base64offset modifiers (Phase 10 follow-up) ----------------

def test_base64_modifier_matches_encoded_value():
    import base64 as _b64
    enc = _b64.b64encode(b"whoami").decode()
    body = {"sel": {"CommandLine|base64": "whoami"}, "condition": "sel"}
    assert match_event(body, {"CommandLine": enc})[0] is True
    assert match_event(body, {"CommandLine": "whoami"})[0] is False


def test_base64_with_contains():
    import base64 as _b64
    enc = _b64.b64encode(b"whoami").decode()
    body = {"sel": {"CommandLine|base64|contains": "whoami"}, "condition": "sel"}
    assert match_event(body, {"CommandLine": f"prefix{enc}suffix"})[0] is True


def test_base64offset_matches_embedded_value():
    import base64 as _b64
    # 'powershell' embedded mid-stream in a longer base64 blob — at least
    # one of the three offset encodings must appear as a substring.
    blob = _b64.b64encode(b"XYZpowershell -enc abc").decode()
    body = {
        "sel": {"CommandLine|base64offset|contains": "powershell"},
        "condition": "sel",
    }
    assert match_event(body, {"CommandLine": blob})[0] is True


def test_base64offset_no_match():
    import base64 as _b64
    blob = _b64.b64encode(b"nothing interesting here").decode()
    body = {
        "sel": {"CommandLine|base64offset|contains": "mimikatz"},
        "condition": "sel",
    }
    assert match_event(body, {"CommandLine": blob})[0] is False


def test_base64offset_resolves_not_indeterminate():
    # The whole point of Phase 10's base64offset support: this used to
    # return (None, "not supported"). It must now be a clean decision.
    body = {"sel": {"CommandLine|base64offset|contains": "whoami"}, "condition": "sel"}
    matched, _ = match_event(body, {"CommandLine": "unrelated"})
    assert matched is False  # decided, not None


def test_unknown_selection_in_condition_returns_none():
    body = {"sel_a": {"Image": "cmd.exe"}, "condition": "sel_a and missing"}
    matched, msg = match_event(body, {"Image": "cmd.exe"})
    assert matched is None
    assert "unknown selection" in msg


def test_missing_condition_returns_none():
    body = {"sel": {"Image": "cmd.exe"}}
    matched, msg = match_event(body, {"Image": "cmd.exe"})
    assert matched is None
    assert "condition" in msg


def test_no_selections_returns_none():
    body = {"condition": "sel"}
    matched, msg = match_event(body, {})
    assert matched is None
    assert "selections" in msg
