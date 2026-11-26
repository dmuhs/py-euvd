from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from pyeuvd import EUVDError, parsing


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Apr 12, 2024, 7:20:00 AM", datetime(2024, 4, 12, 7, 20, tzinfo=UTC)),
        ("Oct 21, 2025, 11:05:21 PM", datetime(2025, 10, 21, 23, 5, 21, tzinfo=UTC)),
        ("Dec 13, 2024, 12:00:00 AM", datetime(2024, 12, 13, 0, 0, tzinfo=UTC)),
        ("Dec 13, 2024, 12:30:00 PM", datetime(2024, 12, 13, 12, 30, tzinfo=UTC)),
        # Some Java versions put a narrow no-break space before AM/PM.
        ("Apr 12, 2024, 7:20:00\u202fAM", datetime(2024, 4, 12, 7, 20, tzinfo=UTC)),
        ("2024-04-12T07:20:00Z", datetime(2024, 4, 12, 7, 20, tzinfo=UTC)),
        ("2024-04-12T07:20:00", datetime(2024, 4, 12, 7, 20, tzinfo=UTC)),
    ],
)
def test_parse_datetime(text, expected):
    assert parsing.parse_datetime(text) == expected


@pytest.mark.parametrize(
    "value",
    [None, "", "   ", "not a date", "Foo 12, 2024, 7:20:00 AM", "Feb 31, 2024, 7:20:00 AM", 42],
)
def test_parse_datetime_returns_none_for_bad_input(value):
    assert parsing.parse_datetime(value) is None


def test_parse_date():
    assert parsing.parse_date("2025-10-06") == date(2025, 10, 6)
    assert parsing.parse_date("soon") is None
    assert parsing.parse_date(None) is None


def test_parse_text():
    assert parsing.parse_text("mitre") == "mitre"
    assert parsing.parse_text("") is None
    assert parsing.parse_text(7) is None


def test_parse_number():
    assert parsing.parse_number(7) == 7.0
    assert parsing.parse_number(9.8) == 9.8
    assert parsing.parse_number(True) is None
    assert parsing.parse_number("9.8") is None


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"baseScore": 9.8, "baseScoreVersion": "3.1"}, 9.8),
        ({"baseScore": 0.0, "baseScoreVersion": "3.1"}, 0.0),
        ({"baseScore": 0.0}, None),  # how the API marks a missing score
        ({"baseScore": -1.0}, None),
        ({"baseScore": "high"}, None),
        ({}, None),
    ],
)
def test_parse_score(data, expected):
    assert parsing.parse_score(data) == expected


def test_parse_lines():
    assert parsing.parse_lines("CVE-1\n GHSA-2 \n\n") == ("CVE-1", "GHSA-2")
    assert parsing.parse_lines(["CVE-1"]) == ()
    assert parsing.parse_lines(None) == ()


def test_parse_strings():
    assert parsing.parse_strings(["cisa_kev", 3, "eukev_kev"]) == ("cisa_kev", "eukev_kev")
    assert parsing.parse_strings("cisa_kev") == ()


def test_parse_dicts():
    assert parsing.parse_dicts([{"a": 1}, "junk", None]) == [{"a": 1}]
    assert parsing.parse_dicts({"a": 1}) == []


def test_parse_links():
    links = [{"id": "1", "vendor": {"name": "Cisco"}}, {"id": "2"}, {"id": "3", "vendor": "x"}]
    assert parsing.parse_links(links, "vendor") == [{"name": "Cisco"}]


def test_parse_vendor_names():
    links = [{"vendor": {"name": "Cisco"}}, {"vendor": {"name": ""}}, {"vendor": {}}]
    assert parsing.parse_vendor_names(links) == ("Cisco",)
    assert parsing.parse_vendor_names(None) == ()


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("EUVD-1999-0001,CVE-1999-0001", ("EUVD-1999-0001", "CVE-1999-0001")),
        ("EUVD-1999-0001,CVE-1999-0001\r\n", ("EUVD-1999-0001", "CVE-1999-0001")),
        ("euvd_id,cve_id", None),
        ("no-comma-here", None),
        ("", None),
    ],
)
def test_parse_mapping_line(line, expected):
    assert parsing.parse_mapping_line(line) == expected


def test_expect_dict():
    assert parsing.expect_dict({"a": 1}) == {"a": 1}
    with pytest.raises(EUVDError, match=r"expected a JSON object.*got list"):
        parsing.expect_dict([])


def test_expect_list():
    assert parsing.expect_list([1]) == [1]
    with pytest.raises(EUVDError, match=r"expected a JSON list.*got dict"):
        parsing.expect_list({})
