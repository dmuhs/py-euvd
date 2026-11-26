from __future__ import annotations

import ssl
from datetime import UTC, date, datetime
from urllib.error import URLError

import pytest

import pyeuvd
from pyeuvd import utils


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "true"),
        (False, "false"),
        (date(2024, 1, 1), "2024-01-01"),
        (datetime(2024, 12, 31, 23, 59), "2024-12-31"),
        ("Cisco", "Cisco"),
        (7.5, "7.5"),
        (90, "90"),
        (["mitre", "redhat"], "mitre,redhat"),
        (("mitre",), "mitre"),
    ],
)
def test_format_param(value, expected):
    assert utils.format_param(value) == expected


def test_build_search_params_uses_api_names():
    params = utils.build_search_params(
        0,
        2,
        {
            "text": "remote code",
            "product": "IOS",
            "vendor": "Cisco",
            "advisory": "cisco-sa-1",
            "assigner": ["mitre", "redhat"],
            "exploited": True,
            "from_score": 7.5,
            "to_score": 10,
            "from_epss": 20,
            "to_epss": 90,
            "from_date": date(2024, 1, 1),
            "to_date": "2024-12-31",
            "from_updated_date": "2024-06-01",
            "to_updated_date": "2024-06-30",
            "from_kev_date": date(2024, 2, 1),
            "to_kev_date": date(2024, 3, 1),
        },
    )

    assert params == {
        "page": "0",
        "size": "2",
        "text": "remote code",
        "product": "IOS",
        "vendor": "Cisco",
        "advisory": "cisco-sa-1",
        "assigner": "mitre,redhat",
        "exploited": "true",
        "fromScore": "7.5",
        "toScore": "10",
        "fromEpss": "20",
        "toEpss": "90",
        "fromDate": "2024-01-01",
        "toDate": "2024-12-31",
        "fromUpdatedDate": "2024-06-01",
        "toUpdatedDate": "2024-06-30",
        "fromKEVDate": "2024-02-01",
        "toKEVDate": "2024-03-01",
    }


def test_build_search_params_skips_none():
    assert utils.build_search_params(3, 10, {"vendor": None}) == {"page": "3", "size": "10"}


@pytest.mark.parametrize(("page", "size"), [(0, 0), (0, 101), (-1, 10)])
def test_build_search_params_rejects_bad_paging(page, size):
    with pytest.raises(ValueError):
        utils.build_search_params(page, size, {})


def test_build_search_params_rejects_unknown_filter():
    with pytest.raises(TypeError, match="colour"):
        utils.build_search_params(0, 10, {"colour": "red"})


@pytest.mark.parametrize(
    ("base", "path", "params", "expected"),
    [
        ("https://x.test/api", "/search", None, "https://x.test/api/search"),
        ("https://x.test/api/", "search", {}, "https://x.test/api/search"),
        ("https://x.test/api", "/kev/dump", None, "https://x.test/api/kev/dump"),
        (
            "https://x.test/api",
            "/search",
            {"text": "a & b", "size": "5"},
            "https://x.test/api/search?text=a+%26+b&size=5",
        ),
    ],
)
def test_build_url(base, path, params, expected):
    assert utils.build_url(base, path, params) == expected


def test_describe_error():
    assert utils.describe_error(TimeoutError("timed out")) == "timed out"
    assert utils.describe_error(URLError("no route to host")) == "no route to host"
    assert utils.describe_error(ConnectionResetError()) == "ConnectionResetError"


@pytest.mark.parametrize(
    ("score", "version", "expected"),
    [
        (None, "3.1", None),
        (0.0, "3.1", "none"),
        (0.1, "3.1", "low"),
        (3.9, "3.1", "low"),
        (4.0, "3.1", "medium"),
        (6.9, "4.0", "medium"),
        (7.0, "4.0", "high"),
        (8.9, "3.0", "high"),
        (9.0, "3.1", "critical"),
        (10.0, None, "critical"),
        # CVSS 2 has no "critical" and no "none".
        (10.0, "2.0", "high"),
        (7.0, "2.0", "high"),
        (6.9, "2.0", "medium"),
        (4.0, "2.0", "medium"),
        (0.0, "2.0", "low"),
    ],
)
def test_severity_rating(score, version, expected):
    assert utils.severity_rating(score, version) == expected


def test_to_plain():
    class WithDict:
        def to_dict(self):
            return {"id": "x"}

    assert utils.to_plain(datetime(2024, 4, 12, 7, 20, tzinfo=UTC)) == "2024-04-12T07:20:00+00:00"
    assert utils.to_plain(date(2025, 10, 6)) == "2025-10-06"
    assert utils.to_plain(("a", date(2025, 1, 2), (1,))) == ["a", "2025-01-02", [1]]
    assert utils.to_plain(WithDict()) == {"id": "x"}
    assert utils.to_plain(9.8) == 9.8
    assert utils.to_plain(None) is None


def test_is_certificate_error():
    failed_check = ssl.SSLCertVerificationError("certificate verify failed")

    assert utils.is_certificate_error(failed_check)
    assert utils.is_certificate_error(URLError(failed_check))
    assert not utils.is_certificate_error(URLError(ConnectionRefusedError()))
    assert not utils.is_certificate_error(TimeoutError("timed out"))
    assert not utils.is_certificate_error(None)


def test_severity_type_is_importable_from_the_top_level():
    assert pyeuvd.Severity is utils.Severity
