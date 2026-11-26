from __future__ import annotations

from datetime import date

import pytest

from pyeuvd import (
    EUVD,
    APIError,
    EUVDError,
    NotFoundError,
    Response,
    Transport,
    TransportError,
    UrllibTransport,
    VulnerabilityDetail,
)

from .fakes import BASE_URL, json_response, load_json


def test_latest_lists(euvd, transport):
    assert [v.id for v in euvd.latest()] == [v["id"] for v in load_json("latest.json")]
    assert all(v.exploited for v in euvd.latest_exploited())
    assert euvd.latest_critical()
    assert transport.paths == [
        "/lastvulnerabilities",
        "/exploitedvulnerabilities",
        "/criticalvulnerabilities",
    ]


def test_search(euvd, transport):
    page = euvd.search(vendor="Cisco", exploited=False, from_date=date(2024, 1, 1), size=2)

    assert transport.calls == [
        (
            "/search",
            {
                "page": "0",
                "size": "2",
                "vendor": "Cisco",
                "exploited": "false",
                "fromDate": "2024-01-01",
            },
        )
    ]
    assert (page.total, page.page, page.size, len(page)) == (2, 0, 2, 2)
    assert not page.has_next


def test_search_rejects_bad_arguments_before_any_request(euvd, transport):
    with pytest.raises(ValueError):
        euvd.search(size=101)
    with pytest.raises(TypeError, match="colour"):
        euvd.search(colour="red")
    assert transport.calls == []


def test_iter_search_walks_all_pages(euvd, transport):
    transport.total = 25

    ids = [v.id for v in euvd.iter_search(size=10, vendor="Cisco")]

    assert ids == [f"EUVD-2025-{n}" for n in range(25)]
    assert [params["page"] for _, params in transport.calls] == ["0", "1", "2"]
    assert all(params["vendor"] == "Cisco" for _, params in transport.calls)


def test_iter_search_stops_at_limit(euvd, transport):
    transport.total = 1000

    assert len(list(euvd.iter_search(limit=150))) == 150
    assert len(transport.calls) == 2
    assert len(list(euvd.iter_search(limit=5))) == 5
    assert transport.calls[-1][1]["size"] == "5"
    assert list(euvd.iter_search(limit=0)) == []
    assert len(transport.calls) == 3


def test_iter_search_limit_on_a_page_boundary(euvd, transport):
    transport.total = 1000

    assert len(list(euvd.iter_search(size=10, limit=20))) == 20
    assert len(transport.calls) == 2


def test_iter_search_with_no_results(euvd, transport):
    transport.total = 0
    assert list(euvd.iter_search()) == []


def test_get_vulnerability(euvd, transport):
    vuln = euvd.get_vulnerability("CVE-2024-3400")

    assert isinstance(vuln, VulnerabilityDetail)
    assert vuln.id == "EUVD-2024-31989"
    assert vuln.source_records and vuln.advisories
    assert transport.calls == [("/enisaid", {"id": "CVE-2024-3400"})]


def test_get_vulnerability_not_found(euvd):
    with pytest.raises(NotFoundError, match="404: EUVD not found"):
        euvd.get_vulnerability("missing")


def test_get_advisory(euvd, transport):
    advisory = euvd.get_advisory("cisco-sa-ata19x-multi-RDTEqRsy")

    assert advisory.source == "csaf_cisco"
    assert advisory.vulnerabilities and advisory.source_records
    assert transport.calls == [("/advisory", {"id": "cisco-sa-ata19x-multi-RDTEqRsy"})]


def test_kev(euvd):
    assert [e.cve_id for e in euvd.kev()] == [e["cveId"] for e in load_json("kev.json")]


def test_cve_mapping(euvd):
    rows = list(euvd.cve_mapping())

    assert rows[0] == ("EUVD-1999-0001", "CVE-1999-0001")
    assert len(rows) == 5


def test_cve_mapping_skips_junk_lines(euvd, transport):
    body = b"euvd_id,cve_id\n\nEUVD-1,CVE-1\nno-comma-here\nEUVD-2,CVE-2\n"
    transport.replies["/dump/cve-euvd-mapping"] = Response(200, body)

    assert list(euvd.cve_mapping()) == [("EUVD-1", "CVE-1"), ("EUVD-2", "CVE-2")]


def test_cve_mapping_closes_the_download_when_stopped_early():
    closed = []

    class Streaming(Transport):
        def get(self, url):
            raise AssertionError("not used")

        def stream_lines(self, url):
            try:
                yield "EUVD-1,CVE-1"
                yield "EUVD-2,CVE-2"
            finally:
                closed.append(url)

    rows = EUVD(base_url=BASE_URL, transport=Streaming()).cve_mapping()
    assert next(rows) == ("EUVD-1", "CVE-1")
    rows.close()

    assert closed == [f"{BASE_URL}/dump/cve-euvd-mapping"]


def test_get_json_reaches_any_endpoint(euvd, transport):
    transport.replies["/future/endpoint"] = json_response({"new": True})

    assert euvd.get_json("/future/endpoint", {"q": "1"}) == {"new": True}
    assert transport.calls == [("/future/endpoint", {"q": "1"})]


def test_api_errors_are_raised(euvd, transport):
    transport.replies["/search"] = json_response({"error": "Invalid 'fromDate'"}, status=400)
    transport.replies["/dump/cve-euvd-mapping"] = json_response({"error": "boom"}, status=500)

    with pytest.raises(APIError, match="400: Invalid 'fromDate'"):
        euvd.search(from_date="nope")
    with pytest.raises(APIError, match="500: boom"):
        list(euvd.cve_mapping())


@pytest.mark.parametrize(
    ("path", "reply", "call"),
    [
        ("/lastvulnerabilities", b"<html>maintenance</html>", lambda e: e.latest()),
        ("/lastvulnerabilities", b'{"items": []}', lambda e: e.latest()),
        ("/kev/dump", b"{}", lambda e: e.kev()),
        ("/search", b"[]", lambda e: e.search()),
        ("/enisaid", b"[]", lambda e: e.get_vulnerability("x")),
        ("/advisory", b'"text"', lambda e: e.get_advisory("x")),
    ],
)
def test_unexpected_responses_raise_a_clear_error(euvd, transport, path, reply, call):
    transport.replies[path] = Response(200, reply)

    with pytest.raises(EUVDError):
        call(euvd)


def test_default_transport():
    euvd = EUVD(timeout=5)

    assert isinstance(euvd.transport, UrllibTransport)
    assert euvd.transport.timeout == 5
    assert euvd.base_url == "https://euvdservices.enisa.europa.eu/api"


def test_trailing_slash_in_base_url(transport):
    EUVD(base_url=BASE_URL + "/", transport=transport).latest()
    assert transport.paths == ["/lastvulnerabilities"]


@pytest.mark.parametrize("base_url", ["file:///etc/passwd", "ftp://example.test", "example.test"])
def test_base_url_must_be_http(base_url):
    with pytest.raises(ValueError, match="http"):
        EUVD(base_url=base_url)


def test_ids_are_trimmed(euvd, transport):
    euvd.get_vulnerability("  CVE-2024-3400\n")
    euvd.get_advisory(" oxas-adv-2024-0002 ")

    assert transport.calls == [
        ("/enisaid", {"id": "CVE-2024-3400"}),
        ("/advisory", {"id": "oxas-adv-2024-0002"}),
    ]


def test_with_block_closes_the_transport(transport):
    closed = []
    transport.close = lambda: closed.append(True)

    with EUVD(base_url=BASE_URL, transport=transport) as euvd:
        euvd.latest()
        assert closed == []

    assert closed == [True]


def test_close_works_with_the_default_transport():
    with EUVD() as euvd:
        assert isinstance(euvd.transport, UrllibTransport)
    euvd.close()


def test_requests_are_logged(euvd, caplog):
    with caplog.at_level("DEBUG", logger="pyeuvd"):
        euvd.search(vendor="Cisco")
        list(euvd.cve_mapping())
        with pytest.raises(NotFoundError):
            euvd.get_vulnerability("missing")

    assert f"GET {BASE_URL}/search?page=0&size=10&vendor=Cisco -> 200 in " in caplog.text
    assert f"GET {BASE_URL}/dump/cve-euvd-mapping (streaming)" in caplog.text
    assert f"GET {BASE_URL}/enisaid?id=missing -> 404 in " in caplog.text


def test_search_docstrings_name_every_filter():
    from pyeuvd import AsyncEUVD, SearchFilters

    for client in (EUVD, AsyncEUVD):
        for name in SearchFilters.__annotations__:
            assert f"``{name}``" in client.search.__doc__, name


def test_count(euvd, transport):
    transport.total = 267

    assert euvd.count(vendor="Cisco", from_score=9) == 267
    assert transport.calls == [
        ("/search", {"page": "0", "size": "1", "vendor": "Cisco", "fromScore": "9"})
    ]


def test_errors_name_the_url(euvd, transport):
    transport.replies["/kev/dump"] = Response(200, b"<html>maintenance</html>")
    transport.replies["/lastvulnerabilities"] = Response(200, b"{}")
    transport.replies["/dump/cve-euvd-mapping"] = json_response({"error": "boom"}, status=500)

    with pytest.raises(NotFoundError) as not_found:
        euvd.get_vulnerability("missing")
    with pytest.raises(EUVDError) as not_json:
        euvd.kev()
    with pytest.raises(EUVDError) as wrong_shape:
        euvd.latest()
    with pytest.raises(APIError) as stream:
        list(euvd.cve_mapping())

    assert not_found.value.url == f"{BASE_URL}/enisaid?id=missing"
    assert str(not_found.value) == f"404: EUVD not found ({BASE_URL}/enisaid?id=missing)"
    assert not_found.value.message == "EUVD not found"
    assert not_json.value.url == f"{BASE_URL}/kev/dump"
    assert wrong_shape.value.url == f"{BASE_URL}/lastvulnerabilities"
    assert stream.value.url == f"{BASE_URL}/dump/cve-euvd-mapping"


def test_transport_errors_name_the_url():
    class Offline(Transport):
        def get(self, url):
            raise TransportError("no network")

    with pytest.raises(TransportError) as info:
        EUVD(base_url=BASE_URL, transport=Offline()).latest()

    assert str(info.value) == f"no network ({BASE_URL}/lastvulnerabilities)"


def test_a_url_set_by_the_transport_is_kept():
    class Redirecting(Transport):
        def get(self, url):
            error = TransportError("no network")
            error.url = "https://mirror.test/latest"
            raise error

    with pytest.raises(TransportError) as info:
        EUVD(base_url=BASE_URL, transport=Redirecting()).latest()

    assert info.value.url == "https://mirror.test/latest"


def test_timeout_and_transport_cannot_be_combined(transport):
    with pytest.raises(ValueError, match="set it on your transport"):
        EUVD(timeout=5, transport=transport)
    assert EUVD().transport.timeout == 30
