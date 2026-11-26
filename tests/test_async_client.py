from __future__ import annotations

import asyncio

import pytest

from pyeuvd import (
    APIError,
    AsyncEUVD,
    NotFoundError,
    ThreadedTransport,
    UrllibTransport,
    VulnerabilityDetail,
)

from .fakes import BASE_URL, FakeAsyncTransport, json_response, load_json


@pytest.fixture(params=["blocking transport in threads", "async transport"])
def euvd(request, transport) -> AsyncEUVD:
    """The async client, once on top of each kind of transport."""
    if request.param == "async transport":
        return AsyncEUVD(base_url=BASE_URL, transport=FakeAsyncTransport(transport))
    return AsyncEUVD(base_url=BASE_URL, transport=transport)


def test_latest_lists(euvd, transport):
    async def main():
        return await asyncio.gather(euvd.latest(), euvd.latest_exploited(), euvd.latest_critical())

    latest, exploited, critical = asyncio.run(main())

    assert [v.id for v in latest] == [v["id"] for v in load_json("latest.json")]
    assert all(v.exploited for v in exploited)
    assert critical
    assert sorted(transport.paths) == [
        "/criticalvulnerabilities",
        "/exploitedvulnerabilities",
        "/lastvulnerabilities",
    ]


def test_search(euvd, transport):
    transport.total = 25

    page = asyncio.run(euvd.search(vendor="Cisco", size=10, page=1))

    assert (len(page), page.page, page.total) == (10, 1, 25)
    assert transport.calls == [("/search", {"page": "1", "size": "10", "vendor": "Cisco"})]


def test_iter_search(euvd, transport):
    transport.total = 25

    async def main():
        everything = [v.id async for v in euvd.iter_search(size=10, vendor="Cisco")]
        limited = [v.id async for v in euvd.iter_search(limit=3)]
        nothing = [v.id async for v in euvd.iter_search(limit=0)]
        return everything, limited, nothing

    everything, limited, nothing = asyncio.run(main())

    assert everything == [f"EUVD-2025-{n}" for n in range(25)]
    assert limited == ["EUVD-2025-0", "EUVD-2025-1", "EUVD-2025-2"]
    assert nothing == []
    assert [params["page"] for _, params in transport.calls] == ["0", "1", "2", "0"]


def test_single_records(euvd):
    async def main():
        return (
            await euvd.get_vulnerability("CVE-2024-3400"),
            await euvd.get_advisory("cisco-sa-ata19x-multi-RDTEqRsy"),
            await euvd.kev(),
            await euvd.get_json("/kev/dump"),
        )

    vuln, advisory, kev, raw = asyncio.run(main())

    assert isinstance(vuln, VulnerabilityDetail)
    assert vuln.id == "EUVD-2024-31989"
    assert advisory.id == "cisco-sa-ata19x-multi-RDTEqRsy"
    assert len(kev) == 3
    assert raw == load_json("kev.json")


def test_cve_mapping(euvd):
    async def main():
        return [row async for row in euvd.cve_mapping()]

    rows = asyncio.run(main())

    assert rows[0] == ("EUVD-1999-0001", "CVE-1999-0001")
    assert len(rows) == 5


def test_cve_mapping_can_be_stopped_early(euvd):
    async def main():
        rows = euvd.cve_mapping()
        first = await anext(rows)
        await rows.aclose()
        return first

    assert asyncio.run(main()) == ("EUVD-1999-0001", "CVE-1999-0001")


def test_errors(euvd, transport):
    transport.replies["/search"] = json_response({"error": "bad"}, status=400)
    transport.replies["/dump/cve-euvd-mapping"] = json_response({"error": "boom"}, status=500)

    async def main():
        with pytest.raises(NotFoundError):
            await euvd.get_vulnerability("missing")
        with pytest.raises(APIError, match="400: bad"):
            await euvd.search()
        with pytest.raises(APIError, match="500: boom"):
            [row async for row in euvd.cve_mapping()]

    asyncio.run(main())


def test_default_transport_runs_urllib_in_threads():
    euvd = AsyncEUVD(timeout=5)

    assert isinstance(euvd.transport, ThreadedTransport)
    assert isinstance(euvd.transport.transport, UrllibTransport)
    assert euvd.transport.transport.timeout == 5


def test_ids_are_trimmed(euvd, transport):
    async def main():
        await euvd.get_vulnerability("  CVE-2024-3400\n")
        await euvd.get_advisory(" oxas-adv-2024-0002 ")

    asyncio.run(main())

    assert transport.calls == [
        ("/enisaid", {"id": "CVE-2024-3400"}),
        ("/advisory", {"id": "oxas-adv-2024-0002"}),
    ]


def test_async_with_block_closes_the_transport(euvd, transport):
    closed = []
    transport.close = lambda: closed.append("blocking")
    if isinstance(euvd.transport, FakeAsyncTransport):
        euvd.transport.aclose = lambda: asyncio.sleep(0, closed.append("async"))

    async def main():
        async with euvd as client:
            await client.latest()
            assert closed == []

    asyncio.run(main())

    assert len(closed) == 1


def test_aclose_works_with_default_transports(transport):
    async def main():
        async with AsyncEUVD() as default:
            assert isinstance(default.transport, ThreadedTransport)
        await AsyncEUVD(transport=FakeAsyncTransport(transport)).aclose()

    asyncio.run(main())


def test_requests_are_logged(euvd, caplog):
    async def main():
        await euvd.search(vendor="Cisco")
        return [row async for row in euvd.cve_mapping()]

    with caplog.at_level("DEBUG", logger="pyeuvd"):
        asyncio.run(main())

    assert f"GET {BASE_URL}/search?page=0&size=10&vendor=Cisco -> 200 in " in caplog.text
    assert f"GET {BASE_URL}/dump/cve-euvd-mapping (streaming)" in caplog.text


def test_count(euvd, transport):
    transport.total = 267

    assert asyncio.run(euvd.count(vendor="Cisco")) == 267
    assert transport.calls == [("/search", {"page": "0", "size": "1", "vendor": "Cisco"})]


def test_errors_name_the_url(euvd, transport):
    transport.replies["/dump/cve-euvd-mapping"] = json_response({"error": "boom"}, status=500)

    async def main():
        with pytest.raises(NotFoundError) as not_found:
            await euvd.get_vulnerability("missing")
        with pytest.raises(APIError) as stream:
            [row async for row in euvd.cve_mapping()]
        return not_found.value, stream.value

    not_found, stream = asyncio.run(main())

    assert str(not_found) == f"404: EUVD not found ({BASE_URL}/enisaid?id=missing)"
    assert stream.url == f"{BASE_URL}/dump/cve-euvd-mapping"


def test_timeout_and_transport_cannot_be_combined(transport):
    with pytest.raises(ValueError, match="set it on your transport"):
        AsyncEUVD(timeout=5, transport=transport)
