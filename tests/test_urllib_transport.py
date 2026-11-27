"""The built-in transport, tested against a real local HTTP server."""

from __future__ import annotations

import asyncio
import socket
import ssl
import urllib.request
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from pyeuvd import EUVD, APIError, AsyncEUVD, TransportError, UrllibTransport, __version__
from pyeuvd.transports import urllib_transport

from .fakes import load_json, load_text
from .server import Reply, run_local_api

BUSY = Reply(status=503, body=b'{"error": "busy"}')
CUT_OFF = Reply(body=b"[", declared_length=100)


@pytest.fixture
def transport() -> UrllibTransport:
    return UrllibTransport(timeout=5, retries=0)


@pytest.fixture
def unused_url() -> str:
    """A local URL nothing is listening on."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{probe.getsockname()[1]}/api"


def test_get(transport, api):
    response = transport.get(api.url + "/kev/dump")

    assert response.status == 200
    assert response.json() == load_json("kev.json")


def test_get_returns_error_responses_instead_of_raising(transport, api):
    response = transport.get(api.url + "/enisaid?id=missing")

    assert response.status == 404
    assert response.json() == {"error": "EUVD not found"}


def test_get_keeps_the_status_when_the_error_body_is_cut_off(transport, api):
    api.replies["/kev/dump"] = Reply(status=500, body=b"{", declared_length=500)

    assert transport.get(api.url + "/kev/dump").status == 500


def test_default_headers(transport, api):
    transport.get(api.url + "/kev/dump")

    assert api.headers[0]["user-agent"] == f"py-euvd/{__version__}"
    assert "application/json" in api.headers[0]["accept"]


def test_extra_headers(api):
    transport = UrllibTransport(headers={"X-Team": "blue", "User-Agent": "my-app/1.0"})
    transport.get(api.url + "/kev/dump")

    assert api.headers[0]["x-team"] == "blue"
    assert api.headers[0]["user-agent"] == "my-app/1.0"


def test_custom_opener(api):
    opener = urllib.request.build_opener()
    opener.addheaders = [("X-Via", "opener")]

    UrllibTransport(opener=opener).get(api.url + "/kev/dump")

    assert api.headers[0]["x-via"] == "opener"


def test_cut_off_response_becomes_transport_error(transport, api):
    api.replies["/kev/dump"] = Reply(body=b'[{"cveId": "CVE-1"', declared_length=5000)

    with pytest.raises(TransportError):
        transport.get(api.url + "/kev/dump")


def test_timeout_becomes_transport_error(api):
    api.replies["/kev/dump"] = Reply(body=b"[]", delay=0.5)

    with pytest.raises(TransportError, match="timed out"):
        UrllibTransport(timeout=0.1, retries=0).get(api.url + "/kev/dump")


def test_refused_connection_becomes_transport_error(transport, unused_url):
    with pytest.raises(TransportError, match="refused"):
        transport.get(unused_url)
    with pytest.raises(TransportError, match="refused"):
        list(transport.stream_lines(unused_url))


def test_stream_lines(transport, api):
    api.replies["/dump/cve-euvd-mapping"] = Reply(body=b"a,b\r\nc,d\n\ne,f")

    lines = list(transport.stream_lines(api.url + "/dump/cve-euvd-mapping"))

    assert lines == ["a,b", "c,d", "", "e,f"]


def test_stream_lines_raises_for_error_status(transport, api):
    api.replies["/dump/cve-euvd-mapping"] = Reply(status=500, body=b'{"error": "boom"}')

    with pytest.raises(APIError, match="500: boom"):
        list(transport.stream_lines(api.url + "/dump/cve-euvd-mapping"))


def test_stream_lines_notices_a_cut_off_download(transport, api):
    body = load_text("cve_mapping.csv").encode()
    api.replies["/dump/cve-euvd-mapping"] = Reply(body=body, declared_length=len(body) + 1000)

    with pytest.raises(TransportError, match="ended early"):
        list(transport.stream_lines(api.url + "/dump/cve-euvd-mapping"))


def test_stream_lines_can_be_stopped_early(transport, api):
    lines = transport.stream_lines(api.url + "/dump/cve-euvd-mapping")

    assert next(lines) == "euvd_id,cve_id"
    lines.close()


def test_client_end_to_end(api):
    euvd = EUVD(base_url=api.url)

    assert euvd.get_vulnerability("CVE-2024-3400").id == "EUVD-2024-31989"
    assert len(list(euvd.iter_search(size=10, vendor="Cisco"))) == 25
    assert next(euvd.cve_mapping()) == ("EUVD-1999-0001", "CVE-1999-0001")


def test_async_client_end_to_end(api):
    async def main():
        euvd = AsyncEUVD(base_url=api.url)
        vuln = await euvd.get_vulnerability("CVE-2024-3400")
        found = [v async for v in euvd.iter_search(size=10)]
        rows = [row async for row in euvd.cve_mapping()]
        return vuln, found, rows

    vuln, found, rows = asyncio.run(main())

    assert vuln.id == "EUVD-2024-31989"
    assert len(found) == 25
    assert len(rows) == 5


@pytest.fixture
def retrying() -> UrllibTransport:
    return UrllibTransport(timeout=5, retries=2, backoff=0)


def test_get_retries_busy_statuses(retrying, api):
    api.replies["/kev/dump"] = [BUSY, BUSY, Reply(body=b"[]")]

    assert retrying.get(api.url + "/kev/dump").status == 200
    assert len(api.headers) == 3


def test_get_retries_network_failures(retrying, api):
    api.replies["/kev/dump"] = [CUT_OFF, Reply(body=b"[]")]

    assert retrying.get(api.url + "/kev/dump").status == 200
    assert len(api.headers) == 2


def test_get_gives_up_after_the_last_retry(retrying, api):
    api.replies["/kev/dump"] = BUSY
    api.replies["/advisory"] = CUT_OFF

    assert retrying.get(api.url + "/kev/dump").status == 503
    assert len(api.headers) == 3
    with pytest.raises(TransportError):
        retrying.get(api.url + "/advisory")
    assert len(api.headers) == 6


def test_get_does_not_retry_other_errors(retrying, api):
    api.replies["/kev/dump"] = Reply(status=500, body=b"{}")

    assert retrying.get(api.url + "/enisaid?id=missing").status == 404
    assert retrying.get(api.url + "/kev/dump").status == 500
    assert len(api.headers) == 2


def test_retries_wait_longer_each_time(api, monkeypatch, caplog):
    waits = []
    # Replace the module's view of "time" only, so the test server is not affected.
    monkeypatch.setattr(urllib_transport, "time", SimpleNamespace(sleep=waits.append))
    api.replies["/kev/dump"] = BUSY

    with caplog.at_level("DEBUG", logger="pyeuvd"):
        UrllibTransport(retries=3, backoff=0.5).get(api.url + "/kev/dump")

    assert waits == [0.5, 1.0, 2.0]
    assert "failed (status 503), retrying in 0.5 s" in caplog.text


def test_stream_lines_retries_before_the_first_line(retrying, api):
    api.replies["/dump/cve-euvd-mapping"] = [BUSY, Reply(body=b"a,b\n")]

    assert list(retrying.stream_lines(api.url + "/dump/cve-euvd-mapping")) == ["a,b"]
    assert len(api.headers) == 2


def test_stream_lines_gives_up_after_the_last_retry(retrying, api):
    api.replies["/dump/cve-euvd-mapping"] = BUSY

    with pytest.raises(APIError, match="503: busy"):
        list(retrying.stream_lines(api.url + "/dump/cve-euvd-mapping"))
    assert len(api.headers) == 3


def test_stream_lines_does_not_retry_other_errors(retrying, api):
    api.replies["/dump/cve-euvd-mapping"] = Reply(status=500, body=b"{}")

    with pytest.raises(APIError):
        list(retrying.stream_lines(api.url + "/dump/cve-euvd-mapping"))
    assert len(api.headers) == 1


def test_stream_lines_does_not_retry_once_lines_were_read(retrying, api):
    api.replies["/dump/cve-euvd-mapping"] = Reply(body=b"a,b\n", declared_length=100)
    seen = []

    with pytest.raises(TransportError, match="ended early"):
        for line in retrying.stream_lines(api.url + "/dump/cve-euvd-mapping"):
            seen.append(line)

    assert seen == ["a,b"]
    assert len(api.headers) == 1


def test_stream_lines_of_an_empty_file(retrying, api):
    api.replies["/dump/cve-euvd-mapping"] = Reply(body=b"")

    assert list(retrying.stream_lines(api.url + "/dump/cve-euvd-mapping")) == []


class FailingOpener:
    """Stands in for a urllib opener and fails every request the same way."""

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    def open(self, request, timeout=None):
        self.calls += 1
        raise self.error


def test_certificate_failures_are_not_retried():
    opener = FailingOpener(URLError(ssl.SSLCertVerificationError("certificate verify failed")))
    transport = UrllibTransport(opener=opener, retries=2, backoff=0)

    with pytest.raises(TransportError, match="certificate verify failed"):
        transport.get("https://x.test/api/kev/dump")
    assert opener.calls == 1

    with pytest.raises(TransportError, match="certificate verify failed"):
        list(transport.stream_lines("https://x.test/api/dump/cve-euvd-mapping"))
    assert opener.calls == 2


def test_other_connection_failures_are_retried():
    opener = FailingOpener(URLError(ConnectionRefusedError("refused")))
    transport = UrllibTransport(opener=opener, retries=2, backoff=0)

    with pytest.raises(TransportError):
        transport.get("https://x.test/api/kev/dump")
    assert opener.calls == 3

    with pytest.raises(TransportError):
        list(transport.stream_lines("https://x.test/api/dump/cve-euvd-mapping"))
    assert opener.calls == 6


def test_proxy_from_the_environment_is_used(api, monkeypatch):
    # The local server acts as the proxy. The host below does not exist, so the
    # request can only succeed by going through it.
    monkeypatch.setenv("http_proxy", api.url.removesuffix("/api"))
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)

    response = UrllibTransport(retries=0).get("http://euvd.invalid/api/kev/dump")

    assert response.json() == load_json("kev.json")
    assert api.headers[0]["host"] == "euvd.invalid"


SECRETS = {"Authorization": "Bearer secret", "Cookie": "session=abc", "X-Api-Key": "k"}


def test_extra_headers_are_not_sent_to_another_host(api):
    with run_local_api() as other:
        api.replies["/kev/dump"] = Reply(status=302, location=other.url + "/kev/dump")
        transport = UrllibTransport(retries=0, headers={**SECRETS, "User-Agent": "my-app/1.0"})

        response = transport.get(api.url + "/kev/dump")

    assert response.json() == load_json("kev.json")
    first, redirected = api.headers[0], other.headers[0]
    assert {name.lower(): first[name.lower()] for name in SECRETS} == {
        name.lower(): value for name, value in SECRETS.items()
    }
    assert first["user-agent"] == "my-app/1.0"
    assert not {name.lower() for name in SECRETS} & redirected.keys()
    assert redirected["user-agent"] == "my-app/1.0"
    assert "application/json" in redirected["accept"]


def test_extra_headers_are_not_sent_on_a_redirect_to_the_same_host(api):
    api.replies["/old"] = Reply(status=301, location=api.url + "/kev/dump")

    UrllibTransport(retries=0, headers=SECRETS).get(api.url + "/old")

    assert "authorization" in api.headers[0]
    assert not {name.lower() for name in SECRETS} & api.headers[1].keys()


def test_extra_headers_are_not_sent_along_when_a_download_is_redirected(api):
    with run_local_api() as other:
        api.replies["/dump/cve-euvd-mapping"] = Reply(
            status=302, location=other.url + "/dump/cve-euvd-mapping"
        )
        transport = UrllibTransport(retries=0, headers=SECRETS)

        lines = list(transport.stream_lines(api.url + "/dump/cve-euvd-mapping"))

    assert lines[0] == "euvd_id,cve_id"
    assert "authorization" in api.headers[0]
    assert not {name.lower() for name in SECRETS} & other.headers[0].keys()
