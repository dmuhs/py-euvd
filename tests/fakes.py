"""Stand-ins for the network, so most tests need no HTTP at all."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pyeuvd import AsyncTransport, Response, Transport

FIXTURES = Path(__file__).parent / "fixtures"
BASE_URL = "https://euvd.test/api"

ROUTES = {
    "/lastvulnerabilities": "latest.json",
    "/exploitedvulnerabilities": "exploited.json",
    "/criticalvulnerabilities": "latest.json",
    "/enisaid": "vulnerability.json",
    "/advisory": "advisory.json",
    "/kev/dump": "kev.json",
    "/dump/cve-euvd-mapping": "cve_mapping.csv",
}


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_json(name: str) -> Any:
    return json.loads(load_text(name))


def json_response(data: Any, status: int = 200) -> Response:
    return Response(status, json.dumps(data).encode())


def canned_response(path: str, params: dict[str, str], total: int) -> Response:
    """Answer the way the real API would, using the saved fixtures."""
    if path == "/search":
        page, size = int(params["page"]), int(params["size"])
        count = max(0, min(size, total - page * size))
        items = [{"id": f"EUVD-2025-{page * size + n}"} for n in range(count)]
        return json_response({"items": items, "total": total})
    if path == "/enisaid" and params.get("id") == "missing":
        return json_response({"error": "EUVD not found"}, status=404)
    if path in ROUTES:
        return Response(200, load_text(ROUTES[path]).encode())
    return json_response({"error": "No API endpoint at this path."}, status=404)


class FakeTransport(Transport):
    """Answers from fixtures and remembers every request."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.replies: dict[str, Response] = {}
        self.total = 2  # number of results the search endpoint pretends to have

    def get(self, url: str) -> Response:
        parts = urlsplit(url)
        path = parts.path.removeprefix("/api")
        params = dict(parse_qsl(parts.query))
        self.calls.append((path, params))
        return self.replies.get(path) or canned_response(path, params, self.total)

    @property
    def paths(self) -> list[str]:
        return [path for path, _ in self.calls]


class FakeAsyncTransport(AsyncTransport):
    """The same answers through the async interface."""

    def __init__(self, fake: FakeTransport) -> None:
        self.fake = fake

    async def get(self, url: str) -> Response:
        return self.fake.get(url)
