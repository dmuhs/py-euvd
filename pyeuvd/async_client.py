from __future__ import annotations

import contextlib
import time
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Mapping
from typing import Any, Self, Unpack

from .base_client import BaseClient, logger
from .constants import BASE_URL, MAX_PAGE_SIZE
from .filters import SearchFilters
from .models import AdvisoryDetail, KevEntry, Page, Vulnerability, VulnerabilityDetail
from .parsing import expect_dict, expect_list, parse_mapping_line
from .transports import AsyncTransport, ThreadedTransport, Transport, UrllibTransport
from .utils import build_search_params


class AsyncEUVD(BaseClient):
    """Async client for the EU Vulnerability Database.

    It has the same methods as ``EUVD``:

    ```python
    euvd = AsyncEUVD()
    vuln = await euvd.get_vulnerability("CVE-2024-3400")
    ```

    ``timeout`` is in seconds, 30 by default. The built-in transport runs each
    request in a worker thread. Pass an ``AsyncTransport`` to use an async HTTP
    library. A blocking ``Transport`` also works and runs in threads. A
    transport sets its own timeout, so passing both raises ``ValueError``.

    The client can be used in an ``async with`` block, which closes the
    transport at the end. The built-in transport holds nothing open, so this
    is optional.
    """

    def __init__(
        self,
        *,
        base_url: str = BASE_URL,
        timeout: float | None = None,
        transport: AsyncTransport | Transport | None = None,
    ) -> None:
        super().__init__(base_url)
        timeout = self._timeout(timeout, transport)
        if transport is None:
            transport = UrllibTransport(timeout=timeout)
        if isinstance(transport, Transport):
            transport = ThreadedTransport(transport)
        self.transport: AsyncTransport = transport

    async def aclose(self) -> None:
        """Close the transport."""
        await self.transport.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def get_json(self, path: str, params: Mapping[str, str] | None = None) -> Any:
        """Call any API path and return the decoded JSON.

        Use it for endpoints this library does not cover.
        """
        return await self._get(path, params)

    async def _get(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        check: Callable[[Any], Any] | None = None,
    ) -> Any:
        url = self._url(path, params)
        with self._errors_at(url):
            started = time.perf_counter()
            return self._decode(url, await self.transport.get(url), started, check)

    async def latest(self) -> list[Vulnerability]:
        """The API's list of latest entries. It holds at most 8."""
        data = await self._get("/lastvulnerabilities", check=expect_list)
        return Vulnerability.from_list(data)

    async def latest_exploited(self) -> list[Vulnerability]:
        """The API's list of latest exploited entries. It holds at most 8."""
        data = await self._get("/exploitedvulnerabilities", check=expect_list)
        return Vulnerability.from_list(data)

    async def latest_critical(self) -> list[Vulnerability]:
        """The API's list of latest critical entries. It holds at most 8."""
        data = await self._get("/criticalvulnerabilities", check=expect_list)
        return Vulnerability.from_list(data)

    async def search(
        self, *, page: int = 0, size: int = 10, **filters: Unpack[SearchFilters]
    ) -> Page:
        """Fetch one page of search results. Pages start at 0, ``size`` is at most 100.

        Filters, all optional: ``text``, ``product``, ``vendor``, ``advisory``,
        ``assigner``, ``exploited``, and the ranges ``from_score``/``to_score``,
        ``from_epss``/``to_epss``, ``from_date``/``to_date``,
        ``from_updated_date``/``to_updated_date`` and
        ``from_kev_date``/``to_kev_date``. See ``SearchFilters`` for details.
        """
        params = build_search_params(page, size, filters)
        data = await self._get("/search", params, expect_dict)
        return Page.from_dict(data, page=page, size=size)

    async def count(self, **filters: Unpack[SearchFilters]) -> int:
        """Return how many entries match the filters. Takes the same filters as ``search``."""
        return (await self.search(size=1, **filters)).total

    async def iter_search(
        self,
        *,
        size: int = MAX_PAGE_SIZE,
        limit: int | None = None,
        **filters: Unpack[SearchFilters],
    ) -> AsyncIterator[Vulnerability]:
        """Yield every search result, fetching pages as needed.

        Takes the same filters as ``search``. ``limit`` stops after that many
        results. Without it, a broad search can return hundreds of thousands of
        entries.
        """
        size = self._page_size(size, limit)
        seen = 0
        page = 0
        while limit is None or seen < limit:
            result = await self.search(page=page, size=size, **filters)
            for item in result.items[: None if limit is None else limit - seen]:
                yield item
                seen += 1
            if not result.has_next:
                return
            page += 1

    async def get_vulnerability(self, id: str) -> VulnerabilityDetail:
        """Fetch one entry by EUVD ID, or by another ID such as a CVE ID.

        Raises ``NotFoundError`` if nothing matches.
        """
        data = await self._get("/enisaid", {"id": id.strip()}, expect_dict)
        return VulnerabilityDetail.from_dict(data)

    async def get_advisory(self, id: str) -> AdvisoryDetail:
        """Fetch one advisory by ID. Raises ``NotFoundError`` if nothing matches."""
        data = await self._get("/advisory", {"id": id.strip()}, expect_dict)
        return AdvisoryDetail.from_dict(data)

    async def kev(self) -> list[KevEntry]:
        """Download the full Known Exploited Vulnerabilities list."""
        return KevEntry.from_list(await self._get("/kev/dump", check=expect_list))

    async def cve_mapping(self) -> AsyncGenerator[tuple[str, str], None]:
        """Yield ``(euvd_id, cve_id)`` pairs for every entry linked to a CVE.

        The download is large: several hundred thousand rows.
        """
        url = self._url("/dump/cve-euvd-mapping")
        logger.debug("GET %s (streaming)", url)
        lines = self.transport.stream_lines(url)
        with self._errors_at(url):
            async with contextlib.aclosing(lines):
                async for line in lines:
                    row = parse_mapping_line(line)
                    if row:
                        yield row
