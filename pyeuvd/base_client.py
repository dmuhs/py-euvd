from __future__ import annotations

import logging
import time
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from .constants import BASE_URL, DEFAULT_TIMEOUT
from .errors import EUVDError
from .response import Response
from .utils import build_url

logger = logging.getLogger(__name__)


class BaseClient:
    """Shared by the sync and async clients: URL building and response decoding."""

    def __init__(self, base_url: str = BASE_URL) -> None:
        if urllib.parse.urlsplit(base_url).scheme not in ("http", "https"):
            raise ValueError("base_url must start with http:// or https://")
        self.base_url = base_url.rstrip("/")

    def _url(self, path: str, params: Mapping[str, str] | None = None) -> str:
        return build_url(self.base_url, path, params)

    @staticmethod
    def _timeout(timeout: float | None, transport: object) -> float:
        """The timeout for the built-in transport. A custom transport sets its own."""
        if timeout is not None and transport is not None:
            raise ValueError(
                "timeout only applies to the built-in transport; set it on your transport"
            )
        return DEFAULT_TIMEOUT if timeout is None else timeout

    @staticmethod
    @contextmanager
    def _errors_at(url: str) -> Iterator[None]:
        """Add the URL to any pyeuvd error raised inside the block."""
        try:
            yield
        except EUVDError as exc:
            if exc.url is None:
                exc.url = url
            raise

    @staticmethod
    def _decode(
        url: str,
        response: Response,
        started: float,
        check: Callable[[Any], Any] | None = None,
    ) -> Any:
        """Log the response, then return its JSON or raise for an error status.

        ``started`` is the ``time.perf_counter()`` reading from before the request.
        ``check`` is applied to the JSON, to reject data of the wrong shape.
        """
        elapsed = (time.perf_counter() - started) * 1000
        logger.debug("GET %s -> %d in %.0f ms", url, response.status, elapsed)
        response.raise_for_status()
        data = response.json()
        return data if check is None else check(data)

    @staticmethod
    def _page_size(size: int, limit: int | None) -> int:
        """The page size to request: never more than ``limit``."""
        return size if limit is None else min(size, max(limit, 1))
