from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request
from collections.abc import Generator, Mapping
from http.client import HTTPException
from typing import Any

from ..constants import DEFAULT_TIMEOUT, USER_AGENT
from ..errors import APIError, TransportError
from ..response import Response
from ..utils import describe_error, is_certificate_error
from .transport import Transport

logger = logging.getLogger(__name__)

# Statuses that mean "try again later".
RETRY_STATUSES = frozenset({429, 502, 503, 504})


class UrllibTransport(Transport):
    """The default transport. Uses only the Python standard library.

    A request that fails with a network error, a timeout or a 429, 502, 503
    or 504 status is tried again up to ``retries`` times. It waits ``backoff``
    seconds before the first retry and twice as long before each one after.
    A failed TLS certificate check is not retried.

    Proxies set in the environment (``HTTPS_PROXY``) are used automatically.
    Pass your own ``urllib.request`` opener for other connection settings,
    and ``headers`` to send extra headers with every request.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 2,
        backoff: float = 0.5,
        opener: urllib.request.OpenerDirector | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.opener = opener or urllib.request.build_opener()
        self.headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/csv",
            **(headers or {}),
        }

    def get(self, url: str) -> Response:
        attempt = 0
        while True:
            try:
                response = self._get_once(url)
            except TransportError as exc:
                if attempt >= self.retries or is_certificate_error(exc.__cause__):
                    raise
                problem = str(exc)
            else:
                if attempt >= self.retries or response.status not in RETRY_STATUSES:
                    return response
                problem = f"status {response.status}"
            self._wait(attempt, url, problem)
            attempt += 1

    def stream_lines(self, url: str) -> Generator[str, None, None]:
        attempt = 0
        while True:
            started = False
            try:
                for line in self._stream_once(url):
                    started = True
                    yield line
                return
            except (TransportError, APIError) as exc:
                if isinstance(exc, APIError):
                    transient = exc.status_code in RETRY_STATUSES
                else:
                    transient = not is_certificate_error(exc.__cause__)
                # Lines already handed out cannot be taken back, so only retry before the first.
                if started or attempt >= self.retries or not transient:
                    raise
                problem = str(exc)
            self._wait(attempt, url, problem)
            attempt += 1

    def _get_once(self, url: str) -> Response:
        try:
            with self._open(url) as reply:
                return Response(reply.status, reply.read())
        except urllib.error.HTTPError as exc:
            return self._error_response(exc)
        except (OSError, HTTPException) as exc:
            raise TransportError(describe_error(exc)) from exc

    def _stream_once(self, url: str) -> Generator[str, None, None]:
        try:
            with self._open(url) as reply:
                expected = reply.headers.get("Content-Length")
                received = 0
                for line in reply:
                    received += len(line)
                    yield line.decode("utf-8", "replace").rstrip("\r\n")
                if expected is not None and received != int(expected):
                    raise TransportError(
                        f"download ended early: got {received} of {expected} bytes"
                    )
        except urllib.error.HTTPError as exc:
            self._error_response(exc).raise_for_status()
        except (OSError, HTTPException) as exc:
            raise TransportError(describe_error(exc)) from exc

    def _wait(self, attempt: int, url: str, problem: str) -> None:
        delay = self.backoff * 2**attempt
        logger.debug("GET %s failed (%s), retrying in %.1f s", url, problem, delay)
        time.sleep(delay)

    def _open(self, url: str) -> Any:
        request = urllib.request.Request(url, headers=self.headers)
        return self.opener.open(request, timeout=self.timeout)

    @staticmethod
    def _error_response(error: urllib.error.HTTPError) -> Response:
        """Turn the exception urllib raises for error statuses into a response."""
        try:
            body = error.read()
        except (OSError, HTTPException):
            body = b""
        finally:
            error.close()
        return Response(error.code, body)
