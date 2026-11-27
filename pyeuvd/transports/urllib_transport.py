from __future__ import annotations

import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Generator, Mapping
from http.client import HTTPException, HTTPMessage
from typing import IO, Any

from ..constants import DEFAULT_TIMEOUT, USER_AGENT
from ..errors import APIError, EUVDError, TransportError
from ..response import Response
from ..utils import describe_error, is_certificate_error
from .transport import Transport

logger = logging.getLogger(__name__)

# Statuses that mean "try again later".
RETRY_STATUSES = frozenset({429, 502, 503, 504})

DEFAULT_HEADERS = {"User-Agent": USER_AGENT, "Accept": "application/json, text/csv"}

SCHEMES = ("http", "https")


class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    """Leaves a redirect to anything but http or https unfollowed. urllib allows ftp."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if urllib.parse.urlsplit(newurl).scheme not in SCHEMES:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibTransport(Transport):
    """The default transport. Uses only the Python standard library.

    A request that fails with a network error, a timeout or a 429, 502, 503
    or 504 status is tried again up to ``retries`` times. It waits ``backoff``
    seconds before the first retry and twice as long before each one after.
    A failed TLS certificate check is not retried.

    Proxies set in the environment (``HTTPS_PROXY``) are used automatically.
    Pass your own ``urllib.request`` opener for other connection settings,
    and ``headers`` to send extra headers with every request. Extra headers
    are not sent along when the server redirects the request, except a
    replaced ``User-Agent`` or ``Accept``.

    Only ``http`` and ``https`` addresses are fetched. Any other address
    raises ``ValueError``, and a redirect to one is not followed. Your own
    opener follows redirects by its own rules.

    A response larger than ``max_bytes`` raises ``EUVDError``. For
    ``stream_lines`` the limit applies to each line.

    ``timeout`` limits each wait for data, not the whole request.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 2,
        backoff: float = 0.5,
        opener: urllib.request.OpenerDirector | None = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int = 50_000_000,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.opener = opener or urllib.request.build_opener(_RedirectHandler)
        self.headers = dict(headers or {})
        self.max_bytes = max_bytes

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
                body = self._limited(reply.read(self.max_bytes + 1))
                self._check_complete(reply, len(body))
                return Response(reply.status, body)
        except urllib.error.HTTPError as exc:
            return self._error_response(exc)
        except (OSError, HTTPException) as exc:
            raise TransportError(describe_error(exc)) from exc

    def _stream_once(self, url: str) -> Generator[str, None, None]:
        try:
            with self._open(url) as reply:
                received = 0
                while line := self._limited(reply.readline(self.max_bytes + 1)):
                    received += len(line)
                    yield line.decode("utf-8", "replace").rstrip("\r\n")
                self._check_complete(reply, received)
        except urllib.error.HTTPError as exc:
            self._error_response(exc).raise_for_status()
        except (OSError, HTTPException) as exc:
            raise TransportError(describe_error(exc)) from exc

    def _limited(self, data: bytes) -> bytes:
        if len(data) > self.max_bytes:
            raise EUVDError(f"the response is larger than {self.max_bytes} bytes")
        return data

    @staticmethod
    def _check_complete(reply: Any, received: int) -> None:
        expected = reply.headers.get("Content-Length", "")
        if expected.isdecimal() and received < int(expected):
            raise TransportError(f"download ended early: got {received} of {expected} bytes")

    def _wait(self, attempt: int, url: str, problem: str) -> None:
        delay = self.backoff * 2**attempt
        logger.debug("GET %s failed (%s), retrying in %.1f s", url, problem, delay)
        time.sleep(delay)

    def _open(self, url: str) -> Any:
        request = urllib.request.Request(url, headers=DEFAULT_HEADERS)
        if request.type not in SCHEMES:
            raise ValueError("url must start with http:// or https://")
        for name, value in self.headers.items():
            if request.has_header(name.capitalize()):
                request.add_header(name, value)
            else:
                request.add_unredirected_header(name, value)
        return self.opener.open(request, timeout=self.timeout)

    def _error_response(self, error: urllib.error.HTTPError) -> Response:
        """Turn the exception urllib raises for error statuses into a response."""
        try:
            body = error.read(self.max_bytes)
        except (OSError, HTTPException):
            body = b""
        finally:
            error.close()
        return Response(error.code, body)
