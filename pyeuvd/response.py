from __future__ import annotations

import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

from .errors import APIError, EUVDError, NotFoundError
from .utils import printable


@dataclass(frozen=True, slots=True)
class Response:
    """What a transport returns: the HTTP status and the raw body."""

    status: int
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        """Decode the body as JSON. Raises ``EUVDError`` if it is not JSON."""
        try:
            return json.loads(self.body)
        except (ValueError, RecursionError) as exc:
            raise EUVDError("the API did not return JSON") from exc

    def raise_for_status(self) -> None:
        """Raise ``NotFoundError`` or ``APIError`` if the status is not a success."""
        if self.ok:
            return
        error = NotFoundError if self.status == 404 else APIError
        raise error(self.status, self._error_message())

    def _error_message(self) -> str:
        try:
            return printable(str(json.loads(self.body)["error"]))
        except (ValueError, KeyError, TypeError, RecursionError):
            pass
        text = printable(self.body.decode("utf-8", "replace").strip()[:200])
        if text:
            return text
        try:
            return HTTPStatus(self.status).phrase
        except ValueError:
            return "HTTP error"
