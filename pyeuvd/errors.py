"""Errors raised by pyeuvd. All of them inherit from ``EUVDError``."""

from __future__ import annotations

from typing import Any


class EUVDError(Exception):
    """Base class for all pyeuvd errors."""

    url: str | None = None
    """The URL that was being fetched, if the error came from a request."""

    def __str__(self) -> str:
        message = super().__str__()
        return f"{message} ({self.url})" if self.url else message


class TransportError(EUVDError):
    """No usable response arrived: network failure, timeout or a cut-off download."""


class APIError(EUVDError):
    """The API answered with an error status."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"{status_code}: {message}")
        self.status_code = status_code
        self.message = message

    def __reduce__(self) -> tuple[Any, ...]:
        # Python rebuilds an exception from its constructor arguments when it is
        # pickled or copied, as happens when it leaves a worker process.
        return type(self), (self.status_code, self.message), {"url": self.url}


class NotFoundError(APIError):
    """The API answered 404: no record matches the ID, or the path does not exist."""
