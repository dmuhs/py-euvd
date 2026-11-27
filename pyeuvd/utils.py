"""Helpers for building requests."""

from __future__ import annotations

import ssl
import urllib.parse
from collections.abc import Mapping
from datetime import date, datetime
from typing import Any, Literal

from .constants import MAX_PAGE_SIZE
from .filters import FILTER_PARAMS

Severity = Literal["none", "low", "medium", "high", "critical"]


def format_param(value: Any) -> str:
    """Format a filter value the way the API expects it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, (str, int, float)):
        return str(value)
    return ",".join(str(item) for item in value)


def build_search_params(page: int, size: int, filters: Mapping[str, Any]) -> dict[str, str]:
    """Turn paging options and search filters into API query parameters."""
    if page < 0:
        raise ValueError("page must be 0 or greater")
    if not 1 <= size <= MAX_PAGE_SIZE:
        raise ValueError(f"size must be between 1 and {MAX_PAGE_SIZE}")
    params = {"page": str(page), "size": str(size)}
    for name, value in filters.items():
        if name not in FILTER_PARAMS:
            raise TypeError(f"unknown search filter: {name!r}")
        if value is not None:
            params[FILTER_PARAMS[name]] = format_param(value)
    return params


def build_url(base_url: str, path: str, params: Mapping[str, str] | None = None) -> str:
    """Join the base URL, a path and optional query parameters."""
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return url


def severity_rating(score: float | None, version: str | None = None) -> Severity | None:
    """Return the CVSS severity rating of a base score, or ``None`` without a score.

    CVSS 2 only knows low, medium and high.
    """
    if score is None:
        return None
    if (version or "").startswith("2"):
        return "high" if score >= 7 else "medium" if score >= 4 else "low"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "none"


def to_plain(value: Any) -> Any:
    """Convert a model field into a value that ``json.dumps`` accepts."""
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, (tuple, list)):
        return [to_plain(item) for item in value]
    return value


def is_certificate_error(error: BaseException | None) -> bool:
    """Whether a network error is a failed TLS certificate check. Retrying cannot fix that."""
    reason = getattr(error, "reason", error)
    return isinstance(reason, ssl.SSLCertVerificationError)


def describe_error(error: BaseException) -> str:
    """Return a short reason for a network error."""
    reason = getattr(error, "reason", None)
    return printable(str(reason or error)) or type(error).__name__


def printable(text: str) -> str:
    """Replace control characters with spaces, so text from a server is safe to log."""
    return "".join(char if char.isprintable() else " " for char in text)
