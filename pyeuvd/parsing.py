"""Functions that turn raw API values into Python values.

A value the ``parse_*`` functions cannot read becomes ``None`` or an empty
result, so one bad field does not break a whole record. The ``expect_*``
functions raise when a response has the wrong shape.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from typing import Any

from .errors import EUVDError

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
    )
}

# The API sends timestamps like "Apr 12, 2024, 7:20:00 AM". They are in UTC.
_TIMESTAMP = re.compile(
    r"([A-Za-z]{3})[a-z]*\.? (\d{1,2}), (\d{4}),? (\d{1,2}):(\d{2}):(\d{2}) ([AP]M)",
    re.IGNORECASE,
)


def parse_datetime(value: Any) -> datetime | None:
    """Parse an API timestamp. A timestamp without a time zone is read as UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = " ".join(value.split())
    match = _TIMESTAMP.fullmatch(text)
    if match:
        month_name, day, year, hour, minute, second, meridiem = match.groups()
        month = _MONTHS.get(month_name.lower())
        if month is None:
            return None
        hour_24 = int(hour) % 12 + (12 if meridiem.upper() == "PM" else 0)
        try:
            return datetime(
                int(year), month, int(day), hour_24, int(minute), int(second), tzinfo=UTC
            )
        except ValueError:
            return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_date(value: Any) -> date | None:
    """Parse a ``YYYY-MM-DD`` date."""
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def parse_text(value: Any) -> str | None:
    """Return a non-empty string, or ``None``."""
    return value if isinstance(value, str) and value else None


def parse_number(value: Any) -> float | None:
    """Return a number as a float, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def parse_score(data: dict[str, Any]) -> float | None:
    """Read the CVSS base score of a record.

    The API sends 0 with no CVSS version when a record has no score.
    """
    score = parse_number(data.get("baseScore"))
    if score is None or score < 0:
        return None
    if score == 0 and not data.get("baseScoreVersion"):
        return None
    return score


def parse_lines(value: Any) -> tuple[str, ...]:
    """Split a newline-separated string into its non-empty entries."""
    if not isinstance(value, str):
        return ()
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def parse_strings(value: Any) -> tuple[str, ...]:
    """Return the strings in a list."""
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def parse_dicts(value: Any) -> list[dict[str, Any]]:
    """Return the JSON objects in a list."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def parse_links(value: Any, key: str) -> list[dict[str, Any]]:
    """Unwrap a list of ``{"id": ..., key: {...}}`` link objects into the inner objects."""
    return [item[key] for item in parse_dicts(value) if isinstance(item.get(key), dict)]


def parse_vendor_names(value: Any) -> tuple[str, ...]:
    """Read vendor names from a list of vendor links."""
    names = (parse_text(vendor.get("name")) for vendor in parse_links(value, "vendor"))
    return tuple(name for name in names if name)


def parse_mapping_line(line: str) -> tuple[str, str] | None:
    """Parse one line of the CVE mapping CSV. Returns ``None`` for the header and bad lines."""
    euvd_id, _, cve_id = line.strip().partition(",")
    if not cve_id or euvd_id == "euvd_id":
        return None
    return euvd_id, cve_id


def expect_dict(data: Any) -> dict[str, Any]:
    """Return ``data`` if it is a JSON object, otherwise raise ``EUVDError``."""
    if not isinstance(data, dict):
        raise EUVDError(f"expected a JSON object from the API, got {type(data).__name__}")
    return data


def expect_list(data: Any) -> list[Any]:
    """Return ``data`` if it is a JSON list, otherwise raise ``EUVDError``."""
    if not isinstance(data, list):
        raise EUVDError(f"expected a JSON list from the API, got {type(data).__name__}")
    return data
