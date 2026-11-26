from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, ClassVar

from ..parsing import parse_date, parse_strings, parse_text
from .model import Model


@dataclass(frozen=True, kw_only=True, repr=False)
class KevEntry(Model):
    """One entry of the Known Exploited Vulnerabilities list."""

    repr_fields: ClassVar[tuple[str, ...]] = ("cve_id", "euvd_id", "date_added")

    cve_id: str
    """CVE ID."""
    euvd_id: str | None
    """ID of the matching EUVD entry."""
    date_added: date | None
    """Earliest date the CVE was added to a KEV list."""
    sources: tuple[str, ...]
    """KEV lists that include the CVE, such as ``cisa_kev``."""

    @classmethod
    def parse_fields(cls, data: dict[str, Any]) -> dict[str, Any]:
        return {
            **super().parse_fields(data),
            "cve_id": parse_text(data.get("cveId")) or "",
            "euvd_id": parse_text(data.get("euvdId")),
            "date_added": parse_date(data.get("dateAdded")),
            "sources": parse_strings(data.get("sources")),
        }
