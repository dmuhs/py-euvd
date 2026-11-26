from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from ..parsing import parse_datetime, parse_lines, parse_score, parse_text
from ..utils import Severity, severity_rating
from .model import Model


@dataclass(frozen=True, kw_only=True, repr=False)
class Record(Model):
    """Fields shared by vulnerabilities, source records and advisories."""

    repr_fields: ClassVar[tuple[str, ...]] = ("id", "base_score")

    id: str
    """ID of the record. For an entry this is the EUVD ID."""
    description: str
    """Description text."""
    published: datetime | None
    """When the record was published, in UTC."""
    updated: datetime | None
    """When the record was last updated, in UTC."""
    base_score: float | None
    """CVSS base score, or ``None`` if there is none."""
    aliases: tuple[str, ...]
    """Other IDs for the same issue, such as CVE and GHSA IDs."""
    references: tuple[str, ...]
    """Links to more information."""

    @property
    def severity(self) -> Severity | None:
        """CVSS severity rating of the base score, or ``None`` without a score.

        One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"`` and ``"none"``.
        """
        # Advisories carry no CVSS version, so they are rated on the CVSS 3 and 4 scale.
        version = getattr(self, "base_score_version", None)
        return severity_rating(self.base_score, version)

    @classmethod
    def parse_fields(cls, data: dict[str, Any]) -> dict[str, Any]:
        return {
            **super().parse_fields(data),
            "id": parse_text(data.get("id")) or "",
            "description": parse_text(data.get("description")) or "",
            "published": parse_datetime(data.get("datePublished")),
            "updated": parse_datetime(data.get("dateUpdated")),
            "base_score": parse_score(data),
            "aliases": parse_lines(data.get("aliases")),
            "references": parse_lines(data.get("references")),
        }
