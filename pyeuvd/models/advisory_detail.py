from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..parsing import parse_links
from .advisory import Advisory
from .source_record import SourceRecord
from .vulnerability import Vulnerability


@dataclass(frozen=True, kw_only=True, repr=False)
class AdvisoryDetail(Advisory):
    """An advisory fetched by ID. Adds the linked EUVD entries and source records."""

    vulnerabilities: tuple[Vulnerability, ...]
    """EUVD entries the advisory covers."""
    source_records: tuple[SourceRecord, ...]
    """Records from other databases the advisory covers."""

    @classmethod
    def parse_fields(cls, data: dict[str, Any]) -> dict[str, Any]:
        vulnerabilities = parse_links(data.get("enisaIdAdvisories"), "enisaId")
        records = parse_links(data.get("vulnerabilityAdvisory"), "vulnerability")
        return {
            **super().parse_fields(data),
            "vulnerabilities": tuple(Vulnerability.from_list(vulnerabilities)),
            "source_records": tuple(SourceRecord.from_list(records)),
        }
