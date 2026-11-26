from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..parsing import parse_datetime, parse_lines, parse_number, parse_text, parse_vendor_names
from .product import Product
from .record import Record


@dataclass(frozen=True, kw_only=True, repr=False)
class SourceRecord(Record):
    """A record from another database, such as CVE or GHSA, linked to an EUVD entry."""

    status: str | None
    """Status in the source database, such as ``PUBLISHED``."""
    base_score_version: str | None
    """CVSS version of the score, such as ``3.1``."""
    base_score_vector: str | None
    """CVSS vector string."""
    epss: float | None
    """EPSS score as a percentage from 0 to 100.

    EPSS is usually published as 0 to 1, so divide by 100 to compare.
    """
    assigner: str | None
    """Name of the assigner, such as ``mitre``."""
    exploited_since: datetime | None
    """Since when the record is marked as exploited, or ``None``."""
    processed: datetime | None
    """When EUVD last processed the record."""
    euvd_ids: tuple[str, ...]
    """IDs of the EUVD entries the record is linked to."""
    products: tuple[Product, ...]
    """Affected products. There is one per affected version."""
    vendors: tuple[str, ...]
    """Vendor names."""

    @classmethod
    def parse_fields(cls, data: dict[str, Any]) -> dict[str, Any]:
        return {
            **super().parse_fields(data),
            "status": parse_text(data.get("status")),
            "base_score_version": parse_text(data.get("baseScoreVersion")),
            "base_score_vector": parse_text(data.get("baseScoreVector")),
            "epss": parse_number(data.get("epss")),
            "assigner": parse_text(data.get("assigner")),
            "exploited_since": parse_datetime(data.get("exploitedSince")),
            "processed": parse_datetime(data.get("dataProcessed")),
            "euvd_ids": parse_lines(data.get("enisa_id")),
            "products": tuple(Product.from_list(data.get("vulnerabilityProduct"))),
            "vendors": parse_vendor_names(data.get("vulnerabilityVendor")),
        }
