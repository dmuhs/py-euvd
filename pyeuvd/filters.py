from __future__ import annotations

from collections.abc import Iterable
from datetime import date
from typing import TypedDict


class SearchFilters(TypedDict, total=False):
    """Filters accepted by ``search`` and ``iter_search``. All are optional."""

    text: str
    """Keywords. Looks in the description, IDs, aliases, product and vendor names."""
    product: str
    """Words from the product name. Each must start a word in the name, in any order.

    This is not an exact match: ``Win`` finds "Windows", and a two-letter word
    next to others is ignored, so ``PAN-OS`` matches like ``PAN``.
    """
    vendor: str
    """Words from the vendor name. Matched like ``product``."""
    advisory: str
    """An advisory ID."""
    assigner: str | Iterable[str]
    """One assigner, or several to match any of them."""
    exploited: bool
    """``True`` returns only exploited entries. ``False`` does not filter."""
    from_score: float
    """Lowest CVSS base score, 0 to 10."""
    to_score: float
    """Highest CVSS base score, 0 to 10."""
    from_epss: float
    """Lowest EPSS score as a percentage, 0 to 100."""
    to_epss: float
    """Highest EPSS score as a percentage, 0 to 100."""
    from_date: date | str
    """Earliest publication date."""
    to_date: date | str
    """Latest publication date."""
    from_updated_date: date | str
    """Earliest date of the last update."""
    to_updated_date: date | str
    """Latest date of the last update."""
    from_kev_date: date | str
    """Earliest date the entry was added to a Known Exploited Vulnerabilities list."""
    to_kev_date: date | str
    """Latest date the entry was added to a Known Exploited Vulnerabilities list."""


# Maps each filter to the query parameter the API expects.
FILTER_PARAMS = {
    "text": "text",
    "product": "product",
    "vendor": "vendor",
    "advisory": "advisory",
    "assigner": "assigner",
    "exploited": "exploited",
    "from_score": "fromScore",
    "to_score": "toScore",
    "from_epss": "fromEpss",
    "to_epss": "toEpss",
    "from_date": "fromDate",
    "to_date": "toDate",
    "from_updated_date": "fromUpdatedDate",
    "to_updated_date": "toUpdatedDate",
    "from_kev_date": "fromKEVDate",
    "to_kev_date": "toKEVDate",
}
