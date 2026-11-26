from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, ClassVar

from ..constants import SITE_URL
from ..parsing import parse_text
from .product import Product
from .record import Record


@dataclass(frozen=True, kw_only=True, repr=False)
class Advisory(Record):
    """A security advisory."""

    repr_fields: ClassVar[tuple[str, ...]] = ("id", "source")

    summary: str | None
    """Short summary, if the advisory has one."""
    source: str | None
    """Name of the feed the advisory came from, such as ``csaf_cisco``."""
    products: tuple[Product, ...]
    """Products the advisory covers. They carry no version."""

    @property
    def url(self) -> str:
        """Address of the advisory's page on the EUVD website."""
        return f"{SITE_URL}/advisory/{urllib.parse.quote(self.id, safe='')}"

    @classmethod
    def parse_fields(cls, data: dict[str, Any]) -> dict[str, Any]:
        source = data.get("source")
        return {
            **super().parse_fields(data),
            "summary": parse_text(data.get("summary")),
            "source": parse_text(source.get("name")) if isinstance(source, dict) else None,
            "products": tuple(Product.from_list(data.get("advisoryProduct"))),
        }
