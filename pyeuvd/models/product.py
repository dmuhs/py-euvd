from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from ..parsing import parse_text
from .model import Model


@dataclass(frozen=True, kw_only=True, repr=False)
class Product(Model):
    """An affected product."""

    repr_fields: ClassVar[tuple[str, ...]] = ("name", "vendor", "version")

    name: str
    """Name of the product."""
    vendor: str | None = None
    """Name of the vendor."""
    version: str | None = None
    """Affected version, in the wording of the source."""

    @classmethod
    def parse_fields(cls, data: dict[str, Any]) -> dict[str, Any]:
        product = data.get("product")
        if not isinstance(product, dict):
            product = {}
        vendor = product.get("vendor")
        return {
            **super().parse_fields(data),
            "name": parse_text(product.get("name")) or "",
            "vendor": parse_text(vendor.get("name")) if isinstance(vendor, dict) else None,
            "version": parse_text(data.get("product_version")),
        }
