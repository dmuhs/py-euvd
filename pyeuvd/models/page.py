from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Self, overload

from ..parsing import expect_dict, parse_number
from .vulnerability import Vulnerability


@dataclass(frozen=True, kw_only=True)
class Page:
    """One page of search results."""

    items: tuple[Vulnerability, ...] = field(repr=False)
    """The entries on this page."""
    total: int
    """Number of results across all pages."""
    page: int
    """Page number, starting at 0."""
    size: int
    """Page size that was asked for."""

    @property
    def has_next(self) -> bool:
        """Whether there is another page after this one."""
        return bool(self.items) and (self.page + 1) * self.size < self.total

    def __iter__(self) -> Iterator[Vulnerability]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    @overload
    def __getitem__(self, index: int) -> Vulnerability: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[Vulnerability, ...]: ...

    def __getitem__(self, index: int | slice) -> Vulnerability | tuple[Vulnerability, ...]:
        return self.items[index]

    def to_dict(self) -> dict[str, Any]:
        """Return the page as a dict that ``json.dumps`` accepts."""
        return {
            "items": [item.to_dict() for item in self.items],
            "total": self.total,
            "page": self.page,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, page: int, size: int) -> Self:
        """Build a page from the JSON of the search endpoint."""
        data = expect_dict(data)
        return cls(
            items=tuple(Vulnerability.from_list(data.get("items"))),
            total=int(parse_number(data.get("total")) or 0),
            page=page,
            size=size,
        )
