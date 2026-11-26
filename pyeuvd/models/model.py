from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, ClassVar, Self

from ..parsing import expect_dict, parse_dicts
from ..utils import to_plain


@dataclass(frozen=True, kw_only=True)
class Model:
    """Base class for objects built from the API's JSON.

    To add your own fields, subclass a model and extend ``parse_fields``:

    ```python
    @dataclass(frozen=True, kw_only=True)
    class MyVulnerability(Vulnerability):
        team: str

        @classmethod
        def parse_fields(cls, data):
            fields = super().parse_fields(data)
            fields["team"] = "network" if "Cisco" in fields["vendors"] else "other"
            return fields

    mine = MyVulnerability.from_dict(vulnerability.raw)
    ```
    """

    repr_fields: ClassVar[tuple[str, ...]] = ()
    """Names of the fields and properties shown by ``repr()``."""

    raw: dict[str, Any] = field(repr=False, compare=False)
    """The original JSON, including fields this library does not read."""

    def __repr__(self) -> str:
        shown = ", ".join(f"{name}={getattr(self, name)!r}" for name in self.repr_fields)
        return f"{type(self).__name__}({shown})"

    def to_dict(self) -> dict[str, Any]:
        """Return the parsed values as a dict that ``json.dumps`` accepts.

        Dates become ISO 8601 strings. Properties such as ``cve_id`` are
        included. ``raw`` is left out.

        ``from_dict`` cannot read this dict. To save a result and load it
        again later, store ``raw`` and pass that to ``from_dict``.
        """
        names = [f.name for f in dataclasses.fields(self) if f.name != "raw"]
        for cls in reversed(type(self).__mro__):
            names += [
                name
                for name, attribute in vars(cls).items()
                if isinstance(attribute, property) and not name.startswith("_")
            ]
        return {name: to_plain(getattr(self, name)) for name in names}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Build an instance from one JSON object in the API's format, such as ``raw``."""
        data = expect_dict(data)
        return cls(raw=data, **cls.parse_fields(data))

    @classmethod
    def from_list(cls, items: Any) -> list[Self]:
        """Build instances from a JSON list. Entries that are not objects are skipped."""
        return [cls.from_dict(item) for item in parse_dicts(items)]

    @classmethod
    def parse_fields(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Read this class's fields from the JSON and return them as constructor arguments."""
        return {}
