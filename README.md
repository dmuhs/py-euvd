# py-euvd

[![CI](https://github.com/dmuhs/py-euvd/actions/workflows/ci.yml/badge.svg)](https://github.com/dmuhs/py-euvd/actions/workflows/ci.yml)

A Python client for the [EU Vulnerability Database](https://euvd.enisa.europa.eu) (EUVD), run by ENISA.

**Documentation: [py-euvd.spoons.fyi](https://py-euvd.spoons.fyi)**

- **No dependencies.** Uses only the Python standard library.
- **Complete.** Covers every endpoint of the [public API](https://euvd.enisa.europa.eu/apidoc).
- **Sync and async** clients with the same methods.
- **Typed results.** Dates and lists are parsed, not left as strings.
- **Extensible.** Swap the HTTP layer to add retries, caching or another HTTP library.
- **Tested.** 100% test coverage, and a weekly check against the real API.
- **Open source.** Apache 2.0 licensed.

The API is public. You do not need a key.

This project is unofficial and not affiliated with ENISA.

## Install

```
pip install py-euvd
```

Requires Python 3.11 or newer.

## Quick start

```python
from pyeuvd import EUVD

euvd = EUVD()

# One entry, by EUVD ID or CVE ID
vuln = euvd.get_vulnerability("CVE-2024-3400")
print(vuln.id, vuln.severity, vuln.exploited)   # EUVD-2024-31989 critical True

# Search
for vuln in euvd.iter_search(vendor="Cisco", from_score=9, limit=20):
    print(vuln.id, vuln.cve_id, vuln.base_score)
```

The [documentation](https://py-euvd.spoons.fyi) covers searching, results, async use, errors and customizing.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/dmuhs/py-euvd).

```
uv sync
uv run pytest --cov      # tests; coverage must stay at 100%
uv run pytest -m live    # checks against the real API
uv run ruff check .
uv run mypy
```

To work on the documentation in `docs/`:

```
uv run --only-group docs zensical serve    # preview at http://localhost:8000
```

## License

[Apache License 2.0](https://github.com/dmuhs/py-euvd/blob/main/LICENSE)
