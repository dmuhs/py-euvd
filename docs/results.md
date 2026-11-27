---
title: EUVD results as typed Python objects
description: What py-euvd returns for EUVD entries, advisories and KEV entries, and how to print, export and save them.
---

# Results

Calls return typed objects. The [results reference](reference/results.md) lists every field.

| Call | Returns |
| --- | --- |
| `search`, `iter_search`, `latest` and its variants | `Vulnerability` |
| `get_vulnerability` | `VulnerabilityDetail`: a `Vulnerability` plus `source_records` and `advisories` |
| `get_advisory` | `AdvisoryDetail`: an `Advisory` plus `vulnerabilities` and `source_records` |
| `kev` | `KevEntry` |

A source record is a CVE, GHSA or similar record that an entry is linked to.

## How to read the fields

- **Timestamps are in UTC.**
- **`epss` runs from 0 to 100.** EPSS is usually published as 0 to 1, so divide by 100 to compare.
- **`base_score` and `severity` are `None`** when there is no CVSS score.
- **`severity` follows the CVSS version.** It is `"critical"`, `"high"`, `"medium"`, `"low"` or `"none"`. CVSS 2 has no "critical", so a 10.0 there is "high".
- **`products` has one item per affected version.** An entry can list the same product hundreds of times.
- **`cve_id` is the first CVE ID among the aliases**, or `None`.
- **`url` is the address of the page on the EUVD website.**

## Print a result

Printing a result shows a short summary:

```python
print(vuln)   # VulnerabilityDetail(id='EUVD-2024-31989', cve_id='CVE-2024-3400', base_score=10.0)
```

## Export results to JSON

`to_dict()` turns any result into plain data, ready for JSON or a database. Dates become ISO 8601 strings.

```python
import json

json.dumps(vuln.to_dict())
```

## Save and reload results

Every result keeps the original JSON in `raw`. To save a result and load it again later, store `raw` and pass it to `from_dict`:

```python
from pyeuvd import VulnerabilityDetail

saved = json.dumps(vuln.raw)
again = VulnerabilityDetail.from_dict(json.loads(saved))
```

`from_dict` reads the API's format. It cannot read the output of `to_dict()`.

## Search result pages

A page from `search` works like a list:

```python
page = euvd.search(vendor="Cisco")

len(page)       # entries on this page
page[0]         # the first entry
page.total      # matches across all pages
page.has_next   # whether another page follows
```
