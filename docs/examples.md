# Examples

Each example assumes a client:

```python
from pyeuvd import EUVD

euvd = EUVD()
```

## Details of every exploited entry

`kev()` returns only IDs and dates. A search returns the same entries in full:

```python
for vuln in euvd.iter_search(exploited=True):
    print(vuln.id, vuln.severity, vuln.exploited_since)
```

## What changed since yesterday

```python
from datetime import date, timedelta

yesterday = date.today() - timedelta(days=1)
for vuln in euvd.iter_search(from_updated_date=yesterday):
    print(vuln.id, vuln.updated)
```

## Critical entries for one vendor

```python
for vuln in euvd.iter_search(vendor="Cisco", from_score=9):
    print(vuln.id, vuln.base_score, vuln.url)
```

## EUVD IDs for many CVEs

One download answers any number of lookups:

```python
euvd_ids = {cve_id: euvd_id for euvd_id, cve_id in euvd.cve_mapping()}

print(euvd_ids["CVE-2024-3400"])   # EUVD-2024-31989
```

## Many entries at once

See [Async](async.md#many-requests-at-once).

## Export a search to JSON

```python
import json

rows = [vuln.to_dict() for vuln in euvd.iter_search(vendor="Cisco", limit=200)]

with open("cisco.json", "w") as file:
    json.dump(rows, file)
```
