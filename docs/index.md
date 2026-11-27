---
title: Python client for the EU Vulnerability Database (EUVD)
description: py-euvd is a dependency-free Python client for the ENISA EU Vulnerability Database (EUVD) API, with sync and async clients and typed results.
---

# py-euvd

A Python client for the [EU Vulnerability Database](https://euvd.enisa.europa.eu) (EUVD), run by ENISA.

Look up entries by EUVD or CVE ID, search by vendor, product, CVSS score, EPSS score or date, and download the Known Exploited Vulnerabilities (KEV) list and the CVE to EUVD mapping.

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
vuln = euvd.get_vulnerability("CVE-2024-3400")

print(vuln)              # VulnerabilityDetail(id='EUVD-2024-31989', cve_id='CVE-2024-3400', base_score=10.0)
print(vuln.severity)     # critical
print(vuln.published)    # 2024-04-12 07:20:00+00:00
print(vuln.exploited)    # True
print(vuln.products[0])  # Product(name='PAN-OS', vendor='Palo Alto Networks', version='...')
print(vuln.url)          # https://euvd.enisa.europa.eu/vulnerability/EUVD-2024-31989
```

## Where to go next

- [Fetching data](fetching.md): look up entries and advisories, and download the full lists.
- [Searching](searching.md): filter the database and page through the matches.
- [Results](results.md): what comes back, and how to export it.
- [Examples](examples.md): short answers to common tasks.
