---
title: Fetch EUVD vulnerabilities and advisories in Python
description: Look up EUVD entries by EUVD or CVE ID, fetch advisories, and download the KEV list and the CVE to EUVD mapping with py-euvd.
---

# Fetching data

All calls are methods of the client:

```python
from pyeuvd import EUVD

euvd = EUVD()
```

## Look up a vulnerability by EUVD or CVE ID

```python
vuln = euvd.get_vulnerability("EUVD-2024-31989")
vuln = euvd.get_vulnerability("CVE-2024-3400")
```

`get_vulnerability` takes an EUVD ID, or another ID the entry is known by, such as a CVE or GHSA ID. Case does not matter. It raises `NotFoundError` if nothing matches.

The result also holds the linked `source_records` and `advisories`. Lists and searches leave those out.

## Look up an advisory

```python
advisory = euvd.get_advisory("cisco-sa-ata19x-multi-RDTEqRsy")
```

The result also holds the `vulnerabilities` and `source_records` the advisory covers.

## Latest vulnerabilities

```python
euvd.latest()             # latest entries
euvd.latest_exploited()   # latest exploited entries
euvd.latest_critical()    # latest critical entries
```

Each returns at most 8 entries. "Latest" includes entries that were recently updated, not only new ones. Use [search](searching.md) for more.

## Known exploited vulnerabilities (KEV)

```python
for entry in euvd.kev():
    print(entry.cve_id, entry.euvd_id, entry.date_added)
```

`kev` downloads the full list. Each entry holds only IDs, a date and its sources. For scores and descriptions, [search for exploited entries](examples.md#details-of-every-exploited-entry).

## CVE to EUVD mapping

```python
for euvd_id, cve_id in euvd.cve_mapping():
    ...
```

`cve_mapping` yields one pair for every entry that is linked to a CVE. The download is large: several hundred thousand rows.

## Other API endpoints

```python
euvd.get_json("/some/path", {"key": "value"})
```

`get_json` calls any API path and returns the JSON. Use it for endpoints this library does not cover.
