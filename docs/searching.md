# Searching

```python
from datetime import date

page = euvd.search(vendor="Cisco", from_score=9, exploited=True, from_date=date(2024, 1, 1))

print(page.total)
for vuln in page:
    print(vuln.id, vuln.cve_id, vuln.base_score)
```

`search` returns one page. Pick the page with `page=`, starting at 0. Set its size with `size=`: 10 by default, 100 at most.

Results come with the newest update first.

## All results

To go through all results without handling pages yourself, use `iter_search`:

```python
for vuln in euvd.iter_search(text="keycloak", limit=500):
    print(vuln.id)
```

Set `limit` unless you want every result. A broad search can match hundreds of thousands of entries.

## Entries that change during a search

An entry that is updated while `iter_search` runs moves to the front of the results. The search then never reaches it, and returns another entry twice. Currently, the EUVD API has no facilities to fix this problem. For a short search this is rarely an issue. A search that runs for minutes, such as a copy of the whole database, will run into this problem. The solution is to keep the results by ID, then fetch what was updated since the day before you started:

```python
from datetime import date, timedelta

day_before = date.today() - timedelta(days=1)

entries = {vuln.id: vuln for vuln in euvd.iter_search()}
for vuln in euvd.iter_search(from_updated_date=day_before):
    entries[vuln.id] = vuln
```

Use the same filters in both searches.

## Only the number

```python
euvd.count(vendor="Cisco", from_score=9)
```

## Filters

All three calls take the same filters. Every filter is optional.

| Filter | Meaning |
| --- | --- |
| `text` | Keywords. Looks in the description, IDs, aliases, product and vendor names. |
| `product`, `vendor` | Words from the product or vendor name. Not an exact match, see below. |
| `advisory` | An advisory ID. |
| `assigner` | One assigner, or a list to match any of them. |
| `exploited` | `True` returns only exploited entries. `False` does not filter. |
| `from_score`, `to_score` | Range of the CVSS base score, 0 to 10. |
| `from_epss`, `to_epss` | Range of the EPSS score as a percentage, 0 to 100. |
| `from_date`, `to_date` | Range of the publication date. |
| `from_updated_date`, `to_updated_date` | Range of the last update date. |
| `from_kev_date`, `to_kev_date` | Range of the date added to a Known Exploited Vulnerabilities list. |

Dates can be `date` objects or `"YYYY-MM-DD"` strings. Both ends of a range are included.

## How product and vendor match

`product` and `vendor` match by words, so they can return more than you expect:

- Each word must start a word in the name. `Win` finds "Windows". Order and case do not matter.
- A hyphen separates words, and a two-letter word next to others is ignored. `PAN-OS` matches like `PAN`, which also finds "SEO Panel".

For an exact match, check `vuln.products` or `vuln.vendors` yourself:

```python
for vuln in euvd.iter_search(product="PAN-OS"):
    if any(product.name == "PAN-OS" for product in vuln.products):
        print(vuln.id)
```
