"""Tests that call the real EUVD API, to catch changes on the server side.

Skipped by default. Run them with: pytest -m live
"""

from __future__ import annotations

import itertools

import pytest

from pyeuvd import EUVD, NotFoundError

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def euvd():
    return EUVD()


@pytest.mark.parametrize("method", ["latest", "latest_exploited", "latest_critical"])
def test_latest_lists(euvd, method):
    items = getattr(euvd, method)()

    assert items
    for vuln in items:
        assert vuln.id.startswith("EUVD-")
        assert vuln.published is not None
        assert vuln.updated is not None


def test_search_and_paging(euvd):
    first = euvd.search(vendor="Cisco", from_score=9, size=5)
    second = euvd.search(vendor="Cisco", from_score=9, size=5, page=1)

    assert first.total > 10
    assert len(first) == len(second) == 5
    assert {v.id for v in first}.isdisjoint(v.id for v in second)
    for vuln in first:
        assert vuln.base_score is not None and vuln.base_score >= 9
        assert any("cisco" in vendor.lower() for vendor in vuln.vendors)


def test_get_vulnerability(euvd):
    vuln = euvd.get_vulnerability("CVE-2024-3400")

    assert vuln.id == "EUVD-2024-31989"
    assert vuln.cve_id == "CVE-2024-3400"
    assert vuln.published is not None and vuln.published.year == 2024
    assert vuln.exploited
    assert vuln.products and vuln.vendors and vuln.references
    assert vuln.source_records and vuln.advisories


def test_not_found(euvd):
    with pytest.raises(NotFoundError):
        euvd.get_vulnerability("EUVD-1999-0000")


def test_get_advisory(euvd):
    advisory = euvd.get_advisory("cisco-sa-ata19x-multi-RDTEqRsy")

    assert advisory.source == "csaf_cisco"
    assert advisory.published is not None
    assert advisory.vulnerabilities and advisory.source_records


def test_kev(euvd):
    entries = euvd.kev()

    assert len(entries) > 1000
    assert all(entry.cve_id.startswith("CVE-") for entry in entries)
    assert any(entry.date_added for entry in entries)


def test_cve_mapping(euvd):
    rows = list(itertools.islice(euvd.cve_mapping(), 100))

    assert len(rows) == 100
    assert all(e.startswith("EUVD-") and c.startswith("CVE-") for e, c in rows)
