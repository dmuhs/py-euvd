from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime

import pytest

from pyeuvd import (
    Advisory,
    AdvisoryDetail,
    EUVDError,
    KevEntry,
    Page,
    Product,
    SourceRecord,
    Vulnerability,
    VulnerabilityDetail,
)

from .fakes import load_json


def test_vulnerability_detail():
    data = load_json("vulnerability.json")
    vuln = VulnerabilityDetail.from_dict(data)

    assert vuln.id == "EUVD-2024-31989"
    assert vuln.cve_id == "CVE-2024-3400"
    assert vuln.published == datetime(2024, 4, 12, 7, 20, tzinfo=UTC)
    assert vuln.base_score == 10.0
    assert vuln.base_score_version == "3.1"
    assert vuln.epss == 93.03
    assert vuln.assigner == "palo_alto"
    assert vuln.exploited
    assert vuln.exploited_since == datetime(2024, 4, 12, tzinfo=UTC)
    assert vuln.aliases == ("CVE-2024-3400", "GHSA-v475-xhc9-wfxg")
    assert all(ref.startswith("https://") for ref in vuln.references)
    assert vuln.vendors == ("Palo Alto Networks",)
    assert vuln.raw is data

    product = vuln.products[0]
    assert (product.name, product.vendor) == ("PAN-OS", "Palo Alto Networks")
    assert product.version

    cve, ghsa = vuln.source_records
    assert isinstance(cve, SourceRecord)
    assert cve.id == "CVE-2024-3400"
    assert cve.status == "PUBLISHED"
    assert cve.euvd_ids == ("EUVD-2024-31989",)
    assert cve.processed is not None and cve.processed.tzinfo is UTC
    assert cve.products and cve.vendors
    assert ghsa.id == "GHSA-v475-xhc9-wfxg"
    assert ghsa.base_score is None  # sent as 0.0 with no CVSS version

    assert [a.id for a in vuln.advisories][:2] == ["WID-SEC-W-2024-0878", "ICSA-24-116-03"]
    assert vuln.advisories[0].source == "csaf_certbund"
    assert type(vuln.advisories[0]) is Advisory


def test_vulnerability_from_a_list_result():
    vuln = Vulnerability.from_dict(load_json("latest.json")[0])

    assert vuln.id.startswith("EUVD-")
    assert not vuln.exploited
    assert not hasattr(vuln, "source_records")


def test_a_detail_is_also_a_vulnerability():
    assert isinstance(VulnerabilityDetail.from_dict({"id": "x"}), Vulnerability)
    assert isinstance(AdvisoryDetail.from_dict({"id": "x"}), Advisory)


def test_missing_fields_become_empty():
    vuln = VulnerabilityDetail.from_dict({"id": "EUVD-2025-1"})

    assert vuln.id == "EUVD-2025-1"
    assert vuln.description == ""
    assert vuln.published is None
    assert vuln.base_score is None
    assert vuln.cve_id is None
    assert vuln.aliases == ()
    assert vuln.products == ()
    assert vuln.source_records == ()
    assert vuln.advisories == ()


def test_malformed_fields_do_not_break_a_record():
    vuln = VulnerabilityDetail.from_dict(
        {
            "id": 12,
            "baseScore": "high",
            "epss": True,
            "aliases": ["CVE-2025-1"],
            "enisaIdProduct": [{"id": "a", "product": "PAN-OS"}, "junk"],
            "enisaIdVendor": [{"id": "b", "vendor": {"name": ""}}, {"id": "c"}],
            "enisaIdVulnerability": "none",
        }
    )

    assert vuln.id == ""
    assert vuln.base_score is None
    assert vuln.epss is None
    assert vuln.aliases == ()
    assert [(p.name, p.vendor, p.version) for p in vuln.products] == [("", None, None)]
    assert vuln.vendors == ()
    assert vuln.source_records == ()


def test_from_dict_rejects_non_objects():
    with pytest.raises(EUVDError, match="expected a JSON object"):
        Vulnerability.from_dict(["not", "an", "object"])


def test_from_list_skips_non_objects():
    vulns = Vulnerability.from_list([{"id": "a"}, "junk", {"id": "b"}])

    assert [v.id for v in vulns] == ["a", "b"]
    assert Vulnerability.from_list(None) == []


def test_advisory_detail():
    advisory = AdvisoryDetail.from_dict(load_json("advisory.json"))

    assert advisory.id == "cisco-sa-ata19x-multi-RDTEqRsy"
    assert advisory.source == "csaf_cisco"
    assert advisory.summary
    assert advisory.base_score is None
    assert "CVE-2024-20420" in advisory.aliases
    assert advisory.products[0].vendor == "Cisco"
    assert advisory.products[0].version is None
    assert advisory.vulnerabilities[0].id == "EUVD-2024-18178"
    assert type(advisory.vulnerabilities[0]) is Vulnerability
    assert advisory.source_records[0].id == "CVE-2024-20420"


def test_advisory_without_source():
    assert Advisory.from_dict({"id": "x", "source": "cisco"}).source is None


def test_kev_entry():
    entry = KevEntry.from_dict(load_json("kev.json")[0])

    assert entry.cve_id == "CVE-2021-22555"
    assert entry.euvd_id == "EUVD-2021-9696"
    assert entry.date_added == date(2025, 10, 6)
    assert entry.sources == ("cisa_kev",)


def test_kev_entry_with_malformed_fields():
    entry = KevEntry.from_dict({"cveId": "CVE-1", "dateAdded": "soon", "sources": "cisa_kev"})

    assert entry.euvd_id is None
    assert entry.date_added is None
    assert entry.sources == ()


def test_models_compare_by_value_and_hash():
    data = load_json("vulnerability.json")

    assert VulnerabilityDetail.from_dict(data) == VulnerabilityDetail.from_dict(dict(data))
    assert len({VulnerabilityDetail.from_dict(data), VulnerabilityDetail.from_dict(data)}) == 1


def test_repr_is_short():
    vuln = VulnerabilityDetail.from_dict(load_json("vulnerability.json"))
    advisory = AdvisoryDetail.from_dict(load_json("advisory.json"))
    product = Product.from_dict({"product": {"name": "IOS"}, "product_version": "15"})
    page = Page.from_dict(load_json("search.json"), page=0, size=2)

    assert repr(vuln) == (
        "VulnerabilityDetail(id='EUVD-2024-31989', cve_id='CVE-2024-3400', base_score=10.0)"
    )
    assert repr(vuln.source_records[0]) == "SourceRecord(id='CVE-2024-3400', base_score=10.0)"
    assert repr(advisory) == (
        "AdvisoryDetail(id='cisco-sa-ata19x-multi-RDTEqRsy', source='csaf_cisco')"
    )
    assert repr(product) == "Product(name='IOS', vendor=None, version='15')"
    assert repr(KevEntry.from_dict(load_json("kev.json")[0])) == (
        "KevEntry(cve_id='CVE-2021-22555', euvd_id='EUVD-2021-9696', "
        "date_added=datetime.date(2025, 10, 6))"
    )
    assert repr(page) == f"Page(total={page.total}, page=0, size=2)"


def test_severity():
    def rate(**data):
        return Vulnerability.from_dict({"id": "x", **data}).severity

    assert rate(baseScore=9.8, baseScoreVersion="3.1") == "critical"
    assert rate(baseScore=9.8, baseScoreVersion="2.0") == "high"
    assert rate(baseScore=5.0, baseScoreVersion="4.0") == "medium"
    assert rate() is None
    # Advisories have no CVSS version and are rated on the current scale.
    assert Advisory.from_dict({"id": "x", "baseScore": 9.1}).severity == "critical"


def test_url():
    vuln = Vulnerability.from_dict({"id": "EUVD-2024-31989"})
    advisory = Advisory.from_dict({"id": "oxas-adv-2024-0002"})
    odd = Advisory.from_dict({"id": "a b/c?d"})

    assert vuln.url == "https://euvd.enisa.europa.eu/vulnerability/EUVD-2024-31989"
    assert advisory.url == "https://euvd.enisa.europa.eu/advisory/oxas-adv-2024-0002"
    assert odd.url == "https://euvd.enisa.europa.eu/advisory/a%20b%2Fc%3Fd"


def test_to_dict_is_ready_for_json():
    vuln = VulnerabilityDetail.from_dict(load_json("vulnerability.json"))

    data = vuln.to_dict()

    assert json.loads(json.dumps(data)) == data
    assert "raw" not in data
    assert all(
        "raw" not in item
        for key in ("products", "source_records", "advisories")
        for item in data[key]
    )
    assert data["id"] == "EUVD-2024-31989"
    assert data["published"] == "2024-04-12T07:20:00+00:00"
    assert data["aliases"] == ["CVE-2024-3400", "GHSA-v475-xhc9-wfxg"]
    assert data["products"][0]["name"] == "PAN-OS"
    assert data["source_records"][0]["id"] == "CVE-2024-3400"
    assert data["advisories"][0]["url"].endswith("/advisory/WID-SEC-W-2024-0878")
    # Properties are exported too.
    assert data["cve_id"] == "CVE-2024-3400"
    assert data["exploited"] is True
    assert data["severity"] == "critical"
    assert data["url"] == vuln.url


def test_to_dict_of_other_models():
    entry = KevEntry.from_dict(load_json("kev.json")[0])
    page = Page.from_dict(load_json("search.json"), page=0, size=2)

    assert entry.to_dict() == {
        "cve_id": "CVE-2021-22555",
        "euvd_id": "EUVD-2021-9696",
        "date_added": "2025-10-06",
        "sources": ["cisa_kev"],
    }
    assert json.loads(json.dumps(page.to_dict())) == page.to_dict()
    assert [item["id"] for item in page.to_dict()["items"]] == [v.id for v in page]
    assert {key: page.to_dict()[key] for key in ("total", "page", "size")} == {
        "total": page.total,
        "page": 0,
        "size": 2,
    }


def test_models_can_be_extended():
    @dataclass(frozen=True, kw_only=True)
    class MyVulnerability(Vulnerability):
        severe: bool

        @classmethod
        def parse_fields(cls, data):
            fields = super().parse_fields(data)
            fields["severe"] = (fields["base_score"] or 0) >= 9
            return fields

    mine = MyVulnerability.from_dict({"id": "x", "baseScore": 9.8, "baseScoreVersion": "3.1"})

    assert mine.severe
    assert mine.id == "x"
    assert [v.severe for v in MyVulnerability.from_list([{"id": "y"}])] == [False]
    assert mine.to_dict()["severe"] is True


def test_page_from_dict():
    page = Page.from_dict(load_json("search.json"), page=0, size=2)

    assert page.total > 2
    assert len(page) == 2
    assert [v.id for v in page] == [v["id"] for v in load_json("search.json")["items"]]
    assert page.has_next


def test_page_from_dict_with_odd_data():
    assert Page.from_dict({"total": "many"}, page=0, size=10) == Page(
        items=(), total=0, page=0, size=10
    )
    with pytest.raises(EUVDError):
        Page.from_dict([], page=0, size=10)


def test_page_has_next():
    item = Vulnerability.from_dict({"id": "x"})

    assert Page(items=(item,), total=25, page=1, size=10).has_next
    assert not Page(items=(item,), total=25, page=2, size=10).has_next
    assert not Page(items=(), total=25, page=0, size=10).has_next


def test_to_dict_cannot_be_loaded_but_raw_can():
    vuln = VulnerabilityDetail.from_dict(load_json("vulnerability.json"))

    from_raw = VulnerabilityDetail.from_dict(json.loads(json.dumps(vuln.raw)))
    from_export = VulnerabilityDetail.from_dict(vuln.to_dict())

    assert from_raw == vuln
    assert from_export != vuln  # the export uses this library's names, not the API's


def test_page_supports_indexing():
    page = Page.from_dict(load_json("search.json"), page=0, size=2)

    assert page[0] is page.items[0]
    assert page[-1] is page.items[-1]
    assert page[:1] == page.items[:1]
    with pytest.raises(IndexError):
        page[5]
