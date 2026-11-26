"""What the API returns, as typed objects."""

from .advisory import Advisory
from .advisory_detail import AdvisoryDetail
from .kev_entry import KevEntry
from .model import Model
from .page import Page
from .product import Product
from .record import Record
from .source_record import SourceRecord
from .vulnerability import Vulnerability
from .vulnerability_detail import VulnerabilityDetail

__all__ = [
    "Advisory",
    "AdvisoryDetail",
    "KevEntry",
    "Model",
    "Page",
    "Product",
    "Record",
    "SourceRecord",
    "Vulnerability",
    "VulnerabilityDetail",
]
