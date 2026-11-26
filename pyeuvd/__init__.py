"""Python client for the EU Vulnerability Database (EUVD)."""

from ._version import __version__
from .async_client import AsyncEUVD
from .client import EUVD
from .constants import BASE_URL, MAX_PAGE_SIZE
from .errors import APIError, EUVDError, NotFoundError, TransportError
from .filters import SearchFilters
from .models import (
    Advisory,
    AdvisoryDetail,
    KevEntry,
    Model,
    Page,
    Product,
    Record,
    SourceRecord,
    Vulnerability,
    VulnerabilityDetail,
)
from .response import Response
from .transports import AsyncTransport, ThreadedTransport, Transport, UrllibTransport
from .utils import Severity

__all__ = [
    "BASE_URL",
    "EUVD",
    "MAX_PAGE_SIZE",
    "APIError",
    "Advisory",
    "AdvisoryDetail",
    "AsyncEUVD",
    "AsyncTransport",
    "EUVDError",
    "KevEntry",
    "Model",
    "NotFoundError",
    "Page",
    "Product",
    "Record",
    "Response",
    "SearchFilters",
    "Severity",
    "SourceRecord",
    "ThreadedTransport",
    "Transport",
    "TransportError",
    "UrllibTransport",
    "Vulnerability",
    "VulnerabilityDetail",
    "__version__",
]
