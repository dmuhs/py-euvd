from __future__ import annotations

import pytest

from pyeuvd import EUVD

from .fakes import BASE_URL, FakeTransport
from .server import run_local_api


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def euvd(transport) -> EUVD:
    return EUVD(base_url=BASE_URL, transport=transport)


@pytest.fixture
def api():
    with run_local_api() as local_api:
        yield local_api
