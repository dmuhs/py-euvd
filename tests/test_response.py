from __future__ import annotations

import copy
import pickle

import pytest

from pyeuvd import APIError, EUVDError, NotFoundError, Response, TransportError


@pytest.mark.parametrize(("status", "ok"), [(200, True), (204, True), (301, False), (404, False)])
def test_ok(status, ok):
    assert Response(status).ok is ok


def test_json():
    assert Response(200, b'{"total": 3}').json() == {"total": 3}


def test_json_rejects_other_content():
    with pytest.raises(EUVDError, match="did not return JSON"):
        Response(200, b"<html>maintenance</html>").json()


def test_raise_for_status_passes_on_success():
    Response(200, b"[]").raise_for_status()


def test_not_found():
    with pytest.raises(NotFoundError) as info:
        Response(404, b'{"error": "EUVD not found"}').raise_for_status()

    assert info.value.status_code == 404
    assert info.value.message == "EUVD not found"
    assert str(info.value) == "404: EUVD not found"


def test_other_errors_are_api_errors():
    with pytest.raises(APIError) as info:
        Response(400, b'{"error": "Invalid \'fromDate\'"}').raise_for_status()

    assert info.value.status_code == 400
    assert info.value.message == "Invalid 'fromDate'"
    assert not isinstance(info.value, NotFoundError)


@pytest.mark.parametrize(
    ("status", "body", "message"),
    [
        (503, b"<html>down</html>", "<html>down</html>"),  # not JSON: use the text
        (500, b'["unexpected"]', '["unexpected"]'),  # JSON without an "error" field
        (500, b"x" * 500, "x" * 200),  # long bodies are cut
        (502, b"", "Bad Gateway"),  # no body: use the standard status text
        (599, b"", "HTTP error"),  # no body and an unknown status
    ],
)
def test_error_message_fallbacks(status, body, message):
    with pytest.raises(APIError) as info:
        Response(status, body).raise_for_status()

    assert info.value.message == message


def test_errors_show_their_url_when_they_have_one():
    error = APIError(503, "busy")
    assert str(error) == "503: busy"

    error.url = "https://x.test/api/search"
    assert str(error) == "503: busy (https://x.test/api/search)"


@pytest.mark.parametrize(
    "error",
    [
        APIError(503, "busy"),
        NotFoundError(404, "EUVD not found"),
        TransportError("no network"),
        EUVDError("the API did not return JSON"),
    ],
)
@pytest.mark.parametrize("url", [None, "https://x.test/api/search"])
def test_errors_survive_pickling_and_copying(error, url):
    """Errors are pickled when they leave a worker process."""
    error.url = url

    for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error), copy.deepcopy(error)):
        assert type(clone) is type(error)
        assert str(clone) == str(error)
        assert clone.url == url
        assert vars(clone) == vars(error)
