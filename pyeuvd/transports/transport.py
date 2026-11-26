from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Generator

from ..response import Response


class Transport(ABC):
    """Fetches URLs for the client.

    Subclass it to use another HTTP library, or to add retries, caching or
    rate limiting. Only ``get`` is required:

    ```python
    class HttpxTransport(Transport):
        def __init__(self):
            self.client = httpx.Client()

        def get(self, url):
            response = self.client.get(url)
            return Response(response.status_code, response.content)
    ```
    """

    @abstractmethod
    def get(self, url: str) -> Response:
        """Fetch a URL and return the response, whatever its status.

        Raise ``TransportError`` if no response arrives.
        """

    def stream_lines(self, url: str) -> Generator[str, None, None]:
        """Yield the lines of a large text download, without line endings.

        This default loads the whole body first. Override it to stream.
        Raise ``APIError`` if the status is not a success.
        """
        response = self.get(url)
        response.raise_for_status()
        yield from response.body.decode("utf-8", "replace").splitlines()

    def close(self) -> None:  # noqa: B027 - optional hook, empty on purpose
        """Release what the transport holds open. Does nothing by default."""
