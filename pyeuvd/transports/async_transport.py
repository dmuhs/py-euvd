from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator

from ..response import Response


class AsyncTransport(ABC):
    """Fetches URLs for the async client.

    Subclass it to use an async HTTP library. Only ``get`` is required:

    ```python
    class HttpxTransport(AsyncTransport):
        def __init__(self):
            self.client = httpx.AsyncClient()

        async def get(self, url):
            response = await self.client.get(url)
            return Response(response.status_code, response.content)
    ```
    """

    @abstractmethod
    async def get(self, url: str) -> Response:
        """Fetch a URL and return the response, whatever its status.

        Raise ``TransportError`` if no response arrives.
        """

    async def stream_lines(self, url: str) -> AsyncGenerator[str, None]:
        """Yield the lines of a large text download, without line endings.

        This default loads the whole body first. Override it to stream.
        Raise ``APIError`` if the status is not a success.
        """
        response = await self.get(url)
        response.raise_for_status()
        for line in response.body.decode("utf-8", "replace").splitlines():
            yield line

    async def aclose(self) -> None:  # noqa: B027 - optional hook, empty on purpose
        """Release what the transport holds open. Does nothing by default."""
