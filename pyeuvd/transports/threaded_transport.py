from __future__ import annotations

import asyncio
import contextlib
import itertools
from collections.abc import AsyncGenerator

from ..response import Response
from .async_transport import AsyncTransport
from .transport import Transport
from .urllib_transport import UrllibTransport


class ThreadedTransport(AsyncTransport):
    """Makes a blocking transport usable from async code.

    Each request runs in a worker thread, so the event loop is never blocked.
    """

    def __init__(self, transport: Transport | None = None, *, batch_size: int = 5000) -> None:
        self.transport = transport or UrllibTransport()
        # How many lines stream_lines reads per trip to a worker thread.
        self.batch_size = batch_size

    async def get(self, url: str) -> Response:
        return await asyncio.to_thread(self.transport.get, url)

    async def stream_lines(self, url: str) -> AsyncGenerator[str, None]:
        lines = self.transport.stream_lines(url)

        def next_batch() -> list[str]:
            return list(itertools.islice(lines, self.batch_size))

        try:
            while batch := await asyncio.to_thread(next_batch):
                for line in batch:
                    yield line
        finally:
            # If the task was cancelled mid-batch, a worker thread is still
            # running the generator and close() raises ValueError. Python
            # closes the generator later, when it is garbage collected.
            with contextlib.suppress(ValueError):
                lines.close()

    async def aclose(self) -> None:
        await asyncio.to_thread(self.transport.close)
