"""The transport base classes and the thread adapter."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from pyeuvd import (
    APIError,
    AsyncTransport,
    Response,
    ThreadedTransport,
    Transport,
    UrllibTransport,
)


class OneFile(Transport):
    """Serves the same body for every URL."""

    def __init__(self, response: Response) -> None:
        self.response = response

    def get(self, url: str) -> Response:
        return self.response


class OneFileAsync(AsyncTransport):
    def __init__(self, response: Response) -> None:
        self.response = response

    async def get(self, url: str) -> Response:
        return self.response


async def collect(lines):
    return [line async for line in lines]


def test_a_transport_must_implement_get():
    with pytest.raises(TypeError):
        Transport()
    with pytest.raises(TypeError):
        AsyncTransport()


def test_default_stream_lines_splits_the_body():
    transport = OneFile(Response(200, b"a,b\r\nc,d\n\xff"))
    assert list(transport.stream_lines("https://x.test")) == ["a,b", "c,d", "\ufffd"]


def test_default_stream_lines_raises_for_error_status():
    with pytest.raises(APIError, match="500: boom"):
        list(OneFile(Response(500, b'{"error": "boom"}')).stream_lines("https://x.test"))


def test_async_default_stream_lines():
    transport = OneFileAsync(Response(200, b"a,b\nc,d\n"))
    assert asyncio.run(collect(transport.stream_lines("https://x.test"))) == ["a,b", "c,d"]

    failing = OneFileAsync(Response(404, b""))
    with pytest.raises(APIError, match="404: Not Found"):
        asyncio.run(collect(failing.stream_lines("https://x.test")))


def test_threaded_transport_defaults_to_urllib():
    assert isinstance(ThreadedTransport().transport, UrllibTransport)


def test_threaded_get_does_not_block_the_event_loop():
    class Slow(Transport):
        def get(self, url):
            time.sleep(0.3)
            return Response(200, b"[]")

    async def main():
        transport = ThreadedTransport(Slow())
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        responses = await asyncio.gather(*(transport.get("https://x.test") for _ in range(3)))
        task.cancel()
        return ticks, responses

    ticks, responses = asyncio.run(main())

    assert ticks >= 5
    assert responses == [Response(200, b"[]")] * 3


def test_threaded_stream_reads_in_batches():
    body = "".join(f"line {n}\n" for n in range(7)).encode()
    transport = ThreadedTransport(OneFile(Response(200, body)), batch_size=3)

    lines = asyncio.run(collect(transport.stream_lines("https://x.test")))

    assert lines == [f"line {n}" for n in range(7)]


def test_threaded_stream_closes_the_download_when_stopped_early():
    closed = threading.Event()

    class Streaming(OneFile):
        def stream_lines(self, url):
            try:
                yield from ("a", "b", "c")
            finally:
                closed.set()

    async def main():
        lines = ThreadedTransport(Streaming(Response(200)), batch_size=1).stream_lines("u")
        first = await anext(lines)
        await lines.aclose()
        return first

    assert asyncio.run(main()) == "a"
    assert closed.is_set()


def test_threaded_stream_survives_cancellation_mid_read():
    reading = threading.Event()
    release = threading.Event()

    class Stuck(OneFile):
        def stream_lines(self, url):
            yield "a"
            reading.set()
            release.wait(5)  # a worker thread is parked here when the task is cancelled
            yield "b"

    async def main():
        transport = ThreadedTransport(Stuck(Response(200)), batch_size=2)
        task = asyncio.create_task(collect(transport.stream_lines("u")))
        await asyncio.to_thread(reading.wait, 5)
        task.cancel()
        try:
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()

    asyncio.run(main())
