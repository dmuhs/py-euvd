"""A small local HTTP server, for testing the real network code."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .fakes import canned_response


@dataclass
class Reply:
    """What the server sends for one path."""

    status: int = 200
    body: bytes = b""
    declared_length: int | None = None  # set higher than the body to cut the response short
    delay: float = 0.0


@dataclass
class LocalAPI:
    url: str
    # One reply per path, or a list to send in order. The last one repeats.
    replies: dict[str, Reply | list[Reply]] = field(default_factory=dict)
    headers: list[dict[str, str]] = field(default_factory=list)  # headers of each request seen


class Handler(BaseHTTPRequestHandler):
    api: LocalAPI

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        path = url.path.removeprefix("/api")
        self.api.headers.append({name.lower(): value for name, value in self.headers.items()})
        reply = self.api.replies.get(path)
        if isinstance(reply, list):
            reply = reply.pop(0) if len(reply) > 1 else reply[0]
        if reply is None:
            canned = canned_response(path, dict(parse_qsl(url.query)), total=25)
            reply = Reply(status=canned.status, body=canned.body)
        time.sleep(reply.delay)
        length = len(reply.body) if reply.declared_length is None else reply.declared_length
        try:
            self.send_response(reply.status)
            self.send_header("Content-Length", str(length))
            self.end_headers()
            self.wfile.write(reply.body)
        except OSError:
            pass  # the client gave up, as the timeout tests expect
        self.close_connection = True

    def log_message(self, *args: Any) -> None:
        pass


@contextmanager
def run_local_api() -> Iterator[LocalAPI]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), type("BoundHandler", (Handler,), {}))
    server.daemon_threads = True
    server.block_on_close = False
    api = LocalAPI(url=f"http://127.0.0.1:{server.server_address[1]}/api")
    server.RequestHandlerClass.api = api
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield api
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
