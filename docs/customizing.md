# Customizing

## Timeout and retries

```python
from pyeuvd import EUVD, UrllibTransport

euvd = EUVD(timeout=10)
euvd = EUVD(transport=UrllibTransport(timeout=10, retries=5, backoff=1))
```

- The timeout is 30 seconds by default.
- A request that fails with a network error, a timeout or a 429, 502, 503 or 504 status is tried twice more, after 0.5 and 1 seconds. `retries` and `backoff` change that.
- A failed TLS certificate check is not retried.

With your own transport, set the timeout there. Passing both `timeout` and `transport` raises `ValueError`.

## Corporate networks

Neither of these needs any code:

- To go through a proxy, set the `HTTPS_PROXY` environment variable.
- If the proxy re-signs TLS traffic, set `SSL_CERT_FILE` to your organisation's CA bundle.

## Extra headers

```python
euvd = EUVD(transport=UrllibTransport(headers={"User-Agent": "my-app/1.0"}))
```

Extra headers go only to the address you asked for. If the server redirects the request, they are not sent along. A replaced `User-Agent` or `Accept` is the exception.

## Addresses and redirects

The built-in transport only fetches `http://` and `https://` addresses. Any other address raises `ValueError`.

A redirect to any other kind of address, such as `ftp://`, is not followed. The request fails with an `APIError` that carries the redirect's status.

## Your own opener

`UrllibTransport(opener=...)` takes your own `urllib.request` opener for other connection settings. It follows redirects by its own rules, so it may still follow one to `ftp://`.

## Your own transport

The client hands every request to a transport. You can replace it with your own.

To change how requests are made, extend the built-in transport. This one remembers answers:

```python
from pyeuvd import EUVD, UrllibTransport

class CachingTransport(UrllibTransport):
    def __init__(self, **options):
        super().__init__(**options)
        self.cache = {}

    def get(self, url):
        response = self.cache.get(url) or super().get(url)
        if response.ok:
            self.cache[url] = response
        return response

euvd = EUVD(transport=CachingTransport(timeout=10))
```

To use another HTTP library, write a transport from scratch. It needs one method:

```python
import httpx
from pyeuvd import EUVD, Response, Transport

class HttpxTransport(Transport):
    def __init__(self):
        self.client = httpx.Client()

    def get(self, url):
        response = self.client.get(url)
        return Response(response.status_code, response.content)

    def close(self):
        self.client.close()

with EUVD(transport=HttpxTransport()) as euvd:
    euvd.latest()
```

Leaving the `with` block calls the transport's `close`. The built-in transport holds nothing open, so with it the `with` block is optional.

## Async transports

`AsyncEUVD` accepts the transports above and runs them in threads. For an async HTTP library, subclass `AsyncTransport`:

```python
import httpx
from pyeuvd import AsyncEUVD, AsyncTransport, Response

class AsyncHttpxTransport(AsyncTransport):
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def get(self, url):
        response = await self.client.get(url)
        return Response(response.status_code, response.content)

    async def aclose(self):
        await self.client.aclose()

async with AsyncEUVD(transport=AsyncHttpxTransport()) as euvd:
    await euvd.latest()
```

## Your own fields

To add fields to a result, subclass a model and extend `parse_fields`:

```python
from dataclasses import dataclass
from pyeuvd import Vulnerability

@dataclass(frozen=True, kw_only=True)
class MyVulnerability(Vulnerability):
    team: str

    @classmethod
    def parse_fields(cls, data):
        fields = super().parse_fields(data)
        fields["team"] = "network" if "Cisco" in fields["vendors"] else "other"
        return fields

mine = MyVulnerability.from_dict(vuln.raw)
```

## Logging

Requests are logged at debug level under the `pyeuvd` logger, with status and duration:

```python
import logging

logging.basicConfig()
logging.getLogger("pyeuvd").setLevel("DEBUG")
```
