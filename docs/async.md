# Async

`AsyncEUVD` has the same methods as `EUVD`.

```python
import asyncio
from pyeuvd import AsyncEUVD

async def main():
    euvd = AsyncEUVD()
    vuln = await euvd.get_vulnerability("CVE-2024-3400")

    async for vuln in euvd.iter_search(vendor="Cisco", limit=50):
        print(vuln.id)

asyncio.run(main())
```

By default, requests run in worker threads, so they never block the event loop.

## Many requests at once

Use `asyncio.gather` to run lookups side by side. This turns unknown IDs into `None`:

```python
import asyncio
from pyeuvd import AsyncEUVD, NotFoundError

async def lookup(euvd, cve_id):
    try:
        return await euvd.get_vulnerability(cve_id)
    except NotFoundError:
        return None

async def lookup_all(cve_ids):
    euvd = AsyncEUVD()
    return await asyncio.gather(*(lookup(euvd, cve_id) for cve_id in cve_ids))

vulns = asyncio.run(lookup_all(["CVE-2024-3400", "CVE-2021-22555"]))
```

## An async HTTP library

To use an async HTTP library in place of threads, see [Customizing](customizing.md#async-transports).
