---
title: EUVD API errors and retries in Python
description: The errors py-euvd raises for missing entries, API errors and network failures, and how requests are retried.
---

# Errors

All errors inherit from `EUVDError`.

| Error | When |
| --- | --- |
| `NotFoundError` | The API answered 404. No entry or advisory has that ID. |
| `APIError` | The API answered with an error status. See `status_code` and `message`. |
| `TransportError` | Network failure, timeout, or a download that was cut off. |
| `EUVDError` | The API returned something unexpected, such as a page that is not JSON or a response that is too large. |

`NotFoundError` is a kind of `APIError`.

Control characters in text from the server, such as line breaks, are replaced with spaces in error messages. That makes the messages safe to log.

```python
from pyeuvd import NotFoundError

try:
    euvd.get_vulnerability("CVE-0000-0000")
except NotFoundError:
    print("no such entry")
```

## Which request failed

An error that comes from a request shows the address in its message and keeps it in `error.url`:

```python
from pyeuvd import EUVDError

try:
    euvd.search(from_score=11)
except EUVDError as error:
    print(error)       # 400: Invalid 'fromScore': '11.0'. Expected a number between 0 and 10 (https://...)
    print(error.url)   # https://euvdservices.enisa.europa.eu/api/search?page=0&size=10&fromScore=11
```

## Retries

A request that fails with a network error, a timeout or a 429, 502, 503 or 504 status is tried twice more before the error is raised. See [Customizing](customizing.md#timeout-and-retries) to change that.
