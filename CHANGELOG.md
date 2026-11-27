# Changelog

## Unreleased

- A search result without a usable `total` now raises `EUVDError`. Before, `iter_search` stopped after the first page without an error, and a `total` of `NaN` raised `ValueError`.

## 0.2.2 (2026-11-27)

- Security: the built-in transport no longer follows a redirect to an `ftp://` address. The request fails with an `APIError` instead.
- Security: `UrllibTransport` now raises `ValueError` for any address that is not `http://` or `https://`, such as `file:` or `data:`.
- Security: `UrllibTransport` refuses a response larger than 50 MB and raises `EUVDError`. The new `max_bytes` option changes the limit. For `cve_mapping()` the limit applies to each line.
- Security: control characters in text from the server are replaced with spaces in error messages.
- JSON that is nested too deeply now raises `EUVDError` instead of `RecursionError`.

## 0.2.1 (2026-11-27)

- Security: headers set with `UrllibTransport(headers=...)` are no longer sent along when the server redirects a request. A replaced `User-Agent` or `Accept` still follows redirects.
- `UrllibTransport.headers` now holds only the headers you passed in, without the defaults.

## 0.2.0 (2026-11-27)

First public release. Version 0.1.0 was never published.
