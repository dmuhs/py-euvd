# Changelog

## 0.2.1 (2026-11-27)

- Security: headers set with `UrllibTransport(headers=...)` are no longer sent along when the server redirects a request. A replaced `User-Agent` or `Accept` still follows redirects.
- `UrllibTransport.headers` now holds only the headers you passed in, without the defaults.

## 0.2.0 (2026-11-27)

First public release. Version 0.1.0 was never published.
