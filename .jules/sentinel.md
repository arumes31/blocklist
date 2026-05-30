## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2026-05-30 - [Directory Traversal in GeoIP Download]
**Vulnerability:** Directory Traversal (CWE-22)
**Learning:** Sanitizing paths with `filepath.Base` alone can be insufficient if input strings contain unexpected characters or if the environment handles path separators differently (e.g., backslashes on Linux).
**Prevention:** Use strict allow-list validation (e.g., regex `^[a-zA-Z0-9-]+$`) for externally controlled strings used in path construction or URL parameters. Apply `filepath.Base` as a defense-in-depth measure to ensure only the final component of a path is used.
