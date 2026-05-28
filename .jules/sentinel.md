## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.

## 2025-02-28 - [Unconstrained Resource Consumption via Input Lengths]
**Vulnerability:** Missing input length validation (CWE-400)
**Learning:** HTMX form parsing (`c.PostForm`) without string length bounds allowed for the potential of extremely large strings to be allocated in memory and submitted to the database, leading to potential unconstrained memory growth and DB bloat.
**Prevention:** Always implement explicit maximum length checks (e.g., `len(str) > 2048` for URLs and `len(str) > 255` for short strings) immediately after parsing untrusted string inputs, before further processing or database insertion.

## 2024-05-28 - [IP Spoofing via Unverified Headers]
**Vulnerability:** IP Spoofing
**Learning:** Manual processing of proxy headers like `CF-Connecting-IP` without cryptographically verifying the proxy's identity allows attackers to spoof their IP by sending the header directly. Gin's built-in `c.ClientIP()` securely handles proxy headers, but only if configured with valid trusted proxies. By manually overriding `X-Forwarded-For` with `CF-Connecting-IP` in middleware, or parsing it in handlers, we bypassed these built-in safety checks.
**Prevention:** Rely entirely on framework-provided IP detection methods (e.g., `c.ClientIP()`) after properly configuring trusted proxy CIDR ranges. Do not manually parse or override proxy headers.

## 2026-05-30 - [Directory Traversal in GeoIP Download]
**Vulnerability:** Directory Traversal (CWE-22)
**Learning:** Sanitizing paths with `filepath.Base` alone can be insufficient if input strings contain unexpected characters or if the environment handles path separators differently (e.g., backslashes on Linux).
**Prevention:** Use strict allow-list validation (e.g., regex `^[a-zA-Z0-9-]+$`) for externally controlled strings used in path construction or URL parameters. Apply `filepath.Base` as a defense-in-depth measure to ensure only the final component of a path is used.
