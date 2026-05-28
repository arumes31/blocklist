## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2024-05-28 - [IP Spoofing via Unverified Headers]
**Vulnerability:** IP Spoofing
**Learning:** Manual processing of proxy headers like `CF-Connecting-IP` without cryptographically verifying the proxy's identity allows attackers to spoof their IP by sending the header directly. Gin's built-in `c.ClientIP()` securely handles proxy headers, but only if configured with valid trusted proxies. By manually overriding `X-Forwarded-For` with `CF-Connecting-IP` in middleware, or parsing it in handlers, we bypassed these built-in safety checks.
**Prevention:** Rely entirely on framework-provided IP detection methods (e.g., `c.ClientIP()`) after properly configuring trusted proxy CIDR ranges. Do not manually parse or override proxy headers.
