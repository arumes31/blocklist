## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2026-05-26 - [IP Spoofing via Insecure Header Trust]
**Vulnerability:** IP Spoofing via Insecure Header Trust (CWE-290 / CWE-345)
**Learning:** Manually trusting headers like `CF-Connecting-IP` without verifying if the request actually came from Cloudflare (or a trusted source) is dangerous. If an application trusts any proxy (like 127.0.0.1), an attacker behind that proxy can spoof the header.
**Prevention:** Rely on standard, well-tested IP detection mechanisms like Gin's `c.ClientIP()`, which correctly validates `X-Forwarded-For` against a list of `TrustedProxies`. Avoid manual header overrides for IP detection unless you can strictly verify the source IP against a known-good range.
