## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2026-05-26 - [Server-Side Request Forgery (SSRF) in Webhook Delivery]
**Vulnerability:** The webhook delivery task used unsanitized URLs directly from the database to make outbound POST requests. This allowed an attacker (or a compromised account) to probe internal network services by adding webhooks pointing to internal IP addresses (e.g., 127.0.0.1, 169.254.169.254).
**Learning:** Even if the input is validated at the API level when a resource is created, background workers must re-validate the data before use to ensure defense-in-depth, especially when the data (like a URL) is used for outbound connections. Socket-level protections (like `SafeSocketControl`) are excellent but explicit URL validation (checking scheme and resolving IP) provides an earlier and more descriptive failure point.
**Prevention:** Implement a multi-layered defense for all outbound requests:
1. Validate URLs at the time of entry using `security.IsSafeURL`.
2. Re-validate URLs in background tasks before making the request.
3. Use a custom `http.Client` with a `net.Dialer.Control` function that blocks connections to internal IP ranges at the socket level to prevent DNS rebinding attacks.
