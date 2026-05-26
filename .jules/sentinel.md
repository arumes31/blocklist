## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2024-06-12 - [Improved Webhook Handler Maintainability]
**Vulnerability:** Not a direct security vulnerability, but a maintainability issue (Long Function).
**Learning:** Extracting complex logic into smaller, focused helper methods (IP detection, permission checking) and action-specific handlers (ban, unban, whitelist) improves readability and reduces the risk of logic errors in a large, monolithic function.
**Prevention:** Regularly refactor long functions into smaller components with single responsibilities. Reusing validated logic (like GeoIP lookups) can also improve performance.
