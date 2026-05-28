## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## GeoIP Task Handler Testing
To test the `GeoIPTaskHandler` effectively without relying on external MaxMind servers:
1.  **Refactor for Injectability**: The `GeoIPTaskHandler` struct was updated to include `baseURL` and `dataDir` fields. This allows tests to redirect downloads to a `httptest.Server` and use `t.TempDir()` for file storage.
2.  **Valid Fixtures**: Tests now use a `createTestTarGz` helper to generate valid, compressed `tar.gz` archives containing `.mmdb` files. This ensures that the decompression and extraction logic is properly exercised.
3.  **Isolation**: By using `t.TempDir()`, tests no longer risk polluting the local environment or failing due to permission issues in standard system paths.
