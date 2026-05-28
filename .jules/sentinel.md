## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2026-05-28 - [Directory Traversal in GeoIP Download]
**Vulnerability:** Directory Traversal (CWE-22)
**Learning:** Using `filepath.Base(filepath.Clean(input))` for sanitization can be insufficient on Linux if the input contains backslashes, as `filepath.Base` on Linux does not treat backslashes as path separators. This could allow an attacker to bypass sanitization and influence URL construction or file paths.
**Prevention:** Implement strict input validation using a whitelist (e.g., regular expression `^[a-zA-Z0-9-]+$`) for identifiers used in path or URL construction. Additionally, apply `filepath.Base` as a defense-in-depth measure immediately before using the variable in `filepath.Join`.
