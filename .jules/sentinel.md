## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2026-05-27 - [SECURITY] Directory Traversal in GeoIP Download

**Vulnerability:** The GeoIP task handler allowed potentially malicious `edition` strings to be used in URL construction and file path generation. Although some sanitization with `filepath.Base` and `filepath.Clean` was present, it was insufficient to prevent all forms of path manipulation or unexpected URL construction when external input is passed.

**Learning:** Sanitizing with `filepath.Base(filepath.Clean(input))` is not enough if the input is used to construct URLs or if the application logic doesn't strictly validate the allowed character set. In this case, MaxMind edition IDs have a very specific format (alphanumeric and dashes).

**Prevention:** Implement strict allow-list validation (e.g., regex or character-by-character check) for any input used in file system operations or URL construction. Explicitly reject path components like `..`, `/`, and `\` early in the processing pipeline.
