## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2024-05-28 - [Testing QR Code Generation]
**Task:** Untested generateQRWithLogo function
**Learning:** Testing functions that rely on filesystem paths (like  looking for a logo) in Go can be done by temporarily changing the working directory using . This ensures that hardcoded relative paths resolve correctly during tests.
**Prevention:** Always verify that generated images (e.g., QR codes) are valid by decoding them in tests, and cover both fallback and success paths for asset loading.

## 2024-05-28 - [Testing QR Code Generation]
**Task:** Untested generateQRWithLogo function
**Learning:** Testing functions that rely on filesystem paths (like `generateQRWithLogo` looking for a logo) in Go can be done by temporarily changing the working directory using `os.Chdir`. This ensures that hardcoded relative paths resolve correctly during tests.
**Prevention:** Always verify that generated images (e.g., QR codes) are valid by decoding them in tests, and cover both fallback and success paths for asset loading.
