## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.## 2025-02-28 - [Unconstrained Resource Consumption via Input Lengths]
**Vulnerability:** Missing input length validation (CWE-400)
**Learning:** HTMX form parsing (`c.PostForm`) without string length bounds allowed for the potential of extremely large strings to be allocated in memory and submitted to the database, leading to potential unconstrained memory growth and DB bloat.
**Prevention:** Always implement explicit maximum length checks (e.g., `len(str) > 2048` for URLs and `len(str) > 255` for short strings) immediately after parsing untrusted string inputs, before further processing or database insertion.
