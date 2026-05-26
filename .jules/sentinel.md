## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.## 2026-05-26 - [PERF] Optimized JSON Unmarshaling in ListIPsPaginated

**Vulnerability:** Inefficient JSON unmarshaling in a loop over large datasets.
**Learning:** Calling `json.Unmarshal` inside a loop for filtering purposes can be extremely slow and resource-intensive when dealing with thousands of entries in Redis. Pre-filtering using raw string checks before unmarshaling can significantly improve performance. Additionally, high-performance libraries like `sonic` provide faster unmarshaling compared to the standard library.
**Prevention:** Always consider pre-filtering techniques (like string matching on raw data) before performing expensive operations like JSON unmarshaling in hot loops. Use high-performance JSON libraries when dealing with large volumes of data.
