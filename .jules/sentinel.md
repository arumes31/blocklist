## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.

## 2026-05-28 - [N+1 Query Pattern]
**Vulnerability:** Performance degradation due to N+1 query anti-pattern (CWE-400 equivalent for DB/Cache).
**Learning:** Iterating over a list of identifiers and fetching details for each individually (`GetIPEntry`) causes excessive network round-trips to Redis.
**Prevention:** Use batch retrieval methods like `HMGet` (via `GetIPEntries`) to fetch all required data in a single operation before processing the loop.
