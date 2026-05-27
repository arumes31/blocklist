## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2026-05-27 - [N+1 Query in Bulk Operations]
**Vulnerability:** Inefficient Database Interaction (N+1 Query Pattern)
**Learning:** Executing prepared statements in a loop for bulk operations (like `BulkCreatePersistentBlocks`) causes multiple network roundtrips and increases database load, which can lead to performance degradation or resource exhaustion under high load.
**Prevention:** Use `pgx.Batch` to group multiple operations into a single network roundtrip. Access the underlying `*pgx.Conn` from `sqlx.DB` via `db.Conn(ctx)` and `Raw` casting to `*stdlib.Conn` to utilize batching capabilities within a transaction.
