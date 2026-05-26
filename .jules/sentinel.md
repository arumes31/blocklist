## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2024-06-12 - [SQL Injection in Table Partition Creation]
**Vulnerability:** Potential SQL Injection (CWE-89) in DDL statements.
**Learning:** Using `fmt.Sprintf` to construct DDL statements (`CREATE TABLE`, `DROP TABLE`) with variables representing identifiers (table names) is unsafe. Even if identifiers are currently hardcoded, any future changes allowing user-controlled input or configuration-based table names could lead to direct SQL injection.
**Prevention:** Implement strict whitelisting for any dynamic identifiers used in SQL statements. Additionally, wrap identifiers in double quotes (PostgreSQL standard) to ensure they are treated as names and not keywords or multiple statements, and ensure that other components (like date suffixes) are strictly validated or generated from safe sources.
