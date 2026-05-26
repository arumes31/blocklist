## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.
## 2024-05-26 - [Cross-Site WebSocket Hijacking via Protocol Spoofing]
**Vulnerability:** Cross-Site WebSocket Hijacking (CSWSH) (CWE-1385)
**Learning:** Blindly trusting headers like 'X-Forwarded-Proto' to derive the request scheme in 'CheckOrigin' allows attackers to spoof the protocol (e.g., 'https') and bypass same-origin checks even when the application is accessed over plain 'http'.
**Prevention:** Only trust 'X-Forwarded-Proto' if the request originates from a verified 'Trusted Proxy'. The 'CheckOrigin' function should verify the 'RemoteAddr' against a whitelist of trusted CIDR ranges before considering proxy headers.
