## 2024-05-24 - [Unconstrained Resource Consumption]
**Vulnerability:** Unconstrained Resource Consumption (CWE-400)
**Learning:** `io.ReadAll(resp.Body)` without bounds allowed for the application to try and read responses of any size. If a malicious user controlled the endpoint, they could send gigabytes of data causing memory exhaustion.
**Prevention:** Using `io.LimitReader(resp.Body, max_size)` instead of `resp.Body` restricts the maximum size read, protecting the memory from unbounded allocation from untrusted webhook responses.

## 2025-02-28 - [Unconstrained Resource Consumption via Input Lengths]
**Vulnerability:** Missing input length validation (CWE-400)
**Learning:** HTMX form parsing (`c.PostForm`) without string length bounds allowed for the potential of extremely large strings to be allocated in memory and submitted to the database, leading to potential unconstrained memory growth and DB bloat.
**Prevention:** Always implement explicit maximum length checks (e.g., `len(str) > 2048` for URLs and `len(str) > 255` for short strings) immediately after parsing untrusted string inputs, before further processing or database insertion.

## 2024-05-28 - [IP Spoofing via Unverified Headers]
**Vulnerability:** IP Spoofing
**Learning:** Manual processing of proxy headers like `CF-Connecting-IP` without cryptographically verifying the proxy's identity allows attackers to spoof their IP by sending the header directly. Gin's built-in `c.ClientIP()` securely handles proxy headers, but only if configured with valid trusted proxies. By manually overriding `X-Forwarded-For` with `CF-Connecting-IP` in middleware, or parsing it in handlers, we bypassed these built-in safety checks.
**Prevention:** Rely entirely on framework-provided IP detection methods (e.g., `c.ClientIP()`) after properly configuring trusted proxy CIDR ranges. Do not manually parse or override proxy headers.

## 2026-05-26 - [Server-Side Request Forgery (SSRF) in Webhook Delivery]
**Vulnerability:** The webhook delivery task used unsanitized URLs directly from the database to make outbound POST requests. This allowed an attacker (or a compromised account) to probe internal network services by adding webhooks pointing to internal IP addresses (e.g., 127.0.0.1, 169.254.169.254).
**Learning:** Even if the input is validated at the API level when a resource is created, background workers must re-validate the data before use to ensure defense-in-depth, especially when the data (like a URL) is used for outbound connections. Socket-level protections (like `SafeSocketControl`) are excellent but explicit URL validation (checking scheme and resolving IP) provides an earlier and more descriptive failure point.
**Prevention:** Implement a multi-layered defense for all outbound requests:
1. Validate URLs at the time of entry using `security.IsSafeURL`.
2. Re-validate URLs in background tasks before making the request.
3. Use a custom `http.Client` with a `net.Dialer.Control` function that blocks connections to internal IP ranges at the socket level to prevent DNS rebinding attacks.

## 2026-05-30 - [Directory Traversal in GeoIP Download]
**Vulnerability:** Directory Traversal (CWE-22)
**Learning:** Sanitizing paths with `filepath.Base` alone can be insufficient if input strings contain unexpected characters or if the environment handles path separators differently (e.g., backslashes on Linux).
**Prevention:** Use strict allow-list validation (e.g., regex `^[a-zA-Z0-9-]+$`) for externally controlled strings used in path construction or URL parameters. Apply `filepath.Base` as a defense-in-depth measure to ensure only the final component of a path is used.


## 2026-06-03 - [CRLF Injection in Email Alerts]
**Vulnerability:** CRLF Injection (CWE-93) / Email Content Injection
**Learning:** Interpolating untrusted data (like IP addresses, block reasons, or actor names) directly into email headers or the `Subject` line without sanitization allows an attacker to inject CR/LF characters. This can be used to terminate headers prematurely and inject additional headers (e.g., `Bcc`, `Reply-To`) or even replace the entire email body.
**Prevention:** Always sanitize any input destined for a network header or a delimited protocol. Using a `strings.NewReplacer("\r", "", "\n", "")` to strip line-break characters ensures that untrusted content remains confined to its intended field and cannot "break out" to inject new headers.
<<<<<<< HEAD

## 2026-06-04 - [Directory Traversal in GeoIP Download]
**Vulnerability:** Directory Traversal (CWE-22)
**Learning:** Even when inputs are escaped or sanitized with `filepath.Base`, the lack of strict validation for the core parameters used in URL and path construction can leave edge cases open. In this case, although `url.PathEscape` and `filepath.Base` were used, adding a strict regex validation at the entry point provides a much stronger security guarantee.
**Prevention:** Implement strict allow-list validation (e.g., regex `^[a-zA-Z0-9-]+$`) for any externally influenced strings used in file system operations or as dynamic components of URLs. Apply this validation as early as possible (e.g., in the task constructor and the handler).

## 2026-06-06 - Unbounded String Input via Form Parsing
**Vulnerability:** HTTP POST endpoints utilizing `c.PostForm()` allowed unbounded string inputs, causing uncontrolled memory allocation per request. This exposes the application to Denial of Service (DoS) attacks via memory exhaustion (CWE-400).
**Learning:** Functions like `c.PostForm` or manual JSON binding on unbounded strings implicitly trust client data lengths. While `c.ShouldBindJSON` provides some protection if the body is limited (e.g., via middleware), form fields individually extracted have no length cap unless checked explicitly.
**Prevention:** Always implement explicit boundary checks (e.g., `len(str) > MAX_LENGTH`) immediately after extracting variables from HTTP requests. Apply limits based on data types (e.g., 255 for tokens, 2048 for texts/URLs).

## 2025-03-05 - [DOM-based XSS in Toast Notifications]
**Vulnerability:** DOM-based Cross-Site Scripting (XSS) via `innerHTML` (CWE-79)
**Learning:** The `showToast` function across multiple HTML templates (`admin_management.html`, `excluded.html`, `settings.html`, `whitelist.html`) dynamically constructed HTML using `toast.innerHTML = \`<span>${message}</span>\`;`. If the `message` contained untrusted data (like a failed API response reflecting user input), it could execute arbitrary JavaScript in the user's browser context.
**Prevention:** Always use safe DOM manipulation methods. Instead of `innerHTML`, create elements dynamically (e.g., `document.createElement("span")`) and assign untrusted data to safe properties like `textContent` or `innerText`.

## 2026-06-04 - Fix potential panic in getCombinedIPs
**Vulnerability:** Application panic (DoS) due to nil map assignment.
**Learning:** Functions returning maps alongside errors might return a nil map on failure. Merging such results without initialization can cause runtime panics.
**Prevention:** Always initialize map variables with `make()` or check for nil before assignment when receiving them from external dependencies or repositories.
