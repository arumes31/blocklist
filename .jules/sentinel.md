## 2026-06-04 - [security improvement] Refactor long Webhook handler
**Vulnerability:** Not a direct vulnerability, but overly long handlers increase cognitive load and the likelihood of security-critical logic (like permission checks or input validation) being overlooked or bypassed during future maintenance.
**Learning:** Modularizing complex handlers into distinct "parse", "authorize", and "dispatch" phases clarifies the security boundaries and ensures that each step (authentication, authorization, validation) must succeed before any state-changing action is taken.
**Prevention:** Regularly refactor handlers that exceed a reasonable length (e.g., 50 lines) into smaller, single-responsibility methods.
