# Security scope

Fieldbook is a local learning and portfolio application. It is not an authorization system for actual specimen collection or a production hosting template. Use only fictional data and the generated local accounts.

Report a reproducible issue to the owner of your fork using its private security advisory feature if enabled. This unhosted portfolio does not claim a monitored response address, SLA or bug bounty. Do not post real credentials or private field locations in issues.

**Supported execution:** Python 3.10 or newer, `127.0.0.1`, one process, local disk. The server deliberately exposes no external bind option. It uses Python's `http.server`, which Python documents as unsuitable for production. Moving to production requires a supported server/framework, TLS, secure cookies, an identity provider with MFA and recovery, hardened hosting, durable audit storage, backup/restore validation and independent review.

The local cookie lacks `Secure` because the demo uses HTTP; it is HttpOnly, SameSite=Strict, path-scoped and expires after 30 minutes. Host, Origin and CSRF enforcement still apply. A local machine compromise or local process able to read `var/` is outside this threat boundary. Runtime files are excluded from releases; do not commit them.
