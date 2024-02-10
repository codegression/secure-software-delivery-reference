# Design decisions

## ADR-01 · A local, auditable Python/SQLite stack

A standard-library application makes setup reliable and keeps the complete enforcement path inspectable. It also means the repository owns parsing, cookies and authorization code that a mature framework would normally provide. The server binds only to 127.0.0.1 and serves a fixed asset map. Python explicitly discourages `http.server` for production; this choice does not extend to public hosting. SQLite transactions make review+audit atomic on one host; multi-instance coordination and distributed recovery are outside scope.

## ADR-02 · PBKDF2 rather than inventing cryptography

Use Python/OpenSSL PBKDF2-HMAC-SHA256 with 600,000 iterations, independent 16-byte salts and constant-time comparison. OWASP prefers Argon2id; PBKDF2 is a documented option with a 600,000-or-more work factor for HMAC-SHA256 in its FIPS discussion. We select this standard-library option to avoid an installation requirement, **not** to claim FIPS validation or that it is the strongest default. Production would use a managed identity service, or benchmark Argon2id with an appropriate maintained library. Work factor needs review as hardware changes. Rate limiting bounds accepted hash attempts in this small lab. Unknown usernames still take a dummy password-hash verification path to reduce simple account-timing differences; timing side-channel resistance has not been measured.

## ADR-03 · Opaque, revocable sessions

The cookie contains a fresh 32-byte random URL-safe token. SQLite stores its SHA-256 digest and the user link, CSRF token and absolute expiry. Revocation does not require a JWT blacklist or waiting for a signed token to expire. Cookies use HttpOnly and SameSite=Strict. `Secure` is intentionally absent on loopback HTTP; there is no production switch that could suggest this server becomes production-ready by flipping a flag. Re-sign-in replaces the presented session; logout destroys it. Five sessions per account limits ordinary accumulation, although high-concurrency session creation has not been load tested.

## ADR-04 · Both origin and synchronizer CSRF checks

Every POST must carry the exact configured Origin. Authenticated writes also need the current session's random CSRF token in a custom header. Login uses exact origin validation and accepts JSON only, closing the unauthenticated login-CSRF path without a second anonymous session system. All GET routes are read-only. Non-browser clients must send Origin explicitly. SameSite is defense in depth; it does not replace the server checks. The server does not trust forwarded host/proto headers and is not intended to run behind a proxy without redesign.

## ADR-05 · Tenant and object policy in the server

Submitters can create and read their own proposals. Reviewers can read team proposals and review another owner's pending work. Reviewers can submit proposals too, but cannot approve their own. Every detail and review lookup includes tenant equality before it can expose a row. Client-provided identity or status keys are rejected. An inaccessible ID returns 404; missing required role returns 403. This policy is intentionally narrower than a general role hierarchy.

## ADR-06 · Final decision, one atomic write

Review changes only a pending record. Two simultaneous reviewers can both read a pending row, but only one guarded UPDATE succeeds; the other receives 409. The state change and audit append commit together. Decisions are final in this version. A production amendment mechanism would require reasons, previous state and a clear policy for who may reopen a record. A generic unrestricted update endpoint would undermine the invariant.

## ADR-07 · Evidence can be reproducible without deterministic secrets

Fixtures, verdicts, reports, source archives and their manifests are deterministic for unchanged code. Random credentials, salts and tokens are deliberately excluded from that requirement. Tests create ephemeral databases and ports. The build never rewrites existing local state. Build reports describe actual executed assertions; they do not advertise 100% security or vulnerability-detection accuracy.
