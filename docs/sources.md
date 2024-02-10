# Public technical references

Read on 2026-09-16. These references support design choices; they are not imported datasets or proof that the application satisfies a complete standard. Guidance and release versions can change.

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): recommends modern password hashing, describes Argon2id and alternatives, and gives the PBKDF2-HMAC-SHA256 600,000-iteration guidance used here. Choosing that setting alone does not imply FIPS certification.
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): supports synchronizer tokens, origin checks, SameSite defense in depth and Fetch Metadata validation. The application's exact-origin policy intentionally rejects unlabelled POST clients.
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html): informs the use of text-only DOM sinks and contextual treatment of untrusted values. The API returns JSON; the browser treats proposal fields as text.
- [Python HTTP server documentation](https://docs.python.org/3/library/http.server.html): explicitly describes `http.server` as unsuitable for production, constraining this repository to its loopback lab purpose.
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use): informs least-privilege workflow permissions and immutable action pins. These choices reduce some supply-chain exposure without eliminating dependency trust.
- [actions/checkout v6.1.0 release](https://github.com/actions/checkout/releases/tag/v6.1.0) and [the selected commit](https://github.com/actions/checkout/commit/d23441a48e516b6c34aea4fa41551a30e30af803): official source for the pinned checkout action.
- [actions/setup-python v7.0.0 release](https://github.com/actions/setup-python/releases/tag/v7.0.0) and [the selected commit](https://github.com/actions/setup-python/commit/5fda3b95a4ea91299a34e894583c3862153e4b97): official source for the pinned interpreter setup action.
