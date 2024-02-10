# Dependency inventory and delivery risks

**Zero third-party Python packages is a packaging fact, not zero dependency risk.** The source artifact is not a container or operating-system distribution. This is a human-readable inventory, not a complete transitive SBOM.

| Component | Constraint / provenance | Role and exposure | Owner action |
| --- | --- | --- | --- |
| CPython | 3.10+ from the user's trusted distribution; local tested version recorded by operator, not baked into deterministic evidence | HTTP/JSON/cookies/concurrency and crypto wrappers; upstream bugs can affect controls | Run a supported patched version; review Python security releases |
| OpenSSL | Linked by the installed Python; version varies | PBKDF2 and comparison implementation via Python; no application TLS listener | Track distribution and OpenSSL advisories; do not infer FIPS certification |
| SQLite | Linked by the installed Python; version varies | Local SQL parsing, transactions, constraints | Patch with the Python/OS runtime, test backup/restore |
| Browser | Modern fetch/DOM/CSS implementation | SameSite, Origin, CSP, text rendering and user interaction | Browser support, end-to-end and accessibility testing remain required |
| GitHub-hosted runner | `ubuntu-24.04`; mutable image updates | Builds and executes PR code | Restrict permissions; do not expose deployment credentials; review image changes |
| actions/checkout | v6.1.0, immutable commit `d23441a48e516b6c34aea4fa41551a30e30af803` | Fetches source; credentials not persisted | Dependabot proposes updates; review provenance and release notes |
| actions/setup-python | v7.0.0, immutable commit `5fda3b95a4ea91299a34e894583c3862153e4b97` | Obtains interpreter from upstream tool cache/releases | Review upstream integrity and new action versions |
| GitHub Actions' transitive Node packages | Bundled inside pinned upstream actions; not vendored here | Supply-chain exposure outside Python dependency count | Review upstream actions; a full deployment SBOM must include them |

## Pipeline and release gates

`.github/workflows/verify.yml` uses ordinary `pull_request` execution, read-only content permissions, no repository secrets and no publish/deploy step. It pins actions by full commit SHA and uses a timeout. Each matrix job runs real HTTP tests, checks narrow source policies, rebuilds reports, packages an allowlisted archive, checks committed report freshness and verifies the archive checksum and exclusion of runtime state. Remote matrix execution is unverified in this delivered local folder.

The local source policy checker catches selected token/private-key shapes, unpinned actions, privileged workflow patterns and explicit dynamic execution/shell flags. It is not a replacement for a maintained secret scanner, SAST engine, software-composition analysis or code review. It does not query a vulnerability database. The fixed inputs and complete assertions make its claims inspectable and small.

`SHA256SUMS` can detect an accidental changed archive when trusted independently; it is **not a signature or supply-chain attestation**. Replacing both archive and checksum defeats that check. The package excludes `var/` by allowlist even if a user forgets to respect `.gitignore`.

Before production delivery: require protected branches and reviewer ownership, adopt authenticated artifact signing/attestation, generate a full deployable-image SBOM, scan the deployed runtime with current advisory data, and add an approval-gated deployment to a hardened environment. These are future gates, not silently assumed GitHub settings.

To inspect the exact local native runtime (version inventory only):

```bash
python3 -c "import sys,ssl,sqlite3; print(sys.version); print(ssl.OPENSSL_VERSION); print(sqlite3.sqlite_version)"
```
