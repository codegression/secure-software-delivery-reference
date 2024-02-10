# Fixture provenance

`fictional_permits.json` is a hand-authored, fixed version-1 fixture created for this repository on 2026-09-16. It contains **4 fictional accounts across 2 fictional teams and 7 permit records**. Names, plot codes, workflow histories and rationale are invented. The sample data is licensed CC0-1.0; no source organization or actual collection permission is implied.

There are no imported public datasets. A real biodiversity dataset would introduce sensitive-location and licensing questions without improving the authorization demonstration. Public security references inform the controls; they are not experimental observations or application data.

The database is derived from this fixture. Passwords are generated with `secrets.token_urlsafe`, hashed with independently random salts and never included in this file. New proposals, sessions and audit events are runtime data under ignored `var/`. Seeded approved/rejected records are explicitly fictional history, not generated audit evidence; the audit table starts empty.

The build records the fixture's SHA-256 digest in `docs/fixture-manifest.json`. That digest proves input identity, not truth, authenticity or protection against someone replacing both the file and manifest.
