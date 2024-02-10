# Fieldbook: control evidence and release decision

**Decision:** accept this repository as a local application-security demonstration. Do not treat it as a production deployment approval.

The executed suite passed **25 of 25 real HTTP test scenarios**, with 0 failures, 0 errors and 0 skipped tests. The evidence comes from isolated SQLite fixtures and actual loopback connections. It is not a percentage of all possible security controls or an estimate of vulnerability prevalence.

## Findings that matter to a delivery lead

| Question | Observed behavior | Decision implication |
| --- | --- | --- |
| Can one team inspect or decide another team’s proposal? | The tested read and mutation attempts return 404; stored proposal stays pending after denied mutation. | Tenant policy is enforced on server-side object lookup. |
| Can the author approve their own proposal? | Reviewer self-approval returns 403 and leaves the state unchanged. | The independent-review invariant survives direct API calls. |
| Can racing reviews overwrite each other? | Two concurrent requests produce one 200 and one 409, and only one decision audit event. | Guarded state transition plus transaction preserves the tested invariant. |
| Is a copied old cookie still useful after sign-out, expiry or rotation? | Those requests return 401 in the corresponding isolated tests. | Sessions are revocable and have server-side expiry. |
| Can a foreign web page submit a authenticated decision? | Missing/wrong CSRF or incorrect Origin is denied; foreign Host is rejected. | Browser-origin boundary has complementary controls. |
| Does security work block legitimate researchers? | Authorized submission and independent review persist the expected owner, team, state, reviewer and audit event. | Positive workflow evidence accompanies negative tests. |

## Release scope and priorities

1. **Keep the lab local.** The server binds to 127.0.0.1, serves HTTP and intentionally omits Secure on its local cookie. It is not a production web server.
2. **Replace local identity for real use.** Managed identity, MFA, recovery and account lifecycle need ownership and testing.
3. **Close assurance gaps before deployment.** Add supported hosting/TLS, browser and accessibility tests, current dependency advisories, persistent abuse controls, external audit retention and backup restoration tests.

## Exact executed scenarios

| Test | Outcome |
| --- | --- |
| `test_audit_scoped_and_forbidden_to_submitter` | pass |
| `test_authenticated_writes_reject_cross_origin_and_fetch_site` | pass |
| `test_authentication_requires_valid_credentials` | pass |
| `test_cross_tenant_mutation_denied` | pass |
| `test_duplicate_and_concurrent_review_have_one_winner` | pass |
| `test_expired_session_denied` | pass |
| `test_host_rebinding_rejected` | pass |
| `test_invalid_json_duplicate_fields_and_body_limits` | pass |
| `test_login_rate_limit_reached` | pass |
| `test_login_requires_exact_origin` | pass |
| `test_logout_revokes_session` | pass |
| `test_mass_assignment_rejected_and_tenant_set_server_side` | pass |
| `test_missing_and_wrong_csrf_rejected_without_change` | pass |
| `test_password_hashes_use_random_salts_and_work_factor` | pass |
| `test_relogin_rotates_and_invalidates_previous_cookie` | pass |
| `test_review_writes_decision_and_audit_atomically` | pass |
| `test_reviewer_can_see_same_tenant_only` | pass |
| `test_reviewer_cannot_approve_own_proposal` | pass |
| `test_script_payload_is_data_and_not_reflected_as_html` | pass |
| `test_session_cookie_and_browser_response_policy` | pass |
| `test_session_secret_hashed_in_database` | pass |
| `test_sql_injection_login_does_not_authenticate` | pass |
| `test_static_route_whitelist_blocks_database_and_traversal` | pass |
| `test_submitter_cannot_review` | pass |
| `test_submitter_only_sees_own_objects` | pass |

## Limits of this result

- Passing scenarios are evidence for the stated assertions, not a vulnerability prevalence or universal security-coverage estimate.
- The XSS check verifies JSON content type, CSP and rendering sink convention; browser exploit execution is outside this suite.
- No TLS, public deployment, live CVE feed, independent penetration test, accessibility audit or sustained load test was performed.
- Rate limiting and concurrent review cover bounded lab cases only; process-local rate state resets on restart.

Source archive packaging uses fixed timestamps and an allowlist; local passwords and databases are excluded. The CI workflow is provided, but no remote GitHub execution or branch-protection setting is claimed.

Regenerate: `python3 run.py verify`. Machine-readable observations: [evaluation.json](evaluation.json). Method and threat boundaries: [threat-model.md](threat-model.md).
